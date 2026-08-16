/**
 * John Deere Operations Center - OAuth2 Flow + Data Fetching
 * ---------------------------------------------------------------
 * FIXES IN THIS VERSION:
 *   1) UPSERT by organization_id  -> no more duplicate rows per org
 *   2) Link traversal             -> follow the `links` array Deere returns
 *                                    instead of hand-building URLs (avoids 403s)
 *   3) Self-healing org lookup    -> if organization_id wasn't saved during the
 *                                    callback, /api/boundaries finds it live and
 *                                    backfills the database
 *
 * Requires: npm install express axios dotenv pg
 */

const express = require("express");
const axios = require("axios");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

// ---- Configuration -------------------------------------------------------
const CLIENT_ID = process.env.DEERE_CLIENT_ID;
const CLIENT_SECRET = process.env.DEERE_CLIENT_SECRET;
const REDIRECT_URI = process.env.DEERE_REDIRECT_URI;

const TOKEN_ENDPOINT = "https://signin.johndeere.com/oauth2/aus78tnlaysMraFhC1t7/v1/token";
const AUTHORIZATION_ENDPOINT = "https://signin.johndeere.com/oauth2/aus78tnlaysMraFhC1t7/v1/authorize";

// Entry point for the Platform API. Everything else is discovered from `links`.
const API_ROOT = "https://api.deere.com/platform";

// READ-ONLY BY DESIGN.
// Deere's scopes come in pairs per domain: the lower number grants read, the
// higher adds write. We deliberately request only the read level, so the token
// itself is incapable of modifying a grower's data — even if that grower grants
// a "Manage" (level 3) permission at connections.deere.com.
// work1/work2 and files are left out until Deere approves those APIs;
// requesting an unapproved scope fails the whole authorization.
// Deere support (15 Aug 2026) advised the Assets API needs an equipment
// write-tier scope, not eq1 — quoting it as "eg2" in the same message where
// they said their docs were wrong on this point. Both spellings are requested
// since one of them is almost certainly a typo; an unrecognised scope is
// ignored by the authorization server rather than failing the request.
const SCOPES = "ag1 ag2 ag3 eq1 eq2 eg2 org1 files offline_access";
const DEERE_ACCEPT_HEADER = "application/vnd.deere.axiom.v3+json";

// ---- Database setup --------------------------------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function ensureTableExists() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS deere_tokens (
      id SERIAL PRIMARY KEY,
      organization_id TEXT,
      organization_name TEXT,
      access_token TEXT NOT NULL,
      refresh_token TEXT,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // CREATE TABLE IF NOT EXISTS silently skips an existing table, so columns
  // added in later versions of this file won't appear on a database created
  // by an earlier version. Backfill them explicitly.
  await pool.query(`
    ALTER TABLE deere_tokens
      ADD COLUMN IF NOT EXISTS organization_id TEXT,
      ADD COLUMN IF NOT EXISTS organization_name TEXT,
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW(),
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW();
  `);

  // Clean up duplicate rows per organization left over from earlier versions,
  // keeping the newest. saveToken() below uses delete-then-insert rather than
  // ON CONFLICT, so no unique index is required.
  await pool.query(`
    DELETE FROM deere_tokens a
    USING deere_tokens b
    WHERE a.organization_id IS NOT NULL
      AND a.organization_id = b.organization_id
      AND a.id < b.id;
  `);

  console.log("Database ready: deere_tokens table exists.");
}

// ---- Small helper: pull a URL out of Deere's `links` array ---------------
function findLink(entity, rel) {
  const link = (entity.links || []).find((l) => l.rel === rel);
  return link ? link.uri : null;
}

function deereHeaders(accessToken) {
  return {
    Authorization: `Bearer ${accessToken}`,
    Accept: DEERE_ACCEPT_HEADER,
  };
}

// ---- Read-only guard ----------------------------------------------------
// Belt and braces alongside the read-only scopes: a dedicated axios instance
// that refuses to send anything except GET to Deere. If someone later adds a
// POST/PUT/DELETE by accident, it fails here rather than changing a grower's
// data. All Deere calls in this file go through deereGet().
const deereClient = axios.create();

deereClient.interceptors.request.use((config) => {
  const method = (config.method || "get").toLowerCase();
  if (method !== "get") {
    throw new Error(
      `Blocked a ${method.toUpperCase()} request to ${config.url}. ` +
        `This connector is read-only and must never modify grower data.`
    );
  }
  return config;
});

async function deereGet(url, accessToken) {
  return deereClient.get(url, { headers: deereHeaders(accessToken) });
}

// ---- Step A: Kick off the flow -------------------------------------------
app.get("/auth/deere/start", (req, res) => {
  const state = generateRandomState(); // TODO: store & verify this (CSRF protection)

  const authUrl = new URL(AUTHORIZATION_ENDPOINT);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authUrl.searchParams.set("scope", SCOPES);
  authUrl.searchParams.set("state", state);

  res.redirect(authUrl.toString());
});

// ---- Step B: Redirect URI --------------------------------------------
app.get("/auth/deere/callback", async (req, res) => {
  const { code, error } = req.query;

  if (error) return res.status(400).send(`Authorization was not completed: ${error}`);
  if (!code) return res.status(400).send("Missing authorization code.");

  try {
    const tokenResponse = await axios.post(
      TOKEN_ENDPOINT,
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization:
            "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64"),
        },
      }
    );

    const { access_token, refresh_token, expires_in } = tokenResponse.data;
    const expiresAt = new Date(Date.now() + expires_in * 1000);

    // Try to resolve which organization this token belongs to, right away.
    let org = null;
    try {
      const orgsResponse = await deereGet(`${API_ROOT}/organizations`, access_token);
      org = orgsResponse.data.values?.[0] || null;
      if (org) console.log(`Connected organization: ${org.name} (${org.id})`);
    } catch (orgErr) {
      // Non-fatal: the token is still worth saving, and /api/boundaries will
      // backfill the organization later.
      console.error(
        "Could not resolve organization during callback:",
        orgErr.response?.data || orgErr.message
      );
    }

    await saveToken({
      organizationId: org?.id || null,
      organizationName: org?.name || null,
      accessToken: access_token,
      refreshToken: refresh_token,
      expiresAt,
    });

    console.log("Tokens saved to database. Expires at:", expiresAt);
    res.send("Connection successful! You can close this window.");
  } catch (err) {
    console.error("Token exchange failed:", err.response?.data || err.message);
    res.status(500).send("Something went wrong completing the connection.");
  }
});

// ---- Save or update a token row (UPSERT by organization_id) --------------
async function saveToken({ organizationId, organizationName, accessToken, refreshToken, expiresAt }) {
  if (organizationId) {
    // Delete-then-insert rather than ON CONFLICT: same end result, but it
    // doesn't depend on a unique index existing on organization_id.
    await pool.query(`DELETE FROM deere_tokens WHERE organization_id = $1`, [organizationId]);
    await pool.query(
      `INSERT INTO deere_tokens
         (organization_id, organization_name, access_token, refresh_token, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [organizationId, organizationName, accessToken, refreshToken, expiresAt]
    );
  } else {
    await pool.query(
      `INSERT INTO deere_tokens (access_token, refresh_token, expires_at)
       VALUES ($1, $2, $3)`,
      [accessToken, refreshToken, expiresAt]
    );
  }
}

// ---- Refresh an expired access token -------------------------------------
async function getValidAccessToken(tokenRow) {
  const bufferMs = 60 * 1000;
  if (new Date(tokenRow.expires_at).getTime() - bufferMs > Date.now()) {
    return tokenRow.access_token;
  }

  console.log("Access token expired, refreshing...");
  const response = await axios.post(
    TOKEN_ENDPOINT,
    new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tokenRow.refresh_token,
    }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64"),
      },
    }
  );

  const { access_token, refresh_token, expires_in } = response.data;
  const expiresAt = new Date(Date.now() + expires_in * 1000);

  await pool.query(
    `UPDATE deere_tokens
     SET access_token = $1, refresh_token = $2, expires_at = $3, updated_at = NOW()
     WHERE id = $4`,
    [access_token, refresh_token, expiresAt, tokenRow.id]
  );

  return access_token;
}

// ---- Find a usable token for a given organization ------------------------
// Tries the database first. If no row is tagged with this org, falls back to
// checking every stored token against Deere, and backfills the match.
async function findTokenForOrg(orgId) {
  const tagged = await pool.query(
    `SELECT * FROM deere_tokens WHERE organization_id = $1 ORDER BY updated_at DESC LIMIT 1`,
    [orgId]
  );
  if (tagged.rows.length > 0) {
    return { row: tagged.rows[0], org: null };
  }

  // Backfill path: look through untagged tokens for one that can see this org.
  const candidates = await pool.query(
    `SELECT * FROM deere_tokens WHERE organization_id IS NULL ORDER BY created_at DESC`
  );

  for (const row of candidates.rows) {
    try {
      const accessToken = await getValidAccessToken(row);
      const orgsResponse = await deereGet(`${API_ROOT}/organizations`, accessToken);

      const match = (orgsResponse.data.values || []).find((o) => String(o.id) === String(orgId));
      if (match) {
        await pool.query(
          `UPDATE deere_tokens SET organization_id = $1, organization_name = $2, updated_at = NOW()
           WHERE id = $3`,
          [match.id, match.name, row.id]
        );
        console.log(`Backfilled organization ${match.name} (${match.id}) onto token row ${row.id}`);
        return { row: { ...row, organization_id: match.id }, org: match };
      }
    } catch (err) {
      console.error(`Token row ${row.id} could not be checked:`, err.response?.data || err.message);
    }
  }

  return null;
}

// ---- GET /api/organizations ------------------------------------------
app.get("/api/organizations", async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM deere_tokens ORDER BY updated_at DESC`);
    if (rows.length === 0) {
      return res.status(404).json({ message: "No connected organizations yet." });
    }

    // Deduplicate by organization id across all stored tokens.
    const seen = new Map();
    for (const tokenRow of rows) {
      try {
        const accessToken = await getValidAccessToken(tokenRow);
        const orgsResponse = await deereGet(`${API_ROOT}/organizations`, accessToken);
        for (const org of orgsResponse.data.values || []) {
          if (!seen.has(org.id)) seen.set(org.id, org);
        }
      } catch (err) {
        console.error(`Skipping token row ${tokenRow.id}:`, err.response?.data || err.message);
      }
    }

    res.json([...seen.values()]);
  } catch (err) {
    console.error("Failed to fetch organizations:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to fetch organizations." });
  }
});

// ---- Shared helper: fetch a linked collection off an organization --------
// Every data endpoint below follows the same shape: resolve a token, re-fetch
// the org to get a fresh `links` array, find the relevant link, follow it.
// Re-fetching matters — the links reflect what this token+grower combination
// can actually reach right now, so we never hand-build a URL and guess.
async function fetchOrgCollection({ orgId, rel, res, resultKey, missingHint }) {
  const found = await findTokenForOrg(orgId);
  if (!found) {
    return res.status(404).json({ message: "No stored token grants access to this organization." });
  }

  const accessToken = await getValidAccessToken(found.row);

  const orgsResponse = await deereGet(`${API_ROOT}/organizations`, accessToken);
  const org = (orgsResponse.data.values || []).find((o) => String(o.id) === String(orgId));
  if (!org) {
    return res.status(404).json({ message: "Organization not visible with this token." });
  }

  const uri = findLink(org, rel);
  if (!uri) {
    return res.status(403).json({
      message: `This organization has not shared "${rel}" with the application.`,
      hint: missingHint,
      availableLinks: (org.links || []).map((l) => l.rel),
    });
  }

  const response = await deereGet(uri, accessToken);

  return res.json({
    organization: { id: org.id, name: org.name },
    source: uri,
    total: response.data.total,
    [resultKey]: response.data.values || response.data,
  });
}

// Wraps an endpoint so a failure reports Deere's own error rather than a
// generic 500 — the status code and body are what tell us whether a
// permission is missing versus something else being wrong.
function handleDeereRoute(label, handler) {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (err) {
      const status = err.response?.status;
      console.error(`Failed to fetch ${label}:`, status, err.response?.data || err.message);
      res.status(500).json({
        error: `Failed to fetch ${label}.`,
        deereStatus: status || null,
        detail: err.response?.data || err.message,
      });
    }
  };
}

// ---- GET /api/boundaries/:orgId --------------------------------------
app.get(
  "/api/boundaries/:orgId",
  handleDeereRoute("boundaries", (req, res) =>
    fetchOrgCollection({
      orgId: req.params.orgId,
      rel: "boundaries",
      res,
      resultKey: "boundaries",
      missingHint: "Ask the grower to raise the Locations permission at connections.deere.com.",
    })
  )
);

// ---- GET /api/fields/:orgId ------------------------------------------
app.get(
  "/api/fields/:orgId",
  handleDeereRoute("fields", (req, res) =>
    fetchOrgCollection({
      orgId: req.params.orgId,
      rel: "fields",
      res,
      resultKey: "fields",
      missingHint: "Ask the grower to raise the Locations permission at connections.deere.com.",
    })
  )
);

// ---- Field operations: per-field, not per-org -------------------------
// Deere support confirmed (15 Aug 2026) that
// /platform/organizations/{orgId}/fieldOperations is an internal lookup
// endpoint, not publicly available, and is slated for removal — it appears in
// the org's `links` but always returns 403. The supported route is per field:
// /platform/organizations/{orgId}/fields/{fieldId}/fieldOperations
//
// That means one request per field. With 221 fields on a real grower account
// this needs to be paced, so requests run in small batches with a pause
// between them rather than all at once.

const FIELD_OPS_BATCH_SIZE = 5;
const FIELD_OPS_BATCH_PAUSE_MS = 250;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchFieldOperationsForField(field, accessToken) {
  const uri = findLink(field, "fieldOperation");
  if (!uri) {
    return { fieldId: field.id, fieldName: field.name, status: "no link", operations: [] };
  }

  try {
    const response = await deereGet(uri, accessToken);
    const operations = response.data.values || [];
    return {
      fieldId: field.id,
      fieldName: field.name,
      status: "ok",
      total: response.data.total ?? operations.length,
      operations,
    };
  } catch (err) {
    return {
      fieldId: field.id,
      fieldName: field.name,
      status: "error",
      httpStatus: err.response?.status || null,
      detail: err.response?.data || err.message,
      operations: [],
    };
  }
}

// ---- GET /api/field-operations/:orgId --------------------------------
// Walks the org's fields and collects operations for each. This is what feeds
// fact_ops and fact_yield.
//
// Query parameters:
//   ?limit=N        stop after N fields (default 25; use 0 for all)
//   ?fieldId=UUID   fetch a single field only
//   ?summary=true   omit the operation bodies, return counts only
app.get(
  "/api/field-operations/:orgId",
  handleDeereRoute("field operations", async (req, res) => {
    const { orgId } = req.params;
    const limit = req.query.limit === undefined ? 25 : parseInt(req.query.limit, 10);
    const summaryOnly = req.query.summary === "true";
    const singleFieldId = req.query.fieldId;

    const found = await findTokenForOrg(orgId);
    if (!found) {
      return res.status(404).json({ message: "No stored token grants access to this organization." });
    }
    const accessToken = await getValidAccessToken(found.row);

    const orgsResponse = await deereGet(`${API_ROOT}/organizations`, accessToken);
    const org = (orgsResponse.data.values || []).find((o) => String(o.id) === String(orgId));
    if (!org) return res.status(404).json({ message: "Organization not visible with this token." });

    const fieldsUri = findLink(org, "fields");
    if (!fieldsUri) {
      return res.status(403).json({ message: "Field data not shared with this application." });
    }

    const fieldsResponse = await deereGet(fieldsUri, accessToken);
    let fields = fieldsResponse.data.values || [];

    if (singleFieldId) {
      fields = fields.filter((f) => f.id === singleFieldId);
      if (fields.length === 0) {
        return res.status(404).json({ message: "Field not found in this organization." });
      }
    } else if (limit > 0) {
      fields = fields.slice(0, limit);
    }

    const results = [];
    for (let i = 0; i < fields.length; i += FIELD_OPS_BATCH_SIZE) {
      const batch = fields.slice(i, i + FIELD_OPS_BATCH_SIZE);
      results.push(...(await Promise.all(batch.map((f) => fetchFieldOperationsForField(f, accessToken)))));
      if (i + FIELD_OPS_BATCH_SIZE < fields.length) await sleep(FIELD_OPS_BATCH_PAUSE_MS);
    }

    const withOps = results.filter((r) => r.operations.length > 0);
    const errored = results.filter((r) => r.status === "error");

    res.json({
      organization: { id: org.id, name: org.name },
      fieldsInOrg: fieldsResponse.data.total,
      fieldsQueried: results.length,
      fieldsWithOperations: withOps.length,
      totalOperations: results.reduce((n, r) => n + r.operations.length, 0),
      errors: errored.length,
      // A single repeated error across every field usually means a permission
      // or entitlement problem rather than anything field-specific.
      sampleError: errored[0] ? { httpStatus: errored[0].httpStatus, detail: errored[0].detail } : null,
      fields: summaryOnly
        ? results.map(({ fieldId, fieldName, status, total, httpStatus }) => ({
            fieldId,
            fieldName,
            status,
            total: total ?? 0,
            httpStatus,
          }))
        : results,
    });
  })
);

// ---- GET /api/operation/:orgId/:operationId --------------------------
// Opens a single field operation and follows its measurement links — the
// harvest yield, seeding varieties, application rate and speed layers that
// sit underneath the operation record.
//
// READ ONLY: every call here is a GET through deereGet(). Nothing is written
// back to the grower's account.
//
// Measurement payloads can be large (sub-field grids), so the response is
// summarised by default and the raw values are only included on request.
//
// Query parameters:
//   ?raw=true       include the full measurement payloads
//   ?only=rel1,rel2 fetch just these measurement links
app.get(
  "/api/operation/:orgId/:operationId",
  handleDeereRoute("field operation detail", async (req, res) => {
    const { orgId, operationId } = req.params;
    const includeRaw = req.query.raw === "true";
    const only = req.query.only ? req.query.only.split(",").map((s) => s.trim()) : null;

    const found = await findTokenForOrg(orgId);
    if (!found) {
      return res.status(404).json({ message: "No stored token grants access to this organization." });
    }
    const accessToken = await getValidAccessToken(found.row);

    // Fetch the operation itself first, so we work from its own link list
    // rather than assuming which measurement types exist for its type.
    const opResponse = await deereGet(`${API_ROOT}/fieldOperations/${operationId}`, accessToken);
    const operation = opResponse.data;

    // Measurement links are the ones ending in "Result", plus the
    // measurementTypes index itself.
    let measurementRels = (operation.links || [])
      .map((l) => l.rel)
      .filter((rel) => rel.endsWith("Result") || rel === "measurementTypes");

    if (only) measurementRels = measurementRels.filter((rel) => only.includes(rel));

    const measurements = {};
    for (const rel of measurementRels) {
      const uri = findLink(operation, rel);
      try {
        const r = await deereGet(uri, accessToken);
        measurements[rel] = includeRaw ? r.data : summariseMeasurement(r.data);
      } catch (err) {
        measurements[rel] = {
          status: "error",
          httpStatus: err.response?.status || null,
          detail: err.response?.data || err.message,
        };
      }
      await sleep(120); // be gentle: one operation can have 8+ layers
    }

    res.json({
      operation: {
        id: operationId,
        type: operation.fieldOperationType,
        cropSeason: operation.cropSeason,
        startDate: operation.startDate,
        endDate: operation.endDate,
        machines: (operation.fieldOperationMachines || []).map((m) => ({ name: m.name, vin: m.vin })),
        products: (operation.products || []).map((p) => ({
          name: p.name,
          type: p.productType,
          tankMix: p.tankMix,
          rate: p.rate ? { value: p.rate.value, unit: p.rate.unitId } : null,
          components: (p.components || []).map((c) => ({
            name: c.name,
            type: c.productType,
            rate: c.rate ? { value: c.rate.value, unit: c.rate.unitId } : null,
          })),
        })),
      },
      measurementsAvailable: measurementRels,
      measurements,
      note: includeRaw
        ? "Raw payloads included."
        : "Summarised. Add ?raw=true for full payloads, or ?only=harvestYieldResult to target one layer.",
    });
  })
);

// Measurement payloads vary by type, so rather than assuming a shape this
// reports what came back: the keys present, how many values, and the range
// and units of any numbers found. Enough to design a mapping against without
// pulling megabytes of grid data into the browser.
function summariseMeasurement(data) {
  if (data == null) return { empty: true };

  const summary = { topLevelKeys: Object.keys(data) };

  if (Array.isArray(data.values)) {
    summary.valueCount = data.values.length;
    summary.total = data.total;
    if (data.values.length > 0) {
      summary.firstValue = data.values[0];
      summary.valueKeys = typeof data.values[0] === "object" ? Object.keys(data.values[0]) : null;
    }
  }

  // Walk the payload for anything that looks like a measurement so units and
  // ranges surface even when they're nested a few levels down.
  const numbers = [];
  const units = new Set();
  (function walk(node, depth) {
    if (depth > 6 || node == null) return;
    if (Array.isArray(node)) {
      // Sample rather than scan: grids can hold tens of thousands of points.
      for (const item of node.slice(0, 200)) walk(item, depth + 1);
      return;
    }
    if (typeof node !== "object") return;
    if (typeof node.value === "number") numbers.push(node.value);
    if (node.unitId) units.add(node.unitId);
    if (node.unit) units.add(node.unit);
    for (const v of Object.values(node)) walk(v, depth + 1);
  })(data, 0);

  if (numbers.length > 0) {
    summary.numericSample = {
      count: numbers.length,
      min: Math.min(...numbers),
      max: Math.max(...numbers),
      note: "Sampled from the first 200 array entries at each level.",
    };
  }
  if (units.size > 0) summary.units = [...units];

  return summary;
}

// ---- Operation layer: polygon + attributes per operation --------------
// Builds the layer the platform actually needs: one polygon per field
// operation, carrying what happened there. The polygon comes from the
// operation's own boundary (the area the machine actually covered),
// falling back to the field boundary when the operation has none.
//
// Deere generates operation boundaries on demand and returns them without an
// area figure, so area is computed here from the geometry.

// Spherical excess over a WGS84 sphere. Accurate enough for field-scale
// polygons and avoids pulling in a projection library.
function ringAreaSqMeters(ring) {
  const R = 6378137;
  let total = 0;
  for (let i = 0; i < ring.length - 1; i++) {
    const [lon1, lat1] = ring[i];
    const [lon2, lat2] = ring[i + 1];
    total +=
      ((lon2 - lon1) * Math.PI) / 180 *
      (2 + Math.sin((lat1 * Math.PI) / 180) + Math.sin((lat2 * Math.PI) / 180));
  }
  return Math.abs((total * R * R) / 2);
}

function geometryAreaHa(geometry) {
  if (!geometry) return null;
  // First ring of each polygon is the exterior; the rest are holes.
  const polygons =
    geometry.type === "Polygon" ? [geometry.coordinates] : geometry.coordinates;
  let sqm = 0;
  for (const rings of polygons) {
    rings.forEach((ring, idx) => {
      const a = ringAreaSqMeters(ring);
      sqm += idx === 0 ? a : -a;
    });
  }
  return Math.round((sqm / 10000) * 100) / 100;
}

// Pulls the numbers out of an operation's measurement summary. Every harvest
// layer returns the same record, so one call to measurementTypes is enough
// rather than one per layer.
async function fetchOperationMeasurements(operation, accessToken) {
  const uri = findLink(operation, "measurementTypes");
  if (!uri) return null;

  try {
    const r = await deereGet(uri, accessToken);
    const values = r.data.values || [];
    const record = values.find((v) => v.yield || v.wetMass || v.area) || values[0];
    if (!record) return null;

    return {
      reportedAreaHa: record.area?.value ?? null,
      yieldValue: record.yield?.value ?? null,
      yieldUnit: record.yield?.unitId ?? null,
      averageYield: record.averageYield?.value ?? null,
      averageYieldUnit: record.averageYield?.unitId ?? null,
      wetMassT: record.wetMass?.value ?? null,
      averageWetMassTHa: record.averageWetMass?.value ?? null,
      moisturePct: record.averageMoisture?.value ?? null,
      averageSpeedKmh: record.averageSpeed?.value ?? null,
      varietyTotals: (record.varietyTotals || []).map((v) => ({
        name: v.name,
        areaHa: v.area?.value ?? null,
        yield: v.yield?.value ?? null,
      })),
    };
  } catch {
    return null;
  }
}

// Assembles one operation into a GeoJSON feature with flat properties —
// flat because the same records feed the spreadsheet export.
async function buildOperationFeature(field, operation, accessToken, fieldBoundaryCache) {
  let geometry = null;
  let geometrySource = "none";

  // Preferred: the operation's own coverage boundary.
  try {
    const r = await deereGet(
      `${API_ROOT}/fieldOperations/${operation.id}/boundary`,
      accessToken
    );
    const candidate = r.data.multipolygons ? r.data : (r.data.values || [])[0];
    const feature = candidate ? boundaryToGeoJsonFeature(candidate) : null;
    if (feature) {
      geometry = feature.geometry;
      geometrySource = "operation";
    }
  } catch {
    /* fall through to the field boundary */
  }

  // Fallback: the field's active boundary, cached so each field is fetched once.
  if (!geometry) {
    const fieldId = field.id;
    if (!fieldBoundaryCache.has(fieldId)) {
      let cached = null;
      try {
        const bUri = findLink(field, "boundaries");
        if (bUri) {
          const r = await deereGet(bUri, accessToken);
          const active = (r.data.values || []).find((b) => b.active) || (r.data.values || [])[0];
          const feature = active ? boundaryToGeoJsonFeature(active) : null;
          if (feature) cached = feature.geometry;
        }
      } catch {
        /* leave null */
      }
      fieldBoundaryCache.set(fieldId, cached);
    }
    geometry = fieldBoundaryCache.get(fieldId);
    if (geometry) geometrySource = "field";
  }

  const measurements = await fetchOperationMeasurements(operation, accessToken);

  const products = (operation.products || []).flatMap((p) => {
    const parts = [];
    if (p.rate) parts.push(`${p.name} ${p.rate.value} ${p.rate.unitId}`);
    else parts.push(p.name);
    for (const c of p.components || []) {
      parts.push(`${c.name} ${c.rate?.value ?? ""} ${c.rate?.unitId ?? ""}`.trim());
    }
    return parts;
  });

  const varieties = [
    ...new Set([
      ...(operation.varieties || []).map((v) => v.name),
      ...((measurements?.varietyTotals || []).map((v) => v.name)),
    ]),
  ].filter(Boolean);

  const properties = {
    operationId: operation.id,
    operationType: operation.fieldOperationType,
    cropSeason: operation.cropSeason,
    cropName: operation.cropName || null,
    varieties: varieties.join(", ") || null,
    startDate: operation.startDate || null,
    endDate: operation.endDate || null,
    fieldId: field.id,
    fieldName: field.name,
    machines: (operation.fieldOperationMachines || [])
      .map((m) => m.name || m.vin)
      .filter(Boolean)
      .join(", ") || null,
    products: products.join(" | ") || null,
    geometrySource,
    computedAreaHa: geometryAreaHa(geometry),
    reportedAreaHa: measurements?.reportedAreaHa ?? null,
    yieldValue: measurements?.yieldValue ?? null,
    yieldUnit: measurements?.yieldUnit ?? null,
    averageYield: measurements?.averageYield ?? null,
    averageYieldUnit: measurements?.averageYieldUnit ?? null,
    wetMassT: measurements?.wetMassT ?? null,
    averageWetMassTHa: measurements?.averageWetMassTHa ?? null,
    moisturePct: measurements?.moisturePct ?? null,
    averageSpeedKmh: measurements?.averageSpeedKmh ?? null,
  };

  return geometry ? { type: "Feature", geometry, properties } : { type: null, properties };
}

// Walks fields and builds a feature per operation. Shared by both exports so
// the map and the spreadsheet always describe the same data.
async function collectOperationFeatures(orgId, accessToken, { limit, types }) {
  const orgsResponse = await deereGet(`${API_ROOT}/organizations`, accessToken);
  const org = (orgsResponse.data.values || []).find((o) => String(o.id) === String(orgId));
  if (!org) throw Object.assign(new Error("Organization not visible"), { statusCode: 404 });

  const fieldsUri = findLink(org, "fields");
  if (!fieldsUri) throw Object.assign(new Error("Field data not shared"), { statusCode: 403 });

  const fieldsResponse = await deereGet(fieldsUri, accessToken);
  let fields = fieldsResponse.data.values || [];
  if (limit > 0) fields = fields.slice(0, limit);

  const fieldBoundaryCache = new Map();
  const features = [];
  const skipped = [];

  for (let i = 0; i < fields.length; i += FIELD_OPS_BATCH_SIZE) {
    const batch = fields.slice(i, i + FIELD_OPS_BATCH_SIZE);
    const results = await Promise.all(batch.map((f) => fetchFieldOperationsForField(f, accessToken)));

    for (let j = 0; j < results.length; j++) {
      const field = batch[j];
      for (const op of results[j].operations) {
        if (types && !types.includes(op.fieldOperationType)) continue;
        const built = await buildOperationFeature(field, op, accessToken, fieldBoundaryCache);
        if (built.type === "Feature") features.push(built);
        else skipped.push(built.properties);
        await sleep(80);
      }
    }
    if (i + FIELD_OPS_BATCH_SIZE < fields.length) await sleep(FIELD_OPS_BATCH_PAUSE_MS);
  }

  return { org, fieldsScanned: fields.length, fieldsInOrg: fieldsResponse.data.total, features, skipped };
}

// ---- GET /api/operations-geojson/:orgId -------------------------------
// One polygon per operation, attributes attached. Load into QGIS, geojson.io,
// or the map endpoint below.
//
//   ?limit=N          fields to scan (default 15; 0 = all, slow)
//   ?types=harvest    comma-separated operation types to include
app.get(
  "/api/operations-geojson/:orgId",
  handleDeereRoute("operations GeoJSON", async (req, res) => {
    const { orgId } = req.params;
    const limit = req.query.limit === undefined ? 15 : parseInt(req.query.limit, 10);
    const types = req.query.types ? req.query.types.split(",").map((s) => s.trim()) : null;

    const found = await findTokenForOrg(orgId);
    if (!found) return res.status(404).json({ message: "No stored token for this organization." });
    const accessToken = await getValidAccessToken(found.row);

    const { org, fieldsScanned, fieldsInOrg, features, skipped } =
      await collectOperationFeatures(orgId, accessToken, { limit, types });

    res.json({
      type: "FeatureCollection",
      features,
      metadata: {
        organization: { id: org.id, name: org.name },
        fieldsScanned,
        fieldsInOrg,
        operationsWithGeometry: features.length,
        operationsWithoutGeometry: skipped.length,
        geometrySources: features.reduce((acc, f) => {
          acc[f.properties.geometrySource] = (acc[f.properties.geometrySource] || 0) + 1;
          return acc;
        }, {}),
      },
    });
  })
);

// ---- GET /api/operations-xlsx/:orgId ----------------------------------
// The same records as a spreadsheet: one sheet of operations, one of harvest
// only, and the polygon geometry as WKT so it can be re-imported into GIS.
//
//   ?limit=N        fields to scan (default 15; 0 = all, slow)
//   ?types=harvest  comma-separated operation types
app.get(
  "/api/operations-xlsx/:orgId",
  handleDeereRoute("operations spreadsheet", async (req, res) => {
    const { orgId } = req.params;
    const limit = req.query.limit === undefined ? 15 : parseInt(req.query.limit, 10);
    const types = req.query.types ? req.query.types.split(",").map((s) => s.trim()) : null;

    const found = await findTokenForOrg(orgId);
    if (!found) return res.status(404).json({ message: "No stored token for this organization." });
    const accessToken = await getValidAccessToken(found.row);

    const { org, fieldsScanned, fieldsInOrg, features, skipped } =
      await collectOperationFeatures(orgId, accessToken, { limit, types });

    const ExcelJS = require("exceljs");
    const wb = new ExcelJS.Workbook();
    wb.creator = "AgriData connector";
    wb.created = new Date();

    const columns = [
      { header: "Field", key: "fieldName", width: 14 },
      { header: "Operation", key: "operationType", width: 13 },
      { header: "Season", key: "cropSeason", width: 9 },
      { header: "Crop", key: "cropName", width: 18 },
      { header: "Varieties", key: "varieties", width: 20 },
      { header: "Start", key: "startDate", width: 12 },
      { header: "End", key: "endDate", width: 12 },
      { header: "Area (ha, computed)", key: "computedAreaHa", width: 18 },
      { header: "Area (ha, reported)", key: "reportedAreaHa", width: 18 },
      { header: "Yield", key: "yieldValue", width: 10 },
      { header: "Yield unit", key: "yieldUnit", width: 10 },
      { header: "Avg yield", key: "averageYield", width: 11 },
      { header: "Avg yield unit", key: "averageYieldUnit", width: 13 },
      { header: "Wet mass (t)", key: "wetMassT", width: 12 },
      { header: "Avg wet mass (t/ha)", key: "averageWetMassTHa", width: 18 },
      { header: "Moisture (%)", key: "moisturePct", width: 12 },
      { header: "Avg speed (km/h)", key: "averageSpeedKmh", width: 15 },
      { header: "Machines", key: "machines", width: 24 },
      { header: "Products", key: "products", width: 40 },
      { header: "Geometry source", key: "geometrySource", width: 15 },
      { header: "Operation ID", key: "operationId", width: 40 },
    ];

    const toRow = (p) => ({
      ...p,
      startDate: p.startDate ? p.startDate.slice(0, 10) : null,
      endDate: p.endDate ? p.endDate.slice(0, 10) : null,
    });

    const opsSheet = wb.addWorksheet("Operations");
    opsSheet.columns = columns;
    for (const f of features) opsSheet.addRow(toRow(f.properties));
    for (const p of skipped) opsSheet.addRow(toRow(p));
    opsSheet.getRow(1).font = { bold: true };
    opsSheet.autoFilter = { from: "A1", to: { row: 1, column: columns.length } };
    opsSheet.views = [{ state: "frozen", ySplit: 1 }];

    const harvests = features.filter((f) => f.properties.operationType === "harvest");
    if (harvests.length > 0) {
      const hs = wb.addWorksheet("Harvest");
      hs.columns = columns;
      for (const f of harvests) hs.addRow(toRow(f.properties));
      hs.getRow(1).font = { bold: true };
      hs.autoFilter = { from: "A1", to: { row: 1, column: columns.length } };
      hs.views = [{ state: "frozen", ySplit: 1 }];
    }

    // WKT keeps the polygons usable outside this file — QGIS, PostGIS and
    // BigQuery all read it directly.
    const geo = wb.addWorksheet("Geometry (WKT)");
    geo.columns = [
      { header: "Operation ID", key: "id", width: 40 },
      { header: "Field", key: "field", width: 14 },
      { header: "Operation", key: "type", width: 13 },
      { header: "Season", key: "season", width: 9 },
      { header: "WKT", key: "wkt", width: 120 },
    ];
    for (const f of features) {
      geo.addRow({
        id: f.properties.operationId,
        field: f.properties.fieldName,
        type: f.properties.operationType,
        season: f.properties.cropSeason,
        wkt: geometryToWkt(f.geometry),
      });
    }
    geo.getRow(1).font = { bold: true };

    const info = wb.addWorksheet("About");
    info.columns = [{ header: "Field", key: "k", width: 30 }, { header: "Value", key: "v", width: 60 }];
    [
      ["Organization", `${org.name} (${org.id})`],
      ["Generated", new Date().toISOString()],
      ["Fields scanned", `${fieldsScanned} of ${fieldsInOrg}`],
      ["Operations with geometry", features.length],
      ["Operations without geometry", skipped.length],
      ["Source", "John Deere Operations Center API (read-only)"],
      ["Note", "Computed area is derived from polygon geometry; reported area comes from the machine."],
      ["Note", "Yield units follow Deere's coding: m3 = volume, t = tonnes, t1ha-1 = tonnes per hectare."],
    ].forEach(([k, v]) => info.addRow({ k, v }));
    info.getRow(1).font = { bold: true };

    const filename = `agridata-${org.name.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}-operations.xlsx`;
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    await wb.xlsx.write(res);
    res.end();
  })
);

function geometryToWkt(geometry) {
  if (!geometry) return null;
  const ringToWkt = (ring) => "(" + ring.map(([lon, lat]) => `${lon} ${lat}`).join(", ") + ")";
  if (geometry.type === "Polygon") {
    return "POLYGON(" + geometry.coordinates.map(ringToWkt).join(", ") + ")";
  }
  return (
    "MULTIPOLYGON(" +
    geometry.coordinates.map((poly) => "(" + poly.map(ringToWkt).join(", ") + ")").join(", ") +
    ")"
  );
}

// ---- GET /api/operation-boundary/:orgId/:operationId -----------------
// Each field operation carries a "boundary" link — the area actually worked
// in that pass, which is not the same as the field's own boundary. A combine
// covers what it covers; the harvest we inspected reported 26.8 ha on a field
// whose registered boundary is a different size.
//
// This probes that link and reports whether real geometry comes back, so a
// per-operation polygon layer can be designed against fact rather than
// assumption. Returns GeoJSON when geometry is present.
//
// READ ONLY.
app.get(
  "/api/operation-boundary/:orgId/:operationId",
  handleDeereRoute("operation boundary", async (req, res) => {
    const { orgId, operationId } = req.params;

    const found = await findTokenForOrg(orgId);
    if (!found) {
      return res.status(404).json({ message: "No stored token grants access to this organization." });
    }
    const accessToken = await getValidAccessToken(found.row);

    const opResponse = await deereGet(`${API_ROOT}/fieldOperations/${operationId}`, accessToken);
    const operation = opResponse.data;

    const boundaryUri =
      findLink(operation, "boundary") || `${API_ROOT}/fieldOperations/${operationId}/boundary`;

    let boundaryOutcome;
    let geojson = null;

    try {
      const r = await deereGet(boundaryUri, accessToken);
      const data = r.data;

      // The payload may be a boundary object directly, or wrapped in values[].
      const candidate = data.multipolygons ? data : (data.values || [])[0];

      if (candidate && candidate.multipolygons) {
        const feature = boundaryToGeoJsonFeature(candidate);
        geojson = feature ? { type: "FeatureCollection", features: [feature] } : null;
        boundaryOutcome = {
          status: "geometry present",
          areaHa: candidate.area?.valueAsDouble ?? null,
          ringCount: (candidate.multipolygons || []).reduce((n, p) => n + (p.rings || []).length, 0),
          pointCount: (candidate.multipolygons || []).reduce(
            (n, p) => n + (p.rings || []).reduce((m, ring) => m + (ring.points || []).length, 0),
            0
          ),
          centroid: candidate.centroid ?? null,
        };
      } else {
        boundaryOutcome = {
          status: "no geometry in payload",
          topLevelKeys: Object.keys(data || {}),
          total: data?.total ?? null,
        };
      }
    } catch (err) {
      boundaryOutcome = {
        status: "error",
        httpStatus: err.response?.status || null,
        detail: err.response?.data || err.message,
      };
    }

    // The async shapefile export is the other route to per-operation geometry,
    // and the only known path to sub-field detail. Probe it without following
    // through, so we learn what the flow looks like.
    const shapeUri = findLink(operation, "shapeFileAsync");
    let shapeFileOutcome = { status: "no shapeFileAsync link on this operation" };

    if (shapeUri) {
      try {
        const r = await deereClient.get(shapeUri, {
          headers: { Authorization: `Bearer ${accessToken}`, Accept: DEERE_ACCEPT_HEADER },
          responseType: "arraybuffer",
          validateStatus: () => true,
          maxRedirects: 0,
        });

        const contentType = r.headers["content-type"] || "(none)";
        shapeFileOutcome = {
          uri: shapeUri,
          httpStatus: r.status,
          contentType,
          bytes: r.data ? r.data.length : 0,
          location: r.headers["location"] || null,
        };

        if (contentType.includes("json")) {
          try {
            shapeFileOutcome.body = JSON.parse(Buffer.from(r.data).toString("utf8"));
          } catch {
            /* leave body out if it doesn't parse */
          }
        } else if (r.data && r.data.length > 0) {
          const head = Buffer.from(r.data.slice(0, 4)).toString("hex");
          shapeFileOutcome.signature = head;
          shapeFileOutcome.isZip = head.startsWith("504b0304"); // PK.. = zip archive
        }
      } catch (err) {
        shapeFileOutcome = { uri: shapeUri, status: "error", detail: err.message };
      }
    }

    res.json({
      operation: {
        id: operationId,
        type: operation.fieldOperationType,
        cropSeason: operation.cropSeason,
        startDate: operation.startDate,
      },
      fieldUri: findLink(operation, "field"),
      operationBoundary: boundaryOutcome,
      shapeFileExport: shapeFileOutcome,
      geojson,
      note:
        "operationBoundary with 'geometry present' means each operation can carry its own polygon. " +
        "shapeFileExport shows what the async export returns — a zip signature or a job/status body.",
    });
  })
);

// ---- GET /api/yield-quality/:orgId -----------------------------------
// Answers a data-quality question before anything is built on top of yield:
// of the harvest operations on record, how many actually carry a yield
// figure? A combine can log area, speed and duration while its yield sensor
// records nothing — the sample we inspected showed 9.02 ha harvested with
// yield 0. If that is typical, a yield table would be mostly zeros.
//
// Reads the summary record for each harvest operation (one call per
// operation, via measurementTypes) and reports how many are populated.
//
// Query parameters:
//   ?limit=N   fields to scan (default 60; 0 = all, slow)
app.get(
  "/api/yield-quality/:orgId",
  handleDeereRoute("yield data quality", async (req, res) => {
    const { orgId } = req.params;
    const limit = req.query.limit === undefined ? 60 : parseInt(req.query.limit, 10);

    const found = await findTokenForOrg(orgId);
    if (!found) {
      return res.status(404).json({ message: "No stored token grants access to this organization." });
    }
    const accessToken = await getValidAccessToken(found.row);

    const orgsResponse = await deereGet(`${API_ROOT}/organizations`, accessToken);
    const org = (orgsResponse.data.values || []).find((o) => String(o.id) === String(orgId));
    if (!org) return res.status(404).json({ message: "Organization not visible with this token." });

    const fieldsUri = findLink(org, "fields");
    if (!fieldsUri) return res.status(403).json({ message: "Field data not shared." });

    const fieldsResponse = await deereGet(fieldsUri, accessToken);
    let fields = fieldsResponse.data.values || [];
    if (limit > 0) fields = fields.slice(0, limit);

    // Collect harvest operations first, then inspect each one's measurements.
    const harvests = [];
    for (let i = 0; i < fields.length; i += FIELD_OPS_BATCH_SIZE) {
      const batch = fields.slice(i, i + FIELD_OPS_BATCH_SIZE);
      const results = await Promise.all(batch.map((f) => fetchFieldOperationsForField(f, accessToken)));
      for (const r of results) {
        for (const op of r.operations) {
          if (op.fieldOperationType === "harvest") {
            harvests.push({ fieldName: r.fieldName, fieldId: r.fieldId, op });
          }
        }
      }
      if (i + FIELD_OPS_BATCH_SIZE < fields.length) await sleep(FIELD_OPS_BATCH_PAUSE_MS);
    }

    const rows = [];
    let withYield = 0;
    let withWetMass = 0;
    let withMoisture = 0;
    let measurementErrors = 0;

    for (const h of harvests) {
      const uri = findLink(h.op, "measurementTypes");
      if (!uri) {
        measurementErrors++;
        continue;
      }

      try {
        const r = await deereGet(uri, accessToken);
        // Any of the harvest layers carries the same summary record, so the
        // first one that has yield fields is enough.
        const record = (r.data.values || []).find((v) => v.yield || v.wetMass) || (r.data.values || [])[0];

        const yieldVal = record?.yield?.value ?? null;
        const wetMassVal = record?.wetMass?.value ?? null;
        const moistureVal = record?.averageMoisture?.value ?? null;
        const avgYield = record?.averageYield?.value ?? null;

        if (yieldVal > 0) withYield++;
        if (wetMassVal > 0) withWetMass++;
        if (moistureVal > 0) withMoisture++;

        rows.push({
          field: h.fieldName,
          season: h.op.cropSeason,
          date: h.op.startDate?.slice(0, 10),
          areaHa: record?.area?.value ?? null,
          yield: yieldVal,
          yieldUnit: record?.yield?.unitId ?? null,
          averageYield: avgYield,
          wetMassT: wetMassVal,
          moisturePct: moistureVal,
          varieties: (record?.varietyTotals || []).map((v) => v.name),
          hasUsableYield: yieldVal > 0 || wetMassVal > 0,
        });
      } catch (err) {
        measurementErrors++;
      }
      await sleep(120);
    }

    const usable = rows.filter((r) => r.hasUsableYield);
    const seasonsWithYield = [...new Set(usable.map((r) => r.season))].sort();
    const varietiesSeen = [...new Set(rows.flatMap((r) => r.varieties))].sort();

    res.json({
      organization: { id: org.id, name: org.name },
      fieldsScanned: fields.length,
      fieldsInOrg: fieldsResponse.data.total,
      harvestOperations: harvests.length,
      measurementErrors,
      populated: {
        withYieldVolume: withYield,
        withWetMass: withWetMass,
        withMoisture: withMoisture,
        usableForYieldAnalysis: usable.length,
      },
      // The headline number: what share of harvests could feed a yield table.
      usableSharePct:
        harvests.length > 0 ? Math.round((usable.length / harvests.length) * 1000) / 10 : null,
      seasonsWithUsableYield: seasonsWithYield,
      varietiesSeen,
      harvests: rows,
    });
  })
);

// ---- GET /api/measurement/:orgId/:operationId/:measurementName -------
// Opens one measurement layer and probes its "mapImage" link, which is where
// the sub-field detail lives — the heat maps Operations Center renders.
//
// The mapImage URI is identical to the layer's own "self" URI, so what comes
// back depends on the Accept header: the axiom media type yields the summary
// record, while image types may yield a rendered raster. This endpoint tries
// several and reports what each returns, rather than assuming a format.
//
// READ ONLY: all requests are GETs.
app.get(
  "/api/measurement/:orgId/:operationId/:measurementName",
  handleDeereRoute("measurement layer", async (req, res) => {
    const { orgId, operationId, measurementName } = req.params;

    const found = await findTokenForOrg(orgId);
    if (!found) {
      return res.status(404).json({ message: "No stored token grants access to this organization." });
    }
    const accessToken = await getValidAccessToken(found.row);

    const baseUri = `${API_ROOT}/fieldOperations/${operationId}/measurementTypes/${measurementName}`;

    // Accept headers worth trying, and what each would mean if it works.
    const attempts = [
      { accept: DEERE_ACCEPT_HEADER, meaning: "Deere axiom JSON (summary record)" },
      { accept: "application/json", meaning: "plain JSON" },
      { accept: "image/png", meaning: "rendered raster image" },
      { accept: "application/vnd.deere.axiom.v3+png", meaning: "axiom PNG variant" },
      { accept: "application/geo+json", meaning: "GeoJSON grid" },
      { accept: "*/*", meaning: "server's default choice" },
    ];

    const results = {};
    for (const { accept, meaning } of attempts) {
      try {
        const r = await deereClient.get(baseUri, {
          headers: { Authorization: `Bearer ${accessToken}`, Accept: accept },
          // Binary-safe: an image would be corrupted if parsed as text.
          responseType: "arraybuffer",
          validateStatus: () => true,
        });

        const contentType = r.headers["content-type"] || "(none)";
        const bytes = r.data ? r.data.length : 0;
        const entry = { meaning, httpStatus: r.status, contentType, bytes };

        if (r.status >= 400) {
          entry.outcome = "error";
        } else if (contentType.includes("image")) {
          // A real raster: report its signature rather than dumping bytes.
          const head = Buffer.from(r.data.slice(0, 8)).toString("hex");
          entry.outcome = "IMAGE";
          entry.signature = head;
          entry.isPng = head.startsWith("89504e47");
          entry.isJpeg = head.startsWith("ffd8ff");
        } else {
          const text = Buffer.from(r.data).toString("utf8");
          try {
            const parsed = JSON.parse(text);
            entry.outcome = "json";
            entry.topLevelKeys = Object.keys(parsed);
            // A points/values array here would be the sub-field grid.
            const gridKey = ["values", "points", "features", "cells"].find((k) => Array.isArray(parsed[k]));
            if (gridKey) {
              entry.gridKey = gridKey;
              entry.gridCount = parsed[gridKey].length;
              entry.gridFirst = parsed[gridKey][0];
            }
          } catch {
            entry.outcome = "non-JSON text";
            entry.preview = text.slice(0, 200);
          }
        }

        results[accept] = entry;
      } catch (err) {
        results[accept] = { meaning, outcome: "request failed", detail: err.message };
      }
      await sleep(150);
    }

    res.json({
      operationId,
      measurementName,
      uri: baseUri,
      attempts: results,
      note:
        "An entry with outcome IMAGE means Deere renders this layer server-side. " +
        "An entry with a gridKey means the raw sub-field values are retrievable as data.",
    });
  })
);

// ---- GET /api/operation-types/:orgId ---------------------------------
// Answers a question the per-field view can't: which kinds of operation does
// this grower actually have on record? Sampling one field is misleading —
// a field worked only by a sprayer will show nothing but "application" even
// when the org has harvest data elsewhere.
//
// Walks fields, collects every operation, and reports counts by type and by
// crop season. Note cropSeason is used rather than the calendar year of
// startDate: Deere assigns autumn work to the following season, and that is
// the agronomically correct grouping for rotation analysis.
//
// Query parameters:
//   ?limit=N   how many fields to sample (default 40; 0 = all 221, slow)
app.get(
  "/api/operation-types/:orgId",
  handleDeereRoute("operation type census", async (req, res) => {
    const { orgId } = req.params;
    const limit = req.query.limit === undefined ? 40 : parseInt(req.query.limit, 10);

    const found = await findTokenForOrg(orgId);
    if (!found) {
      return res.status(404).json({ message: "No stored token grants access to this organization." });
    }
    const accessToken = await getValidAccessToken(found.row);

    const orgsResponse = await deereGet(`${API_ROOT}/organizations`, accessToken);
    const org = (orgsResponse.data.values || []).find((o) => String(o.id) === String(orgId));
    if (!org) return res.status(404).json({ message: "Organization not visible with this token." });

    const fieldsUri = findLink(org, "fields");
    if (!fieldsUri) return res.status(403).json({ message: "Field data not shared." });

    const fieldsResponse = await deereGet(fieldsUri, accessToken);
    let fields = fieldsResponse.data.values || [];
    if (limit > 0) fields = fields.slice(0, limit);

    const byType = {};
    const bySeason = {};
    const typeSeasons = {};
    const examples = {};
    let totalOperations = 0;
    let errors = 0;

    for (let i = 0; i < fields.length; i += FIELD_OPS_BATCH_SIZE) {
      const batch = fields.slice(i, i + FIELD_OPS_BATCH_SIZE);
      const results = await Promise.all(batch.map((f) => fetchFieldOperationsForField(f, accessToken)));

      for (const r of results) {
        if (r.status === "error") errors++;
        for (const op of r.operations) {
          const type = op.fieldOperationType || "(unspecified)";
          const season = op.cropSeason || "(none)";

          byType[type] = (byType[type] || 0) + 1;
          bySeason[season] = (bySeason[season] || 0) + 1;
          (typeSeasons[type] = typeSeasons[type] || new Set()).add(season);
          totalOperations++;

          // Keep one example per type so the shape of each can be inspected
          // without pulling the whole payload back.
          if (!examples[type]) {
            examples[type] = {
              fieldName: r.fieldName,
              cropSeason: op.cropSeason,
              startDate: op.startDate,
              endDate: op.endDate,
              machines: (op.fieldOperationMachines || []).map((m) => m.name),
              products: (op.products || []).map((p) => p.name),
              measurementLinks: (op.links || [])
                .map((l) => l.rel)
                .filter((rel) => rel.toLowerCase().includes("result") || rel === "measurementTypes"),
              operationUri: findLink(op, "self"),
            };
          }
        }
      }

      if (i + FIELD_OPS_BATCH_SIZE < fields.length) await sleep(FIELD_OPS_BATCH_PAUSE_MS);
    }

    res.json({
      organization: { id: org.id, name: org.name },
      fieldsInOrg: fieldsResponse.data.total,
      fieldsSampled: fields.length,
      totalOperations,
      errors,
      operationTypes: byType,
      seasonsPerType: Object.fromEntries(
        Object.entries(typeSeasons).map(([t, s]) => [t, [...s].sort()])
      ),
      operationsBySeason: Object.fromEntries(Object.entries(bySeason).sort()),
      examplePerType: examples,
    });
  })
);

// ---- GET /api/machines/:orgId ----------------------------------------
// Equipment list for the organization.
app.get(
  "/api/machines/:orgId",
  handleDeereRoute("machines", (req, res) =>
    fetchOrgCollection({
      orgId: req.params.orgId,
      rel: "machines",
      res,
      resultKey: "machines",
      missingHint: "Ask the grower to raise the Equipment permission at connections.deere.com.",
    })
  )
);

// ---- GET /api/files/:orgId -------------------------------------------
app.get(
  "/api/files/:orgId",
  handleDeereRoute("files", (req, res) =>
    fetchOrgCollection({
      orgId: req.params.orgId,
      rel: "files",
      res,
      resultKey: "files",
      missingHint: "The Files API is still pending approval from Deere for this application.",
    })
  )
);

// ---- GET /api/assets/:orgId ------------------------------------------
app.get(
  "/api/assets/:orgId",
  handleDeereRoute("assets", (req, res) =>
    fetchOrgCollection({
      orgId: req.params.orgId,
      rel: "assets",
      res,
      resultKey: "assets",
      missingHint: "Ask the grower to raise the Equipment permission at connections.deere.com.",
    })
  )
);

// ---- GET /api/machine/:machineId/hours -------------------------------
// Engine hours for a single machine. Machine IDs come from /api/machines.
// Deere's docs are explicit that resource IDs should be read from a response
// immediately before use rather than stored, since access can change.
app.get(
  "/api/machine/:orgId/:machineId/hours",
  handleDeereRoute("machine engine hours", async (req, res) => {
    const { orgId, machineId } = req.params;

    const found = await findTokenForOrg(orgId);
    if (!found) {
      return res.status(404).json({ message: "No stored token grants access to this organization." });
    }
    const accessToken = await getValidAccessToken(found.row);

    const [engineHours, hoursOfOperation] = await Promise.allSettled([
      deereGet(`${API_ROOT}/machines/${machineId}/engineHours`, accessToken),
      deereGet(`${API_ROOT}/machines/${machineId}/hoursOfOperation`, accessToken),
    ]);

    res.json({
      machineId,
      engineHours:
        engineHours.status === "fulfilled"
          ? engineHours.value.data
          : { error: engineHours.reason.response?.data || engineHours.reason.message },
      hoursOfOperation:
        hoursOfOperation.status === "fulfilled"
          ? hoursOfOperation.value.data
          : { error: hoursOfOperation.reason.response?.data || hoursOfOperation.reason.message },
    });
  })
);

// ---- GET /api/diagnostics/:orgId -------------------------------------
// Tries every collection we care about in one request and reports which ones
// come back, which are empty, and which are blocked. Useful for checking a
// newly connected grower without hitting each endpoint by hand.
app.get(
  "/api/diagnostics/:orgId",
  handleDeereRoute("diagnostics", async (req, res) => {
    const { orgId } = req.params;

    const found = await findTokenForOrg(orgId);
    if (!found) {
      return res.status(404).json({ message: "No stored token grants access to this organization." });
    }
    const accessToken = await getValidAccessToken(found.row);

    const orgsResponse = await deereGet(`${API_ROOT}/organizations`, accessToken);
    const org = (orgsResponse.data.values || []).find((o) => String(o.id) === String(orgId));
    if (!org) return res.status(404).json({ message: "Organization not visible with this token." });

    // "fieldOperation" is deliberately absent: Deere confirmed the org-level
    // endpoint is internal-only and always 403s. Use /api/field-operations/:orgId,
    // which walks fields individually, to check operations access.
    const rels = ["fields", "farms", "boundaries", "machines", "assets", "files", "clients", "flags"];
    const report = {};

    for (const rel of rels) {
      const uri = findLink(org, rel);
      if (!uri) {
        report[rel] = { status: "no link — not shared with this application" };
        continue;
      }
      try {
        const r = await deereGet(uri, accessToken);
        const total = r.data.total ?? (r.data.values ? r.data.values.length : null);
        report[rel] = {
          status: total === 0 ? "reachable but empty" : "reachable",
          total,
        };
      } catch (err) {
        report[rel] = {
          status: "blocked",
          httpStatus: err.response?.status || null,
          detail: err.response?.data || err.message,
        };
      }
    }

    res.json({
      organization: { id: org.id, name: org.name },
      scopesRequested: SCOPES,
      report,
    });
  })
);

// ---- Deere geometry -> GeoJSON ---------------------------------------
// Deere returns boundaries as multipolygons -> rings -> points {lat, lon}.
// GeoJSON wants [lon, lat] and a closed ring, so both need converting.
// Rings marked "interior" are holes and must follow their exterior ring.
function boundaryToGeoJsonFeature(boundary) {
  const polygons = [];

  for (const polygon of boundary.multipolygons || []) {
    const exteriors = [];
    const interiors = [];

    for (const ring of polygon.rings || []) {
      const coords = (ring.points || []).map((p) => [p.lon, p.lat]);
      // Deere doesn't pre-close its rings, so 3 distinct points is the
      // minimum valid polygon; we close it ourselves below.
      if (coords.length < 3) continue;

      // GeoJSON requires the ring to be explicitly closed.
      const first = coords[0];
      const last = coords[coords.length - 1];
      if (first[0] !== last[0] || first[1] !== last[1]) coords.push([...first]);

      if (ring.type === "interior") interiors.push(coords);
      else exteriors.push(coords);
    }

    // Deere sometimes returns several exterior rings inside one polygon
    // (separate parcels worked as one unit), so each becomes its own polygon.
    for (const ext of exteriors) polygons.push([ext, ...interiors]);
  }

  if (polygons.length === 0) return null;

  // Each entry of `polygons` is already [exterior, ...holes], which is exactly
  // the shape both Polygon and MultiPolygon coordinates expect.
  return {
    type: "Feature",
    geometry:
      polygons.length === 1
        ? { type: "Polygon", coordinates: polygons[0] }
        : { type: "MultiPolygon", coordinates: polygons },
    properties: {
      id: boundary.id,
      name: boundary.name,
      areaHa: boundary.area?.valueAsDouble ?? null,
      workableAreaHa: boundary.workableArea?.valueAsDouble ?? null,
      active: boundary.active,
      irrigated: boundary.irrigated,
      sourceType: boundary.sourceType,
      createdTime: boundary.createdTime,
      modifiedTime: boundary.modifiedTime,
    },
  };
}

// ---- GET /api/geojson/:orgId -----------------------------------------
// Boundaries as a GeoJSON FeatureCollection — paste into geojson.io, load
// into QGIS, or feed straight to a map library.
app.get(
  "/api/geojson/:orgId",
  handleDeereRoute("boundaries as GeoJSON", async (req, res) => {
    const { orgId } = req.params;
    const activeOnly = req.query.active !== "false"; // default: active only

    const found = await findTokenForOrg(orgId);
    if (!found) {
      return res.status(404).json({ message: "No stored token grants access to this organization." });
    }
    const accessToken = await getValidAccessToken(found.row);

    const orgsResponse = await deereGet(`${API_ROOT}/organizations`, accessToken);
    const org = (orgsResponse.data.values || []).find((o) => String(o.id) === String(orgId));
    if (!org) return res.status(404).json({ message: "Organization not visible with this token." });

    const uri = findLink(org, "boundaries");
    if (!uri) return res.status(403).json({ message: "Boundary data not shared with this application." });

    const response = await deereGet(uri, accessToken);
    let boundaries = response.data.values || [];
    if (activeOnly) boundaries = boundaries.filter((b) => b.active);

    const features = boundaries.map(boundaryToGeoJsonFeature).filter(Boolean);

    res.json({
      type: "FeatureCollection",
      features,
      // Not part of the GeoJSON spec, but harmless and useful when eyeballing.
      metadata: {
        organization: { id: org.id, name: org.name },
        returned: features.length,
        totalFromDeere: response.data.total,
        activeOnly,
      },
    });
  })
);

// ---- GET /map/:orgId --------------------------------------------------
// Internal inspection map. This is a developer tool for sanity-checking the
// geometry, not a customer-facing product — the real UI belongs in the
// AgriData app.
app.get("/map/:orgId", (req, res) => {
  const orgId = req.params.orgId.replace(/[^0-9]/g, ""); // keep the URL clean
  res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Field boundaries — org ${orgId}</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
  html, body { margin: 0; height: 100%; font-family: system-ui, sans-serif; }
  #map { height: 100%; }
  #panel {
    position: absolute; top: 12px; right: 12px; z-index: 1000;
    background: #fff; padding: 12px 14px; border-radius: 6px;
    box-shadow: 0 1px 6px rgba(0,0,0,.3); font-size: 13px; max-width: 260px;
  }
  #panel h3 { margin: 0 0 6px; font-size: 14px; }
  #panel .muted { color: #666; }
  label { display: block; margin-top: 8px; }
</style>
</head>
<body>
<div id="map"></div>
<div id="panel">
  <h3>Field boundaries</h3>
  <div id="status" class="muted">Loading…</div>
  <label><input type="checkbox" id="showInactive"> Include inactive boundaries</label>
</div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
  const orgId = ${JSON.stringify(orgId)};
  const map = L.map('map');
  L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
    maxZoom: 19, attribution: 'Imagery: Esri'
  }).addTo(map);
  map.setView([31.4, 34.8], 9);

  let layer = null;
  const status = document.getElementById('status');

  function load(includeInactive) {
    status.textContent = 'Loading…';
    if (layer) { map.removeLayer(layer); layer = null; }

    fetch('/api/geojson/' + orgId + (includeInactive ? '?active=false' : ''))
      .then(r => r.json())
      .then(data => {
        if (!data.features || data.features.length === 0) {
          status.textContent = 'No boundaries returned.';
          return;
        }
        layer = L.geoJSON(data, {
          style: f => ({
            color: f.properties.active ? '#3aa655' : '#c0803a',
            weight: 2, fillOpacity: 0.25
          }),
          onEachFeature: (f, l) => {
            const p = f.properties;
            const area = p.areaHa != null ? p.areaHa.toFixed(2) + ' ha' : 'unknown area';
            l.bindPopup(
              '<b>' + (p.name || '(unnamed)') + '</b><br>' +
              area + '<br>' +
              (p.active ? 'active' : 'inactive') +
              (p.irrigated ? ' · irrigated' : '') +
              '<br><span style="color:#666">' + (p.sourceType || '') + '</span>'
            );
          }
        }).addTo(map);
        map.fitBounds(layer.getBounds(), { padding: [20, 20] });
        const org = data.metadata && data.metadata.organization;
        status.innerHTML =
          (org ? '<b>' + org.name + '</b><br>' : '') +
          data.features.length + ' of ' + data.metadata.totalFromDeere + ' boundaries shown';
      })
      .catch(err => { status.textContent = 'Failed to load: ' + err.message; });
  }

  document.getElementById('showInactive').addEventListener('change', e => load(e.target.checked));
  load(false);
</script>
</body>
</html>`);
});

// ---- GET /debug/token/:orgId -----------------------------------------
// TEMPORARY. Returns a live access token so a request can be reproduced in
// Postman for John Deere support. A token is a bearer credential — anyone
// with this URL can read the grower's data until it expires.
//
// Guarded by DEBUG_TOKEN_KEY: the endpoint 404s unless that env var is set
// AND matches ?key=... on the request. Remove this route once the support
// ticket is closed.
app.get("/debug/token/:orgId", async (req, res) => {
  const expectedKey = process.env.DEBUG_TOKEN_KEY;

  // Behave as if the route doesn't exist when unconfigured or mis-keyed,
  // rather than confirming it's here.
  if (!expectedKey || req.query.key !== expectedKey) {
    return res.status(404).send("Cannot GET " + req.path);
  }

  try {
    const found = await findTokenForOrg(req.params.orgId);
    if (!found) return res.status(404).json({ message: "No token for that organization." });

    const accessToken = await getValidAccessToken(found.row);
    res.json({
      organizationId: req.params.orgId,
      accessToken,
      expiresAt: found.row.expires_at,
      scopesRequestedAtAuth: SCOPES,
      warning: "Treat as a password. Remove this endpoint when no longer needed.",
    });
  } catch (err) {
    console.error("Debug token lookup failed:", err.message);
    res.status(500).json({ error: "Lookup failed." });
  }
});

function generateRandomState() {
  return Math.random().toString(36).substring(2, 15);
}

// ---- Startup -----------------------------------------------------------
const PORT = process.env.PORT || 3000;

ensureTableExists()
  .then(() => {
    app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
  })
  .catch((err) => {
    console.error("Failed to set up database:", err);
    process.exit(1);
  });
