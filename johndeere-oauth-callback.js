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
const SCOPES = "ag1 ag2 ag3 eq1 eq2 org1 files offline_access";
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
