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

const SCOPES = "ag1 ag2 ag3 eq1 eq2 org1 org2 offline_access";
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
// The unique index below can't be created while duplicate organization_id
  // rows exist (left over from earlier versions). Keep the newest row per org.
  await pool.query(`
    DELETE FROM deere_tokens a
    USING deere_tokens b
    WHERE a.organization_id IS NOT NULL
      AND a.organization_id = b.organization_id
      AND a.id < b.id;
  `);
  // Needed for ON CONFLICT (organization_id) to work. Partial index so that
  // multiple rows with a NULL org (not yet resolved) are still allowed.
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS deere_tokens_org_unique
    ON deere_tokens (organization_id)
    WHERE organization_id IS NOT NULL;
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
      const orgsResponse = await axios.get(`${API_ROOT}/organizations`, {
        headers: deereHeaders(access_token),
      });
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
    await pool.query(
      `INSERT INTO deere_tokens
         (organization_id, organization_name, access_token, refresh_token, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (organization_id) DO UPDATE SET
         organization_name = EXCLUDED.organization_name,
         access_token      = EXCLUDED.access_token,
         refresh_token     = EXCLUDED.refresh_token,
         expires_at        = EXCLUDED.expires_at,
         updated_at        = NOW()`,
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
      const orgsResponse = await axios.get(`${API_ROOT}/organizations`, {
        headers: deereHeaders(accessToken),
      });

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
        const orgsResponse = await axios.get(`${API_ROOT}/organizations`, {
          headers: deereHeaders(accessToken),
        });
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

// ---- GET /api/boundaries/:orgId --------------------------------------
// Uses link traversal: fetches the org, reads its `boundaries` link, follows it.
app.get("/api/boundaries/:orgId", async (req, res) => {
  const { orgId } = req.params;

  try {
    const found = await findTokenForOrg(orgId);
    if (!found) {
      return res.status(404).json({
        message: "No stored token grants access to this organization.",
      });
    }

    const accessToken = await getValidAccessToken(found.row);

    // Re-fetch the org so we get a fresh `links` array reflecting current
    // permissions, rather than assuming the URL shape.
    const orgsResponse = await axios.get(`${API_ROOT}/organizations`, {
      headers: deereHeaders(accessToken),
    });
    const org = (orgsResponse.data.values || []).find((o) => String(o.id) === String(orgId));

    if (!org) {
      return res.status(404).json({ message: "Organization not visible with this token." });
    }

    const boundariesUri = findLink(org, "boundaries");
    if (!boundariesUri) {
      return res.status(403).json({
        message:
          "This organization has not shared boundary data with the application. " +
          "Ask the grower to raise the Locations permission at connections.deere.com.",
        availableLinks: (org.links || []).map((l) => l.rel),
      });
    }

    const boundariesResponse = await axios.get(boundariesUri, {
      headers: deereHeaders(accessToken),
    });

    res.json({
      organization: { id: org.id, name: org.name },
      total: boundariesResponse.data.total,
      boundaries: boundariesResponse.data.values || [],
    });
  } catch (err) {
    console.error("Failed to fetch boundaries:", err.response?.data || err.message);
    res.status(500).json({
      error: "Failed to fetch boundaries.",
      detail: err.response?.data || err.message,
    });
  }
});

// ---- GET /api/fields/:orgId ------------------------------------------
// Same pattern, for the field list (useful for mapping to dim_polygon).
app.get("/api/fields/:orgId", async (req, res) => {
  const { orgId } = req.params;

  try {
    const found = await findTokenForOrg(orgId);
    if (!found) {
      return res.status(404).json({ message: "No stored token grants access to this organization." });
    }

    const accessToken = await getValidAccessToken(found.row);

    const orgsResponse = await axios.get(`${API_ROOT}/organizations`, {
      headers: deereHeaders(accessToken),
    });
    const org = (orgsResponse.data.values || []).find((o) => String(o.id) === String(orgId));
    if (!org) return res.status(404).json({ message: "Organization not visible with this token." });

    const fieldsUri = findLink(org, "fields");
    if (!fieldsUri) {
      return res.status(403).json({
        message: "This organization has not shared field data with the application.",
        availableLinks: (org.links || []).map((l) => l.rel),
      });
    }

    const fieldsResponse = await axios.get(fieldsUri, { headers: deereHeaders(accessToken) });

    res.json({
      organization: { id: org.id, name: org.name },
      total: fieldsResponse.data.total,
      fields: fieldsResponse.data.values || [],
    });
  } catch (err) {
    console.error("Failed to fetch fields:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to fetch fields.", detail: err.response?.data || err.message });
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
