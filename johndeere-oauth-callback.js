/**
 * John Deere Operations Center - OAuth2 Flow + Data Fetching
 * ---------------------------------------------------------------
 * NEW IN THIS VERSION:
 *   - After a farmer connects, we now call the Organizations API to find
 *     out which organization(s) they connected, and save that org ID
 *     alongside their tokens.
 *   - New endpoints let you actually pull real data:
 *       GET /api/organizations         -> list connected organizations
 *       GET /api/boundaries/:orgId     -> list field boundaries for an org
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

// Production data API base. (Sandbox equivalent: https://sandboxapi.deere.com/platform)
const API_BASE = "https://partnerapi.deere.com/platform";

const SCOPES = "ag1 ag2 org1 org2 offline_access";

// John Deere's custom JSON media type, required on most Platform API calls
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
  console.log("Database ready: deere_tokens table exists.");
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

  if (error) {
    return res.status(400).send(`Authorization was not completed: ${error}`);
  }
  if (!code) {
    return res.status(400).send("Missing authorization code.");
  }

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

    // Save the token first (without an org ID yet)
    const insertResult = await pool.query(
      `INSERT INTO deere_tokens (access_token, refresh_token, expires_at)
       VALUES ($1, $2, $3) RETURNING id`,
      [access_token, refresh_token, expiresAt]
    );
    const tokenRowId = insertResult.rows[0].id;

    // Immediately look up which organization(s) this token grants access to,
    // and save the first one against this row. (A token can cover multiple
    // orgs if the farmer connected more than one; for simplicity we store
    // the first here — you can extend this to store one row per org.)
    try {
      const orgsResponse = await axios.get(`${API_BASE}/organizations`, {
        headers: {
          Authorization: `Bearer ${access_token}`,
          Accept: DEERE_ACCEPT_HEADER,
        },
      });

      const firstOrg = orgsResponse.data.values?.[0];
      if (firstOrg) {
        await pool.query(
          `UPDATE deere_tokens SET organization_id = $1, organization_name = $2 WHERE id = $3`,
          [firstOrg.id, firstOrg.name, tokenRowId]
        );
        console.log(`Connected organization: ${firstOrg.name} (${firstOrg.id})`);
      }
    } catch (orgErr) {
      // Don't fail the whole connection just because this lookup failed —
      // the tokens are already safely saved either way.
      console.error("Could not fetch organization info:", orgErr.response?.data || orgErr.message);
    }

    console.log("Tokens saved to database. Expires at:", expiresAt);
    res.send("Connection successful! You can close this window.");
  } catch (err) {
    console.error("Token exchange failed:", err.response?.data || err.message);
    res.status(500).send("Something went wrong completing the connection.");
  }
});

// ---- Helper: get a valid (non-expired) access token, refreshing if needed
async function getValidAccessToken(tokenRow) {
  const now = new Date();
  const bufferMs = 60 * 1000; // refresh 1 minute before actual expiry

  if (new Date(tokenRow.expires_at).getTime() - bufferMs > now.getTime()) {
    return tokenRow.access_token; // still valid
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
    `UPDATE deere_tokens SET access_token = $1, refresh_token = $2, expires_at = $3, updated_at = NOW() WHERE id = $4`,
    [access_token, refresh_token, expiresAt, tokenRow.id]
  );

  return access_token;
}

// ---- NEW: GET /api/organizations ------------------------------------
// Returns the list of organizations connected so far (from our database),
// re-fetching live data from John Deere for each using their saved token.
app.get("/api/organizations", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM deere_tokens ORDER BY created_at DESC`
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "No connected organizations yet." });
    }

    const results = [];
    for (const tokenRow of rows) {
      const accessToken = await getValidAccessToken(tokenRow);
      const orgsResponse = await axios.get(`${API_BASE}/organizations`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: DEERE_ACCEPT_HEADER,
        },
      });
      results.push(...orgsResponse.data.values);
    }

    res.json(results);
  } catch (err) {
    console.error("Failed to fetch organizations:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to fetch organizations." });
  }
});

// ---- NEW: GET /api/boundaries/:orgId ---------------------------------
// Returns field boundaries for a specific organization.
app.get("/api/boundaries/:orgId", async (req, res) => {
  const { orgId } = req.params;

  try {
    // Find a saved token that has access to this organization
    const { rows } = await pool.query(
      `SELECT * FROM deere_tokens WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [orgId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "No saved connection found for this organization." });
    }

    const accessToken = await getValidAccessToken(rows[0]);

    const boundariesResponse = await axios.get(
      `${API_BASE}/organizations/${orgId}/boundaries`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: DEERE_ACCEPT_HEADER,
        },
      }
    );

    res.json(boundariesResponse.data.values || []);
  } catch (err) {
    console.error("Failed to fetch boundaries:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to fetch boundaries." });
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
