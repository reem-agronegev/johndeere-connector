/**
 * John Deere Operations Center - OAuth2 Authorization Code Flow
 * ---------------------------------------------------------------
 * This is the server-side handler for the "Redirect URI" you registered
 * in your John Deere Developer Portal application (My Applications > Security).
 *
 * NEW IN THIS VERSION: tokens are now persisted in a real PostgreSQL
 * database (via Render's free Postgres) instead of just being logged.
 *
 * Flow recap:
 *   1) Farmer clicks "Connect" on connections.deere.com and authorizes your app.
 *   2) John Deere redirects the farmer's browser to THIS endpoint with ?code=...
 *   3) This server exchanges that code (server-to-server) for an access_token
 *      + refresh_token at John Deere's token endpoint.
 *   4) Tokens are stored in Postgres, linked to the farm/organization, for
 *      future API calls (Fields, Boundaries, Machine data, etc.)
 *
 * Requires: npm install express axios dotenv pg
 */

const express = require("express");
const axios = require("axios");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

// ---- Configuration -------------------------------------------------------
// Get these from developer.deere.com > My Applications > [Your App] > Security
const CLIENT_ID = process.env.DEERE_CLIENT_ID;
const CLIENT_SECRET = process.env.DEERE_CLIENT_SECRET;

// Must exactly match what you registered as "Redirect URI" in the portal
const REDIRECT_URI = process.env.DEERE_REDIRECT_URI; // e.g. https://johndeere-connector.onrender.com/auth/deere/callback

const TOKEN_ENDPOINT = "https://signin.johndeere.com/oauth2/aus78tnlaysMraFhC1t7/v1/token";
const AUTHORIZATION_ENDPOINT = "https://signin.johndeere.com/oauth2/aus78tnlaysMraFhC1t7/v1/authorize";

// Space-separated scopes you actually need.
const SCOPES = "ag1 ag2 org1 org2 offline_access";

// ---- Database setup --------------------------------------------------
// DATABASE_URL comes from Render's Postgres "Internal Database URL"
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Create the tokens table automatically if it doesn't exist yet.
async function ensureTableExists() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS deere_tokens (
      id SERIAL PRIMARY KEY,
      organization_id TEXT,
      access_token TEXT NOT NULL,
      refresh_token TEXT,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log("Database ready: deere_tokens table exists.");
}

// ---- Step A: Kick off the flow (optional helper route) -------------------
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

// ---- Step B: THIS is your "Redirect URI" -----------------------------
// John Deere sends the farmer's browser here after they approve access.
app.get("/auth/deere/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send(`Authorization was not completed: ${error}`);
  }

  if (!code) {
    return res.status(400).send("Missing authorization code.");
  }

  // TODO: verify `state` matches what you generated in Step A (CSRF protection)

  try {
    // Exchange the authorization code for tokens (server-to-server call)
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
            "Basic " +
            Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64"),
        },
      }
    );

    const { access_token, refresh_token, expires_in } = tokenResponse.data;
    const expiresAt = new Date(Date.now() + expires_in * 1000);

    // Save the tokens to the database.
    // NOTE: organization_id isn't known from this response alone in all setups;
    // once your Organizations API access is approved, call the Organizations
    // endpoint right after this and update the row with the real org ID.
    await pool.query(
      `INSERT INTO deere_tokens (access_token, refresh_token, expires_at)
       VALUES ($1, $2, $3)`,
      [access_token, refresh_token, expiresAt]
    );

    console.log("Tokens saved to database. Expires at:", expiresAt);

    res.send("Connection successful! You can close this window.");
  } catch (err) {
    console.error("Token exchange failed:", err.response?.data || err.message);
    res.status(500).send("Something went wrong completing the connection.");
  }
});

// ---- Helper: refresh an expired access_token using its refresh_token -----
async function refreshAccessToken(refreshToken) {
  const response = await axios.post(
    TOKEN_ENDPOINT,
    new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    }),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization:
          "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64"),
      },
    }
  );
  return response.data; // { access_token, refresh_token, expires_in }
}

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
