/**
 * John Deere Operations Center - OAuth2 Authorization Code Flow
 * ---------------------------------------------------------------
 * This is the server-side handler for the "Redirect URI" you register
 * in your John Deere Developer Portal application (My Applications > Security).
 *
 * Flow recap:
 *   1) Farmer clicks "Connect" on connections.deere.com and authorizes your app.
 *   2) John Deere redirects the farmer's browser to THIS endpoint with ?code=...
 *   3) This server exchanges that code (server-to-server) for an access_token
 *      + refresh_token at John Deere's token endpoint.
 *   4) Tokens are stored (linked to the farm/organization) for future API calls.
 *
 * Requires: npm install express axios dotenv
 */

const express = require("express");
const axios = require("axios");
require("dotenv").config();

const app = express();

// ---- Configuration -------------------------------------------------------
// Get these from developer.deere.com > My Applications > [Your App] > Security
const CLIENT_ID = process.env.DEERE_CLIENT_ID;
const CLIENT_SECRET = process.env.DEERE_CLIENT_SECRET;

// Must exactly match what you registered as "Redirect URI" in the portal
const REDIRECT_URI = process.env.DEERE_REDIRECT_URI; // e.g. https://app.yourcompany.com/auth/deere/callback

// From the .well-known discovery document (production):
// https://signin.johndeere.com/oauth2/aus78tnlaysMraFhC1t7/.well-known/oauth-authorization-server
const TOKEN_ENDPOINT = "https://signin.johndeere.com/oauth2/aus78tnlaysMraFhC1t7/v1/token";
const AUTHORIZATION_ENDPOINT = "https://signin.johndeere.com/oauth2/aus78tnlaysMraFhC1t7/v1/authorize";

// Space-separated scopes you actually need. Add "offline_access" to get a
// refresh_token so you don't need the farmer to re-authenticate constantly.
const SCOPES = "ag1 ag2 org1 org2 offline_access";

// ---- Step A: Kick off the flow (optional helper route) -------------------
// You'd normally link users to something like this, or John Deere's
// Connections UI does the equivalent for you.
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
    // e.g. the farmer clicked "Don't Allow"
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

    // TODO: Save access_token, refresh_token, and expiry to your database,
    // linked to the correct farmer/organization record. You'll need this
    // later to call the actual Operations Center data APIs
    // (Organizations, Fields, Boundaries, Machine data, etc.)

    console.log("Received tokens:", { access_token, refresh_token, expires_in });

    res.send("Connection successful! You can close this window.");
  } catch (err) {
    console.error("Token exchange failed:", err.response?.data || err.message);
    res.status(500).send("Something went wrong completing the connection.");
  }
});

function generateRandomState() {
  return Math.random().toString(36).substring(2, 15);
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
