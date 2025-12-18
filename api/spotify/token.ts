import type { VercelRequest, VercelResponse } from '@vercel/node';
import { saveTokens } from "./_utils";

const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID || "";
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET || "";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { code, redirectUri } = req.body;

    if (!code || !redirectUri) {
      return res.status(400).json({ error: "Missing code or redirectUri" });
    }

    if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET) {
      return res.status(500).json({ error: "Server configuration error - missing Spotify credentials" });
    }

    const authString = Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString("base64");
    
    const response = await fetch("https://accounts.spotify.com/api/token", {
      method: "POST",
      headers: {
        Authorization: `Basic ${authString}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri.trim(),
      }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error_description || error.error || "Token exchange failed");
    }

    const tokens = await response.json();
    const expiresAt = Date.now() + (tokens.expires_in || 3600) * 1000;
    await saveTokens(tokens.access_token, tokens.refresh_token, expiresAt);

    res.json({
      success: true,
      message: "Server authenticated with Spotify successfully",
      expires_in: tokens.expires_in,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message || "Token exchange failed" });
  }
}
