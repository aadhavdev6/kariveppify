import type { Express } from "express";
import { type Server } from "http";
import { db } from "./db";
import { spotifyTokens } from "@shared/schema";
import { eq } from "drizzle-orm";

const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID || "";
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET || "";

async function getStoredTokens() {
  const result = await db.select().from(spotifyTokens).where(eq(spotifyTokens.id, "host")).limit(1);
  return result[0] || null;
}

async function saveTokens(accessToken: string, refreshToken: string | null, expiresAt: number) {
  const existing = await getStoredTokens();
  
  const finalRefreshToken = refreshToken || existing?.refreshToken || null;
  
  await db.delete(spotifyTokens).where(eq(spotifyTokens.id, "host"));
  await db.insert(spotifyTokens).values({
    id: "host",
    accessToken,
    refreshToken: finalRefreshToken,
    expiresAt,
  });
}

async function exchangeCodeForTokens(code: string, redirectUri: string) {
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
      redirect_uri: redirectUri,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error_description || error.error || "Token exchange failed");
  }

  return await response.json();
}

async function refreshAccessToken(refreshToken: string) {
  const authString = Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString("base64");
  
  const response = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: {
      Authorization: `Basic ${authString}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error_description || error.error || "Token refresh failed");
  }

  return await response.json();
}

async function getValidToken(): Promise<string | null> {
  const tokens = await getStoredTokens();
  if (!tokens) return null;

  if (Date.now() > tokens.expiresAt - 300000) {
    console.log("Token expiring, refreshing...");
    
    if (!tokens.refreshToken) {
      console.error("No refresh token available - host needs to re-authenticate");
      return null;
    }

    try {
      console.log("Attempting to refresh Spotify token...");
      const data = await refreshAccessToken(tokens.refreshToken);

      if (data.access_token) {
        const newExpiresAt = Date.now() + data.expires_in * 1000;
        await saveTokens(
          data.access_token,
          data.refresh_token || tokens.refreshToken,
          newExpiresAt
        );
        console.log("Token refreshed successfully! New expiry:", new Date(newExpiresAt).toISOString());
        return data.access_token;
      }
    } catch (e: any) {
      console.error("Failed to refresh Spotify token:", e.message);
      return null;
    }
    return null;
  }

  return tokens.accessToken;
}

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {

  app.post("/api/spotify/token", async (req, res) => {
    try {
      const { code, redirectUri } = req.body;

      console.log("Received token exchange request");
      console.log("Has code:", !!code);
      console.log("Redirect URI:", redirectUri);

      if (!code || !redirectUri) {
        return res.status(400).json({ error: "Missing code or redirectUri" });
      }

      if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET) {
        return res.status(500).json({ error: "Server configuration error - missing Spotify credentials" });
      }

      const tokens = await exchangeCodeForTokens(code, redirectUri.trim());

      const expiresAt = Date.now() + (tokens.expires_in || 3600) * 1000;
      await saveTokens(tokens.access_token, tokens.refresh_token, expiresAt);

      console.log("Server authenticated with Spotify successfully!");
      console.log("Token expires at:", new Date(expiresAt).toISOString());

      res.json({
        success: true,
        message: "Server authenticated with Spotify successfully",
        expires_in: tokens.expires_in,
      });
    } catch (error: any) {
      console.error("Token exchange error:", error.message);
      res.status(500).json({ error: error.message || "Token exchange failed" });
    }
  });

  app.post("/api/spotify/store-tokens", async (req, res) => {
    const { access_token, refresh_token, expires_in } = req.body;

    console.log("Received store-tokens request");
    console.log("Has access_token:", !!access_token);
    console.log("Has refresh_token:", !!refresh_token);
    console.log("expires_in:", expires_in);

    if (!access_token) {
      console.error("Missing access_token");
      return res.status(400).json({ error: "Missing access token" });
    }

    const expiresAt = Date.now() + (expires_in || 3600) * 1000;
    
    try {
      await saveTokens(access_token, refresh_token || null, expiresAt);
      console.log("Host tokens stored successfully! Expires at:", new Date(expiresAt).toISOString());
      res.json({ success: true });
    } catch (error: any) {
      console.error("Failed to save tokens:", error.message);
      res.status(500).json({ error: error.message || "Failed to save tokens" });
    }
  });

  app.get("/api/spotify/client-id", (req, res) => {
    if (!SPOTIFY_CLIENT_ID) {
      return res.status(500).json({ error: "Spotify Client ID not configured" });
    }
    res.json({ clientId: SPOTIFY_CLIENT_ID });
  });

  app.get("/api/spotify/status", async (req, res) => {
    try {
      const token = await getValidToken();
      const tokens = await getStoredTokens();
      const hasToken = !!tokens?.accessToken;
      const authenticated = !!token;
      
      res.json({ 
        authenticated,
        hasToken,
        expiresAt: tokens?.expiresAt || null 
      });
    } catch (error: any) {
      res.status(500).json({ 
        error: "Failed to check authentication status",
        authenticated: false,
        hasToken: false
      });
    }
  });

  app.get("/api/spotify/search", async (req, res) => {
    const token = await getValidToken();
    if (!token) {
      return res.status(401).json({ error: "Host not authenticated" });
    }

    const query = req.query.q as string;
    if (!query) {
      return res.status(400).json({ error: "Missing query" });
    }

    try {
      const response = await fetch(
        `https://api.spotify.com/v1/search?q=${encodeURIComponent(query)}&type=track&limit=5`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      if (!response.ok) {
        const error = await response.json();
        return res.status(response.status).json({ error: error.error?.message || "Search failed" });
      }
      
      const data = await response.json();
      res.json(data.tracks?.items || []);
    } catch (e) {
      console.error("Search error", e);
      res.status(500).json({ error: "Search failed" });
    }
  });

  app.post("/api/spotify/queue", async (req, res) => {
    const token = await getValidToken();
    if (!token) {
      return res.status(401).json({ error: "Host not authenticated" });
    }

    const { uri, songName } = req.body;
    
    let trackUri = uri;

    if (songName && !uri) {
      try {
        const searchRes = await fetch(
          `https://api.spotify.com/v1/search?q=${encodeURIComponent(songName)}&type=track&limit=1`,
          { headers: { Authorization: `Bearer ${token}` } }
        );

        if (!searchRes.ok) {
          throw new Error("Search failed");
        }

        const searchData = await searchRes.json();
        if (!searchData.tracks?.items?.length) {
          return res.status(404).json({ error: `Song not found: ${songName}` });
        }

        trackUri = searchData.tracks.items[0].uri;
      } catch (e) {
        return res.status(500).json({ error: "Failed to search for song" });
      }
    }

    if (!trackUri) {
      return res.status(400).json({ error: "Missing track URI or song name" });
    }

    try {
      const response = await fetch(
        `https://api.spotify.com/v1/me/player/queue?uri=${encodeURIComponent(trackUri)}`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (response.status === 204 || response.ok) {
        res.json({ success: true, message: "Song added to queue" });
      } else {
        const error = await response.json().catch(() => ({ error: "Failed to add to queue" }));
        res.status(response.status).json(error);
      }
    } catch (e) {
      console.error("Queue error", e);
      res.status(500).json({ error: "Failed to add to queue" });
    }
  });

  app.post("/api/spotify/play", async (req, res) => {
    const token = await getValidToken();
    if (!token) {
      return res.status(401).json({ error: "Host not authenticated" });
    }

    try {
      const response = await fetch("https://api.spotify.com/v1/me/player/play", {
        method: "PUT",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok && response.status !== 204) {
        const error = await response.json().catch(() => ({}));
        return res.status(response.status).json({ error: error.error?.message || "No active device. Open Spotify on a device first." });
      }
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Play failed" });
    }
  });

  app.post("/api/spotify/pause", async (req, res) => {
    const token = await getValidToken();
    if (!token) {
      return res.status(401).json({ error: "Host not authenticated" });
    }

    try {
      const response = await fetch("https://api.spotify.com/v1/me/player/pause", {
        method: "PUT",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok && response.status !== 204) {
        const error = await response.json().catch(() => ({}));
        return res.status(response.status).json({ error: error.error?.message || "Pause failed" });
      }
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Pause failed" });
    }
  });

  app.post("/api/spotify/next", async (req, res) => {
    const token = await getValidToken();
    if (!token) {
      return res.status(401).json({ error: "Host not authenticated" });
    }

    try {
      const response = await fetch("https://api.spotify.com/v1/me/player/next", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok && response.status !== 204) {
        const error = await response.json().catch(() => ({}));
        return res.status(response.status).json({ error: error.error?.message || "Skip failed" });
      }
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Skip failed" });
    }
  });

  app.post("/api/spotify/volume", async (req, res) => {
    const token = await getValidToken();
    if (!token) {
      return res.status(401).json({ error: "Host not authenticated" });
    }

    const { delta } = req.body;

    try {
      const stateRes = await fetch("https://api.spotify.com/v1/me/player", {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (stateRes.status === 204) {
        return res.status(400).json({ error: "No active playback" });
      }

      const state = await stateRes.json();
      const currentVolume = state.device?.volume_percent || 50;
      const newVolume = Math.max(0, Math.min(100, currentVolume + delta));

      await fetch(
        `https://api.spotify.com/v1/me/player/volume?volume_percent=${newVolume}`,
        {
          method: "PUT",
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      res.json({ volume: newVolume });
    } catch (e) {
      res.status(500).json({ error: "Volume change failed" });
    }
  });

  app.post("/api/spotify/clear-queue", async (req, res) => {
    const token = await getValidToken();
    if (!token) {
      return res.status(401).json({ error: "Host not authenticated" });
    }

    try {
      const stateRes = await fetch("https://api.spotify.com/v1/me/player", {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (stateRes.status === 204) {
        return res.status(400).json({ error: "Nothing is currently playing" });
      }

      const state = await stateRes.json();
      if (!state.item) {
        return res.status(400).json({ error: "Nothing is currently playing" });
      }

      const currentTrackUri = state.item.uri;
      const progressMs = state.progress_ms;

      await fetch("https://api.spotify.com/v1/me/player/play", {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          uris: [currentTrackUri],
          position_ms: progressMs,
        }),
      });

      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Failed to clear queue" });
    }
  });

  app.get("/api/spotify/devices", async (req, res) => {
    const token = await getValidToken();
    if (!token) {
      return res.status(401).json({ error: "Host not authenticated" });
    }

    try {
      const response = await fetch(
        "https://api.spotify.com/v1/me/player/devices",
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const data = await response.json();
      const activeDevice = data.devices?.find((d: any) => d.is_active);
      res.json({
        device: activeDevice || (data.devices?.length > 0 ? data.devices[0] : null),
      });
    } catch (e) {
      res.status(500).json({ error: "Failed to get devices" });
    }
  });

  app.get("/api/spotify/get-queue", async (req, res) => {
    const token = await getValidToken();
    if (!token) {
      return res.status(401).json({ error: "Host not authenticated" });
    }

    try {
      const response = await fetch(
        "https://api.spotify.com/v1/me/player/queue",
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        return res.status(response.status).json({ error: error.error?.message || "Failed to get queue" });
      }
      
      const data = await response.json();
      res.json({
        currently_playing: data.currently_playing || null,
        queue: data.queue || [],
      });
    } catch (e) {
      console.error("Get queue error:", e);
      res.status(500).json({ error: "Failed to get queue" });
    }
  });

  return httpServer;
}
