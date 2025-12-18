import { getDb } from "./_db";
import { spotifyTokens } from "../../shared/schema";
import { eq } from "drizzle-orm";

const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID || "";
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET || "";

export async function getStoredTokens() {
  const db = getDb();
  const result = await db.select().from(spotifyTokens).where(eq(spotifyTokens.id, "host")).limit(1);
  return result[0] || null;
}

export async function saveTokens(accessToken: string, refreshToken: string | null, expiresAt: number) {
  const db = getDb();
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

export async function refreshAccessToken(refreshToken: string) {
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

export async function getValidToken(): Promise<string | null> {
  const tokens = await getStoredTokens();
  if (!tokens) return null;

  if (Date.now() > tokens.expiresAt - 300000) {
    if (!tokens.refreshToken) {
      return null;
    }

    try {
      const data = await refreshAccessToken(tokens.refreshToken);

      if (data.access_token) {
        const newExpiresAt = Date.now() + data.expires_in * 1000;
        await saveTokens(
          data.access_token,
          data.refresh_token || tokens.refreshToken,
          newExpiresAt
        );
        return data.access_token;
      }
    } catch (e) {
      return null;
    }
    return null;
  }

  return tokens.accessToken;
}
