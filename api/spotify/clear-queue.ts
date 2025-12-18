import type { VercelRequest, VercelResponse } from '@vercel/node';
import { getValidToken } from "./_utils";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

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
}
