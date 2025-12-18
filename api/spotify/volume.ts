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
}
