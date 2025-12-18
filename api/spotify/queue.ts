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
    res.status(500).json({ error: "Failed to add to queue" });
  }
}
