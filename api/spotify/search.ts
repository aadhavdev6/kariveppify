import type { VercelRequest, VercelResponse } from '@vercel/node';
import { getValidToken } from "./_utils";

export default async function handler(req: VercelRequest, res: VercelResponse) {
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
    res.status(500).json({ error: "Search failed" });
  }
}
