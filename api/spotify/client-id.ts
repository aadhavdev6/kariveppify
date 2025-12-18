import type { VercelRequest, VercelResponse } from '@vercel/node';

export default function handler(req: VercelRequest, res: VercelResponse) {
  const clientId = process.env.SPOTIFY_CLIENT_ID;
  
  if (!clientId) {
    return res.status(500).json({ error: "Spotify Client ID not configured" });
  }
  
  res.json({ clientId });
}
