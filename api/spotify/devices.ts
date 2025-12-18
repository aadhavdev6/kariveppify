import type { VercelRequest, VercelResponse } from '@vercel/node';
import { getValidToken } from "./_utils";

export default async function handler(req: VercelRequest, res: VercelResponse) {
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
}
