import type { VercelRequest, VercelResponse } from '@vercel/node';
import { getValidToken, getStoredTokens } from "./_utils";

export default async function handler(req: VercelRequest, res: VercelResponse) {
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
}
