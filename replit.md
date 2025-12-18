# Kariveppila Jukebox

## Overview

Kariveppila Jukebox is a web-based music controller application that integrates with Spotify to provide a futuristic jukebox experience. The application features a visually striking interface with morphing particle animations using Three.js, glass-morphism UI design, and allows users to search and queue songs on Spotify. It includes an admin panel for controlling playback (play, pause, skip, volume).

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React with TypeScript
- **Build Tool**: Vite with custom plugins for meta images and Replit integration
- **Styling**: Tailwind CSS v4 with CSS variables for theming
- **UI Components**: shadcn/ui component library (new-york style) with Radix UI primitives
- **State Management**: TanStack React Query for server state
- **Routing**: Wouter (lightweight React router)
- **3D Graphics**: Three.js with @react-three/fiber and @react-three/drei for particle background animations
- **Animation**: GSAP for particle morphing animations

### Backend Architecture
- **Runtime**: Node.js with Express
- **Language**: TypeScript compiled with tsx
- **API Design**: RESTful endpoints under `/api` prefix
- **Development**: Vite dev server with HMR proxied through Express

### Data Storage
- **Database**: PostgreSQL with Drizzle ORM
- **Schema Location**: `shared/schema.ts`
- **Tables**:
  - `users`: Basic user authentication (id, username, password)
  - `spotify_tokens`: Stores Spotify OAuth tokens (access_token, refresh_token, expires_at)
- **Migrations**: Managed via `drizzle-kit push`

### Authentication Flow
- **Spotify OAuth**: Authorization Code with PKCE flow for secure token exchange
- **Token Storage**: Tokens stored in PostgreSQL database for persistence
- **Token Refresh**: Automatic background refresh to maintain session

### Project Structure
```
├── client/           # Frontend React application
│   ├── src/
│   │   ├── components/   # UI components (shadcn/ui)
│   │   ├── hooks/        # Custom React hooks
│   │   ├── lib/          # Utilities (queryClient, spotify, utils)
│   │   └── pages/        # Route components
│   └── index.html
├── server/           # Backend Express application
│   ├── index.ts      # Entry point
│   ├── routes.ts     # API routes
│   ├── db.ts         # Database connection
│   └── storage.ts    # In-memory storage utilities
├── shared/           # Shared code between client/server
│   └── schema.ts     # Drizzle database schema
└── script/           # Build scripts
```

## External Dependencies

### Spotify Web API
- **Client ID**: Configured in `client/src/lib/spotify.ts` and `server/routes.ts`
- **Scopes**: User playback control, library access, streaming
- **Redirect URI**: `{origin}/callback`
- **Authentication**: PKCE flow with server-side token management

### Database
- **PostgreSQL**: Required via `DATABASE_URL` environment variable
- **ORM**: Drizzle ORM with drizzle-kit for schema management

### Key NPM Dependencies
- `@tanstack/react-query`: Server state management
- `three` / `@react-three/fiber`: 3D particle animations
- `gsap`: Animation library
- `drizzle-orm` / `drizzle-kit`: Database ORM and migrations
- `express`: HTTP server framework
- `wouter`: Client-side routing

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string (Replit development database)
- `NEON_DATABASE_URL`: Neon PostgreSQL connection string (for Vercel production - takes priority over DATABASE_URL if set)
- `NODE_ENV`: development/production mode
- `SPOTIFY_CLIENT_ID`: Spotify Developer App Client ID (required)
- `SPOTIFY_CLIENT_SECRET`: Spotify Developer App Client Secret (required)

### Vercel Deployment
For Vercel deployment, set the following environment variables in Vercel:
- `NEON_DATABASE_URL`: Your Neon PostgreSQL connection string
- `SPOTIFY_CLIENT_ID`: Your Spotify Client ID
- `SPOTIFY_CLIENT_SECRET`: Your Spotify Client Secret

### Spotify Developer Dashboard Setup
**IMPORTANT**: For Spotify authentication to work, you must add the redirect URI to your Spotify app settings:
1. Go to https://developer.spotify.com/dashboard
2. Select your app
3. Click "Edit Settings"
4. Under "Redirect URIs", add: `https://YOUR_REPLIT_DOMAIN/callback`
   (e.g., `https://your-app-name.picard.replit.dev/callback`)
5. Click "Save"

## Recent Changes (December 2024)

### Hybrid Deployment Support
- App now works on both Replit (with Express server) and Vercel (static deployment)
- Token storage uses localStorage for client-side, with server fallback when available
- Dynamic redirect URI automatically uses the current origin

### Token Refresh
- Automatic token refresh runs every 60 seconds in the background
- Tokens refresh 5 minutes before expiry to prevent interruptions
- Failed refreshes keep existing tokens (non-destructive)

### Visual Enhancements
- Particles now cycle through multiple colors (red, cyan, yellow, green, pink, purple, orange, blue)
- Color transitions are smooth with 2-second GSAP animations
- Colors change every 3 seconds

### Token Storage Fix (December 2024)
- Made refresh_token column nullable in database to handle cases where Spotify doesn't send one
- Token storage no longer fails when refresh token is missing
- Existing refresh tokens are preserved when only access token is refreshed