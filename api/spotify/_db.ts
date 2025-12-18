import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "../../shared/schema";

const databaseUrl = process.env.NEON_DATABASE_URL || process.env.DATABASE_URL;

let pool: pg.Pool | null = null;

export function getDb() {
  if (!pool) {
    pool = new pg.Pool({
      connectionString: databaseUrl,
    });
  }
  return drizzle(pool, { schema });
}
