import { reply, preflight } from './_shared.mjs';
export async function handler(event) {
  const pf = preflight(event); if (pf) return pf;
  if (event.httpMethod !== 'GET') return reply(event, 405, { error: 'Method tidak diizinkan.' });
  const { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY } = process.env;
  if (!SUPABASE_URL || !SUPABASE_PUBLISHABLE_KEY) return reply(event, 500, { error: 'Konfigurasi Supabase belum lengkap.' });
  return reply(event, 200, { url: SUPABASE_URL, publishableKey: SUPABASE_PUBLISHABLE_KEY });
}
