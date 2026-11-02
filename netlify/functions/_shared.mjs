import { createClient } from '@supabase/supabase-js';

const allowedOrigin = process.env.APP_ORIGIN || 'https://felix-finance.netlify.app';
export function headers(event) {
  const origin = event.headers?.origin || '';
  return {
    'Access-Control-Allow-Origin': origin === allowedOrigin ? origin : allowedOrigin,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, apikey',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Vary': 'Origin',
    'Content-Type': 'application/json; charset=utf-8'
  };
}
export function reply(event, statusCode, body) {
  return { statusCode, headers: headers(event), body: JSON.stringify(body) };
}
export function preflight(event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: headers(event), body: '' };
  return null;
}
export function readBody(event) {
  try { return JSON.parse(event.body || '{}'); } catch { return {}; }
}
export function clients() {
  const url = process.env.SUPABASE_URL;
  const publishable = process.env.SUPABASE_PUBLISHABLE_KEY;
  const secret = process.env.SUPABASE_SECRET_KEY;
  if (!url || !publishable || !secret) throw new Error('Konfigurasi Supabase di Netlify belum lengkap.');
  const admin = createClient(url, secret, { auth: { persistSession: false, autoRefreshToken: false } });
  const publicClient = createClient(url, publishable, { auth: { persistSession: false, autoRefreshToken: false } });
  return { admin, publicClient };
}
export async function requireMaster(event, admin) {
  const auth = event.headers?.authorization || event.headers?.Authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return { error: 'Sesi login tidak ditemukan.', status: 401 };
  const { data: userData, error: userError } = await admin.auth.getUser(token);
  if (userError || !userData?.user) return { error: 'Sesi tidak valid atau sudah berakhir.', status: 401 };
  const { data: profile, error } = await admin.from('profiles')
    .select('id,username,full_name,role,is_active')
    .eq('id', userData.user.id).maybeSingle();
  if (error || !profile || !profile.is_active || profile.role !== 'master') {
    return { error: 'Akses khusus Master diperlukan.', status: 403 };
  }
  return { user: userData.user, profile };
}
export async function logActivity(admin, { actorId = null, ownerId = null, action, tableName = null, recordId = null, oldData = null, newData = null }) {
  const { error } = await admin.from('activity_logs').insert({
    actor_id: actorId, owner_id: ownerId, action,
    table_name: tableName, record_id: recordId,
    old_data: oldData, new_data: newData
  });
  if (error) console.error('Activity log error:', error.message);
}
