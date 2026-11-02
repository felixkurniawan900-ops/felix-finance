import { clients, reply, preflight, readBody, logActivity } from './_shared.mjs';
export async function handler(event) {
  const pf = preflight(event); if (pf) return pf;
  if (event.httpMethod !== 'POST') return reply(event, 405, { error: 'Method tidak diizinkan.' });
  try {
    const { username, password } = readBody(event);
    const clean = String(username || '').trim().toLowerCase();
    if (!/^[a-z0-9_]{3,32}$/.test(clean) || typeof password !== 'string' || password.length < 1) {
      return reply(event, 400, { error: 'Username atau password tidak valid.' });
    }
    const { admin, publicClient } = clients();
    const { data: profile, error: profileError } = await admin.from('profiles')
      .select('id,username,full_name,role,is_active,must_change_password')
      .eq('username', clean).maybeSingle();
    if (profileError || !profile) return reply(event, 401, { error: 'Username atau password salah.' });
    if (!profile.is_active) return reply(event, 403, { error: 'Akun dinonaktifkan. Hubungi Master.' });
    const { data: authData, error: getUserError } = await admin.auth.admin.getUserById(profile.id);
    if (getUserError || !authData?.user?.email) return reply(event, 401, { error: 'Akun autentikasi tidak ditemukan.' });
    const { data: signed, error: signError } = await publicClient.auth.signInWithPassword({
      email: authData.user.email, password
    });
    if (signError || !signed?.session) {
      await logActivity(admin, { action: 'LOGIN_FAILED', newData: { username: clean } });
      return reply(event, 401, { error: 'Username atau password salah.' });
    }
    await admin.from('profiles').update({ last_login_at: new Date().toISOString() }).eq('id', profile.id);
    await logActivity(admin, { actorId: profile.id, ownerId: profile.id, action: 'LOGIN_SUCCESS', newData: { username: clean } });
    return reply(event, 200, {
      session: signed.session,
      profile: {
        id: profile.id, username: profile.username, full_name: profile.full_name,
        role: profile.role, must_change_password: profile.must_change_password
      }
    });
  } catch (e) {
    console.error(e);
    return reply(event, 500, { error: e.message || 'Terjadi kesalahan server.' });
  }
}
