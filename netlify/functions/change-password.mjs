import { clients, reply, preflight, readBody, logActivity } from './_shared.mjs';
export async function handler(event) {
  const pf = preflight(event); if (pf) return pf;
  if (event.httpMethod !== 'POST') return reply(event, 405, { error: 'Method tidak diizinkan.' });
  try {
    const authHeader = event.headers?.authorization || event.headers?.Authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!token) return reply(event, 401, { error: 'Sesi login tidak ditemukan.' });
    const { admin } = clients();
    const { data: authData, error: authError } = await admin.auth.getUser(token);
    if (authError || !authData?.user) return reply(event, 401, { error: 'Sesi tidak valid.' });
    const body = readBody(event);
    const password = String(body.password || '');
    if (password.length < 12) return reply(event, 400, { error: 'Password baru minimal 12 karakter.' });
    const userId = authData.user.id;
    const { data: profile, error: profileError } = await admin.from('profiles').select('id,username,is_active').eq('id', userId).maybeSingle();
    if (profileError || !profile || !profile.is_active) return reply(event, 403, { error: 'Akun tidak aktif.' });
    const { error: updateError } = await admin.auth.admin.updateUserById(userId, { password });
    if (updateError) throw updateError;
    await admin.from('profiles').update({ must_change_password: false, last_password_change_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq('id', userId);
    await logActivity(admin, { actorId: userId, ownerId: userId, action: 'PASSWORD_CHANGED', tableName: 'profiles', recordId: userId, newData: { username: profile.username } });
    return reply(event, 200, { message: 'Password berhasil diperbarui.' });
  } catch (e) {
    console.error(e);
    return reply(event, 500, { error: e.message || 'Gagal mengubah password.' });
  }
}
