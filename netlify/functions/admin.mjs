import { clients, reply, preflight, readBody, requireMaster, logActivity } from './_shared.mjs';

export async function handler(event) {
  const pf = preflight(event); if (pf) return pf;
  if (event.httpMethod !== 'POST') return reply(event, 405, { error: 'Method tidak diizinkan.' });
  try {
    const { admin } = clients();
    const auth = await requireMaster(event, admin);
    if (auth.error) return reply(event, auth.status, { error: auth.error });
    const body = readBody(event);
    const action = String(body.action || '');
    const actorId = auth.user.id;

    if (action === 'list') {
      const { data, error } = await admin.from('profiles')
        .select('id,username,full_name,role,is_active,must_change_password,created_at,updated_at,last_login_at,last_password_change_at')
        .order('created_at', { ascending: true });
      if (error) throw error;
      return reply(event, 200, { users: data || [] });
    }

    if (action === 'create') {
      const username = String(body.username || '').trim().toLowerCase();
      const fullName = String(body.full_name || '').trim();
      const password = String(body.password || '');
      if (!/^[a-z0-9_]{3,32}$/.test(username)) return reply(event, 400, { error: 'Username 3–32 karakter, hanya huruf kecil, angka, dan underscore.' });
      if (fullName.length < 2 || fullName.length > 80) return reply(event, 400, { error: 'Nama lengkap harus 2–80 karakter.' });
      if (password.length < 12) return reply(event, 400, { error: 'Password sementara minimal 12 karakter.' });
      const email = `${username}@members.felix-finance.netlify.app`;
      const { data: created, error: createError } = await admin.auth.admin.createUser({
        email, password, email_confirm: true,
        user_metadata: { username, full_name: fullName, managed_by: 'felix-finance-master' }
      });
      if (createError) return reply(event, 400, { error: createError.message });
      const { error: profileError } = await admin.from('profiles').insert({
        id: created.user.id, username, full_name: fullName, role: 'member',
        is_active: true, must_change_password: true
      });
      if (profileError) {
        await admin.auth.admin.deleteUser(created.user.id);
        throw profileError;
      }
      await logActivity(admin, { actorId, ownerId: created.user.id, action: 'MEMBER_CREATED', tableName: 'profiles', recordId: created.user.id, newData: { username, full_name: fullName, role: 'member' } });
      return reply(event, 200, { message: 'Anggota berhasil dibuat. Simpan password sementara dan berikan kepada anggota secara aman.', user: { id: created.user.id, username, full_name: fullName, role: 'member' } });
    }

    if (action === 'reset-password') {
      const userId = String(body.user_id || '');
      const password = String(body.password || '');
      if (!userId || password.length < 12) return reply(event, 400, { error: 'ID pengguna tidak valid atau password kurang dari 12 karakter.' });
      const { data: target, error: targetError } = await admin.from('profiles').select('id,username,role').eq('id', userId).maybeSingle();
      if (targetError || !target || target.role === 'master') return reply(event, 404, { error: 'Anggota tidak ditemukan atau tidak dapat direset dari menu anggota.' });
      const { error: updateAuthError } = await admin.auth.admin.updateUserById(userId, { password });
      if (updateAuthError) throw updateAuthError;
      await admin.from('profiles').update({ must_change_password: true, last_password_change_at: null, updated_at: new Date().toISOString() }).eq('id', userId);
      await logActivity(admin, { actorId, ownerId: userId, action: 'PASSWORD_RESET_BY_MASTER', tableName: 'profiles', recordId: userId, newData: { username: target.username } });
      return reply(event, 200, { message: 'Password anggota berhasil direset. Anggota wajib mengganti password saat login berikutnya.' });
    }

    if (action === 'set-active') {
      const userId = String(body.user_id || '');
      const active = Boolean(body.is_active);
      const { data: target, error: targetError } = await admin.from('profiles').select('id,username,role,is_active').eq('id', userId).maybeSingle();
      if (targetError || !target || target.role === 'master') return reply(event, 404, { error: 'Anggota tidak ditemukan atau tidak dapat dinonaktifkan.' });
      const { error } = await admin.from('profiles').update({ is_active: active, updated_at: new Date().toISOString() }).eq('id', userId);
      if (error) throw error;
      await logActivity(admin, { actorId, ownerId: userId, action: active ? 'MEMBER_ACTIVATED' : 'MEMBER_DEACTIVATED', tableName: 'profiles', recordId: userId, oldData: { is_active: target.is_active }, newData: { is_active: active } });
      return reply(event, 200, { message: active ? 'Anggota diaktifkan.' : 'Anggota dinonaktifkan. Data tetap disimpan.' });
    }

    if (action === 'logs') {
      const { data, error } = await admin.from('activity_logs').select('id,actor_id,owner_id,action,table_name,record_id,old_data,new_data,created_at').order('created_at', { ascending: false }).limit(300);
      if (error) throw error;
      return reply(event, 200, { logs: data || [] });
    }

    return reply(event, 400, { error: 'Aksi tidak dikenal.' });
  } catch (e) {
    console.error(e);
    return reply(event, 500, { error: e.message || 'Terjadi kesalahan server.' });
  }
}
