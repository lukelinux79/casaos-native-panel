const state = { me: null, users: [], groups: [], sambaUsers: [], sambaAvailable: true, shares: [], services: [], packages: [], accounts: [] };
const roleRank = { viewer: 1, operator: 2, admin: 3 };
const can = (role) => !!state.me && roleRank[state.me.role] >= roleRank[role];
const $ = (id) => document.getElementById(id);
// "" when opened directly, "/panel" when opened through the CasaOS gateway.
const BASE = location.pathname.replace(/\/[^/]*$/, '');

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function fetchJSON(url, options = {}) {
  const opts = { ...options, headers: { ...(options.headers || {}) } };
  if (opts.body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(BASE + url, opts);
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text }; }
  if (res.status === 401 && !/\/auth\/(login|casaos)$/.test(url)) { showLogin(); throw new Error('Please sign in'); }
  if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
  return data;
}

let toastTimer;
function toast(msg, isError = false) {
  const t = $('toast');
  t.textContent = msg;
  t.className = isError ? 'error' : '';
  t.style.display = 'block';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.style.display = 'none'), isError ? 9000 : 3500);
}

async function act(fn, okMsg, reload) {
  try {
    const res = await fn();
    if (res && res.warning) toast(res.warning, true);
    else if (okMsg) toast(okMsg);
    if (reload) await reload();
  } catch (err) {
    toast(err.message, true);
  }
}

function askPassword(title) {
  return new Promise((resolve) => {
    const dlg = $('pwDialog'), form = $('pwForm');
    $('pwTitle').textContent = title;
    form.reset();
    const done = (value) => { dlg.close(); form.onsubmit = null; resolve(value); };
    $('pwCancel').onclick = () => done(null);
    form.onsubmit = (e) => {
      e.preventDefault();
      if (form.pw1.value !== form.pw2.value) { toast('Passwords do not match', true); return; }
      done(form.pw1.value);
    };
    dlg.showModal();
  });
}

const fmtBytes = (b) => {
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; b = Number(b || 0);
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(i ? 1 : 0)} ${u[i]}`;
};
const fmtUptime = (s) => { s = Number(s || 0); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? `${d}d ${h}h` : `${h}h ${m}m`; };
const splitList = (v) => String(v || '').split(/[\s,]+/).filter(Boolean);

/* ---------- dashboard ---------- */
async function loadDashboard() {
  const { data } = await fetchJSON('/api/v1/dashboard');
  const o = data.overview || {}, m = data.metrics || {};
  $('hostname').textContent = o.hostname || 'unknown';
  $('osInfo').textContent = [o.os, o.kernel].filter(Boolean).join(' · ');
  $('modeBadge').textContent = (o.mode || 'system') + ' mode';
  $('loadValue').textContent = [m.load1, m.load5, m.load15].map((v) => Number(v || 0).toFixed(2)).join(' / ');
  const total = Number(m.mem_total_kb || 0) * 1024, used = total - Number(m.mem_available_kb || 0) * 1024;
  $('ramValue').textContent = fmtBytes(used);
  $('ramSub').textContent = total ? `${Math.round(used / total * 100)}% of ${fmtBytes(total)}` : '-';
  $('diskValue').textContent = `${Number(m.disk_used_percent || 0).toFixed(1)}%`;
  $('diskSub').textContent = `${fmtBytes(m.disk_free_bytes)} free of ${fmtBytes(m.disk_total_bytes)}`;
  $('uptimeValue').textContent = fmtUptime(m.uptime_seconds);
  $('netSub').textContent = `net rx ${fmtBytes(m.net_rx_bytes)} · tx ${fmtBytes(m.net_tx_bytes)}`;
}

/* ---------- users ---------- */
async function loadUsers() {
  const [u, g, s] = await Promise.all([
    fetchJSON('/api/v1/users'), fetchJSON('/api/v1/groups'), fetchJSON('/api/v1/samba/users'),
  ]);
  state.users = u.users || []; state.groups = g.groups || [];
  state.sambaUsers = s.users || []; state.sambaAvailable = s.available !== false;
  renderUsers(); renderGroups();
}

function renderUsers() {
  const showSystem = $('showSystemUsers').checked;
  const rows = state.users.filter((u) => showSystem || !u.system).map((u) => {
    const smb = state.sambaUsers.includes(u.username);
    const n = esc(u.username);
    const btns = u.system ? '<span class="muted">system</span>' : !can('operator') ? '' : `
      <button class="small secondary" data-act="pw" data-user="${n}">Password</button>
      ${state.sambaAvailable ? `<button class="small secondary" data-act="smbpw" data-user="${n}">${smb ? 'Samba password' : 'Enable Samba'}</button>` : ''}
      ${smb ? `<button class="small secondary" data-act="smbdel" data-user="${n}">Disable Samba</button>` : ''}
      <button class="small danger" data-act="del" data-user="${n}">Delete</button>`;
    return `<tr><td>${n}</td><td>${u.uid}</td><td>${(u.groups || []).map(esc).join(', ')}</td>
      <td class="${smb ? 'yes' : 'no'}">${smb ? 'yes' : 'no'}</td><td class="muted">${esc(u.shell)}</td>
      <td class="actions">${btns}</td></tr>`;
  });
  $('userTable').innerHTML = rows.join('') || '<tr><td colspan="6" class="muted">No users</td></tr>';
  $('sambaHint').textContent = state.sambaAvailable ? '' : 'Samba is not installed (apt install samba) – Samba features are disabled.';
}

$('userTable').addEventListener('click', async (e) => {
  const b = e.target.closest('button[data-act]'); if (!b) return;
  const user = b.dataset.user, enc = encodeURIComponent(user);
  if (b.dataset.act === 'pw') {
    const pw = await askPassword(`Linux password for ${user}`); if (pw === null) return;
    act(() => fetchJSON(`/api/v1/users/${enc}/password`, { method: 'PUT', body: { password: pw } }), 'Password updated');
  } else if (b.dataset.act === 'smbpw') {
    const pw = await askPassword(`Samba password for ${user}`); if (pw === null) return;
    act(() => fetchJSON(`/api/v1/samba/users/${enc}`, { method: 'PUT', body: { password: pw } }), 'Samba login saved', loadUsers);
  } else if (b.dataset.act === 'smbdel') {
    if (!confirm(`Remove Samba login of ${user}?`)) return;
    act(() => fetchJSON(`/api/v1/samba/users/${enc}`, { method: 'DELETE' }), 'Samba login removed', loadUsers);
  } else if (b.dataset.act === 'del') {
    if (!confirm(`Delete user ${user}?`)) return;
    const home = confirm(`Also delete the home directory of ${user}? (Cancel keeps it)`);
    act(() => fetchJSON(`/api/v1/users/${enc}?remove_home=${home}`, { method: 'DELETE' }), 'User deleted', loadUsers);
  }
});

$('createUserForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const f = e.target;
  const body = { username: f.username.value.trim(), password: f.password.value, shell: f.shell.value, groups: splitList(f.groups.value), samba: f.samba.checked && state.sambaAvailable };
  act(async () => { await fetchJSON('/api/v1/users', { method: 'POST', body }); f.reset(); }, `User ${body.username} created`, loadUsers);
});
$('showSystemUsers').addEventListener('change', renderUsers);

/* ---------- groups ---------- */
function renderGroups() {
  const showSystem = $('showSystemGroups').checked;
  const regularUsers = state.users.filter((u) => !u.system).map((u) => u.username);
  $('groupTable').innerHTML = state.groups.filter((g) => showSystem || !g.system).map((g) => {
    const n = esc(g.name);
    const members = (g.members || []).map((m) => `<span class="chip">${esc(m)}${regularUsers.includes(m) && can('operator') ? `<button title="remove" data-act="rm" data-group="${n}" data-user="${esc(m)}">×</button>` : ''}</span>`).join('');
    const candidates = can('operator') ? regularUsers.filter((u) => !(g.members || []).includes(u)) : [];
    const add = candidates.length ? `<select data-group="${n}"><option value="">add member…</option>${candidates.map((u) => `<option>${esc(u)}</option>`).join('')}</select>` : '';
    const del = g.system || !can('operator') ? '' : `<button class="small danger" data-act="del" data-group="${n}">Delete</button>`;
    return `<tr><td>${n}</td><td>${g.gid}</td><td>${members || '<span class="muted">-</span>'}</td><td class="actions">${add} ${del}</td></tr>`;
  }).join('') || '<tr><td colspan="4" class="muted">No groups</td></tr>';
}

$('groupTable').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-act]'); if (!b) return;
  const g = encodeURIComponent(b.dataset.group);
  if (b.dataset.act === 'rm') {
    act(() => fetchJSON(`/api/v1/groups/${g}/members/${encodeURIComponent(b.dataset.user)}`, { method: 'DELETE' }), 'Member removed', loadUsers);
  } else if (b.dataset.act === 'del' && confirm(`Delete group ${b.dataset.group}?`)) {
    act(async () => {
      try {
        await fetchJSON(`/api/v1/groups/${g}`, { method: 'DELETE' });
      } catch (err) {
        if (!/used by the shares/.test(err.message) || !confirm(`${err.message}\n\nDelete anyway?`)) throw err;
        await fetchJSON(`/api/v1/groups/${g}?force=true`, { method: 'DELETE' });
      }
    }, 'Group deleted', loadUsers);
  }
});
$('groupTable').addEventListener('change', (e) => {
  const sel = e.target.closest('select[data-group]'); if (!sel || !sel.value) return;
  act(() => fetchJSON(`/api/v1/groups/${encodeURIComponent(sel.dataset.group)}/members`, { method: 'POST', body: { user: sel.value } }), 'Member added', loadUsers);
});
$('createGroupForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const name = e.target.name.value.trim();
  act(async () => { await fetchJSON('/api/v1/groups', { method: 'POST', body: { name } }); e.target.reset(); }, `Group ${name} created`, loadUsers);
});
$('showSystemGroups').addEventListener('change', renderGroups);

/* ---------- shares ---------- */
async function loadShares() {
  try {
    const data = await fetchJSON('/api/v1/samba/shares');
    state.shares = data.shares || [];
  } catch (err) {
    state.shares = [];
    $('shareTable').innerHTML = `<tr><td colspan="5" class="muted">${esc(err.message)}</td></tr>`;
    return;
  }
  $('shareTable').innerHTML = state.shares.map((s) => {
    const n = esc(s.name), casa = s.managed_by === 'casaos';
    const access = [s.read_only ? 'read only' : 'read/write', s.guest_ok ? 'guest' : '', s.browseable ? '' : 'hidden'].filter(Boolean).join(', ');
    const users = s.guest_ok ? '<span class="warn">everyone, no password</span>'
      : (s.valid_users || []).length ? s.valid_users.map(esc).join(' ') : '<span class="muted">all Samba users</span>';
    let btns = '';
    if (can('operator')) {
      if (casa) btns = state.me.casaos ? `<button class="small danger" data-act="adopt" data-share="${n}">Secure</button>` : '<span class="muted">CasaOS not running</span>';
      else if (s.special) btns = '<span class="muted">built-in (edit in config)</span>';
      else btns = `<button class="small secondary" data-act="edit" data-share="${n}">Edit</button> <button class="small danger" data-act="del" data-share="${n}">Delete</button>`;
    }
    const warnings = (s.warnings || []).map((w) => `<div class="warn">⚠ ${esc(w)}</div>`).join('');
    return `<tr><td>${n}${casa ? '<span class="tag">CasaOS</span>' : ''}<div class="muted">${esc(s.comment)}</div>${warnings}</td>
      <td>${esc(s.path)}</td><td>${access}</td><td>${users}</td><td class="actions">${btns}</td></tr>`;
  }).join('') || '<tr><td colspan="5" class="muted">No shares</td></tr>';
}

// adopt=true turns a CasaOS share into a password-protected share with the same name and path.
function fillShareForm(s, adopt = false) {
  const f = $('shareForm');
  state.adoptShare = adopt ? s.name : null;
  f.name.value = s?.name || ''; f.name.readOnly = !!s;
  f.path.value = s?.path || ''; f.path.readOnly = adopt; f.comment.value = adopt ? '' : s?.comment || '';
  f.valid_users.value = adopt ? '' : (s?.valid_users || []).join(' '); f.write_list.value = adopt ? '' : (s?.write_list || []).join(' ');
  f.read_only.checked = adopt ? false : !!s?.read_only; f.browseable.checked = s ? !!s.browseable : true;
  f.guest_ok.checked = adopt ? false : !!s?.guest_ok;
  $('shareFormTitle').textContent = adopt ? `Secure CasaOS share ${s.name} (password required, no guest access)` : s ? `Edit share ${s.name}` : 'New share';
}

$('shareTable').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-act]'); if (!b) return;
  const share = state.shares.find((s) => s.name === b.dataset.share);
  if (b.dataset.act === 'edit') { fillShareForm(share); window.scrollTo(0, 0); }
  else if (b.dataset.act === 'adopt') { fillShareForm(share, true); window.scrollTo(0, 0); }
  else if (b.dataset.act === 'del' && confirm(`Delete share ${share.name}? Files stay on disk.`)) {
    act(() => fetchJSON(`/api/v1/samba/shares/${encodeURIComponent(share.name)}`, { method: 'DELETE' }), 'Share deleted', loadShares);
  }
});
$('shareForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const f = e.target;
  const body = { path: f.path.value.trim(), comment: f.comment.value.trim(), read_only: f.read_only.checked, browseable: f.browseable.checked,
    guest_ok: f.guest_ok.checked, valid_users: splitList(f.valid_users.value), write_list: splitList(f.write_list.value) };
  const name = f.name.value.trim();
  if (state.adoptShare) {
    if (body.guest_ok && !confirm('Guest access keeps the share open without a password. Continue?')) return;
    act(async () => { const r = await fetchJSON(`/api/v1/samba/shares/${encodeURIComponent(state.adoptShare)}/adopt`, { method: 'POST', body }); fillShareForm(null); return r; },
      `Share ${name} is now managed by the panel`, loadShares);
    return;
  }
  act(async () => { const r = await fetchJSON(`/api/v1/samba/shares/${encodeURIComponent(name)}`, { method: 'PUT', body }); fillShareForm(null); return r; }, `Share ${name} saved`, loadShares);
});
$('shareFormReset').addEventListener('click', () => fillShareForm(null));

/* ---------- raw samba config ---------- */
async function loadSambaConfig() {
  try { $('sambaConfig').value = (await fetchJSON('/api/v1/samba/config')).content || ''; }
  catch (err) { $('sambaConfig').value = ''; toast(err.message, true); }
}
$('saveSambaBtn').addEventListener('click', () => act(() => fetchJSON('/api/v1/samba/config', { method: 'PUT', body: { content: $('sambaConfig').value } }), 'smb.conf validated and saved'));
$('refreshSambaBtn').addEventListener('click', loadSambaConfig);

/* ---------- services & packages ---------- */
async function loadServices() {
  state.services = (await fetchJSON('/api/v1/services')).services || [];
  renderServices();
}
function renderServices() {
  const q = $('serviceFilter').value.toLowerCase();
  $('serviceTable').innerHTML = state.services.filter((s) => s.name.toLowerCase().includes(q)).map((s) => {
    const n = esc(s.name);
    const color = s.active === 'active' ? 'yes' : s.active === 'failed' ? 'fail' : 'no';
    return `<tr><td>${n}</td><td class="${color}">${esc(s.active || '-')}</td><td class="${s.enabled ? 'yes' : 'no'}">${esc(s.state)}</td><td class="actions">
      ${can('operator') ? ['start', 'stop', 'restart'].map((a) => `<button class="small secondary" data-act="${a}" data-svc="${n}">${a}</button>`).join(' ') : ''}</td></tr>`;
  }).join('') || '<tr><td colspan="4" class="muted">No services</td></tr>';
}
$('serviceFilter').addEventListener('input', renderServices);
$('serviceTable').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-act]'); if (!b) return;
  if (b.dataset.act !== 'start' && !confirm(`${b.dataset.act} ${b.dataset.svc}?`)) return;
  act(() => fetchJSON(`/api/v1/services/${encodeURIComponent(b.dataset.svc)}/${b.dataset.act}`, { method: 'POST', body: {} }), `${b.dataset.svc}: ${b.dataset.act} ok`, loadServices);
});

async function loadPackages() {
  state.packages = (await fetchJSON('/api/v1/packages')).packages || [];
  renderPackages();
}
function renderPackages() {
  const q = $('packageFilter').value.toLowerCase();
  const list = state.packages.filter((p) => p.name.toLowerCase().includes(q));
  $('packageTable').innerHTML = list.slice(0, 300).map((p) => `<tr><td>${esc(p.name)}</td><td class="muted">${esc(p.version)}</td><td>${esc(p.state)}</td></tr>`).join('')
    + (list.length > 300 ? `<tr><td colspan="3" class="muted">${list.length - 300} more – refine the filter</td></tr>` : '');
}
$('packageFilter').addEventListener('input', renderPackages);

/* ---------- network ---------- */
async function loadNetwork() {
  const n = (await fetchJSON('/api/v1/network')).network || {};
  $('gatewayValue').textContent = n.default_gateway || '-';
  $('dnsValue').textContent = (n.dns_servers || []).join(', ') || '-';
  $('networkTable').innerHTML = (n.interfaces || []).map((i) => `<tr>
    <td>${esc(i.name)}${i.loopback ? ' <span class="muted">(loopback)</span>' : ''}</td>
    <td class="${i.up ? 'yes' : 'no'}">${esc(i.oper_state || (i.up ? 'up' : 'down'))}</td>
    <td>${(i.addresses || []).map(esc).join('<br>') || '<span class="muted">-</span>'}</td>
    <td class="muted">${esc(i.mac || '-')}</td>
    <td>${i.speed_mbps ? `${i.speed_mbps} Mbit/s` : '-'}</td>
    <td class="muted">rx ${fmtBytes(i.rx_bytes)} · tx ${fmtBytes(i.tx_bytes)}</td></tr>`).join('');
}

/* ---------- logs ---------- */
async function loadLogs() {
  const f = $('logForm');
  if (!state.services.length) {
    fetchJSON('/api/v1/services').then((d) => {
      state.services = d.services || [];
      $('unitList').innerHTML = state.services.map((s) => `<option value="${esc(s.name)}">`).join('');
    }).catch(() => {});
  }
  const q = new URLSearchParams({ lines: f.lines.value || '200' });
  if (f.unit.value.trim()) q.set('unit', f.unit.value.trim());
  if (f.priority.value) q.set('priority', f.priority.value);
  try {
    const lines = (await fetchJSON(`/api/v1/logs?${q}`)).lines || [];
    $('logOutput').textContent = lines.join('\n') || 'No entries.';
    $('logOutput').scrollTop = $('logOutput').scrollHeight;
  } catch (err) {
    $('logOutput').textContent = err.message;
  }
}
$('logForm').addEventListener('submit', (e) => { e.preventDefault(); loadLogs(); });

/* ---------- panel accounts ---------- */
async function loadAccounts() {
  state.accounts = (await fetchJSON('/api/v1/accounts')).accounts || [];
  $('accountTable').innerHTML = state.accounts.map((a) => {
    const n = esc(a.username), self = a.username === state.me.username;
    const roles = ['viewer', 'operator', 'admin'].map((r) => `<option ${r === a.role ? 'selected' : ''}>${r}</option>`).join('');
    return `<tr><td>${n}${self ? ' <span class="muted">(you)</span>' : ''}</td>
      <td><select data-account="${n}">${roles}</select></td>
      <td class="muted">${esc(new Date(a.created_at).toLocaleString())}</td>
      <td class="actions"><button class="small secondary" data-act="pw" data-account="${n}">Set password</button>
      ${self ? '' : `<button class="small danger" data-act="del" data-account="${n}">Delete</button>`}</td></tr>`;
  }).join('');
}
$('accountTable').addEventListener('change', (e) => {
  const sel = e.target.closest('select[data-account]'); if (!sel) return;
  act(() => fetchJSON(`/api/v1/accounts/${encodeURIComponent(sel.dataset.account)}`, { method: 'PUT', body: { role: sel.value } }),
    `Role of ${sel.dataset.account} set to ${sel.value}`, async () => { await loadAccounts(); await refreshMe(); });
});
$('accountTable').addEventListener('click', async (e) => {
  const b = e.target.closest('button[data-act]'); if (!b) return;
  const name = b.dataset.account, enc = encodeURIComponent(name);
  if (b.dataset.act === 'pw') {
    const pw = await askPassword(`Panel password for ${name}`); if (pw === null) return;
    act(() => fetchJSON(`/api/v1/accounts/${enc}`, { method: 'PUT', body: { password: pw } }), 'Password updated, sessions of this account were ended');
  } else if (b.dataset.act === 'del' && confirm(`Delete panel account ${name}?`)) {
    act(() => fetchJSON(`/api/v1/accounts/${enc}`, { method: 'DELETE' }), 'Account deleted', loadAccounts);
  }
});
$('createAccountForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const f = e.target, body = { username: f.username.value.trim(), password: f.password.value, role: f.role.value };
  act(async () => { await fetchJSON('/api/v1/accounts', { method: 'POST', body }); f.reset(); }, `Account ${body.username} created`, loadAccounts);
});

/* ---------- audit ---------- */
async function loadAudit() {
  const entries = (await fetchJSON('/api/v1/audit')).entries || [];
  $('auditTable').innerHTML = entries.map((e) => `<tr>
    <td class="muted">${esc(new Date(e.time).toLocaleString())}</td><td>${esc(e.user)}</td><td>${esc(e.action)}</td>
    <td class="muted">${esc(e.target)}</td><td class="${e.status < 400 ? 'yes' : 'no'}">${e.status < 400 ? 'ok' : esc(e.status)}</td>
    <td class="muted">${esc(e.remote)}</td></tr>`).join('') || '<tr><td colspan="6" class="muted">No entries yet</td></tr>';
}

/* ---------- session ---------- */
// casaToken returns the CasaOS UI token when the panel runs under the CasaOS address.
function casaToken() {
  try { return localStorage.getItem('access_token') || ''; } catch { return ''; }
}

let casaAutoTried = false;
function showLogin() {
  state.me = null;
  $('loginScreen').classList.add('show');
  $('casaLoginBtn').hidden = !casaToken();
  $('loginForm').username.focus();
  if (casaToken() && !casaAutoTried) { casaAutoTried = true; casaLogin(true); }
}

async function casaLogin(silent) {
  try {
    await fetchJSON('/api/v1/auth/casaos', { method: 'POST', body: { token: casaToken() } });
    await refreshMe();
    $('loginScreen').classList.remove('show');
    route();
  } catch (err) {
    if (!silent) $('loginError').textContent = err.message;
  }
}
$('casaLoginBtn').addEventListener('click', () => casaLogin(false));
function applyMe(me) {
  state.me = me;
  document.body.classList.toggle('can-operator', can('operator'));
  document.body.classList.toggle('can-admin', can('admin'));
  $('meName').textContent = me.username;
  $('meRole').textContent = me.role;
  $('ownPwBtn').style.display = me.auth_disabled ? 'none' : '';
  $('logoutBtn').style.display = me.auth_disabled ? 'none' : '';
  $('casaShellHint').hidden = !me.casaos;
}
async function refreshMe() { applyMe(await fetchJSON('/api/v1/auth/me')); }

$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  try {
    await fetchJSON('/api/v1/auth/login', { method: 'POST', body: { username: f.username.value.trim(), password: f.password.value } });
    f.reset(); $('loginError').textContent = '';
    await refreshMe();
    $('loginScreen').classList.remove('show');
    route();
  } catch (err) {
    $('loginError').textContent = err.message;
  }
});
$('logoutBtn').addEventListener('click', async () => {
  try { await fetchJSON('/api/v1/auth/logout', { method: 'POST', body: {} }); } catch {}
  showLogin();
});
$('ownPwBtn').addEventListener('click', () => {
  const dlg = $('ownPwDialog'), f = $('ownPwForm');
  f.reset();
  $('ownPwCancel').onclick = () => dlg.close();
  f.onsubmit = (e) => {
    e.preventDefault();
    if (f.pw1.value !== f.pw2.value) { toast('Passwords do not match', true); return; }
    const body = { current_password: f.current.value, new_password: f.pw1.value };
    act(async () => { await fetchJSON('/api/v1/auth/password', { method: 'PUT', body }); dlg.close(); }, 'Password changed');
  };
  dlg.showModal();
});

/* ---------- routing ---------- */
const loaders = { dashboard: loadDashboard, users: loadUsers, groups: loadUsers, shares: loadShares, samba: loadSambaConfig, network: loadNetwork,
  services: loadServices, logs: loadLogs, packages: loadPackages, accounts: loadAccounts, audit: loadAudit };
const minRole = { samba: 'admin', accounts: 'admin', audit: 'admin', logs: 'operator' };
function route() {
  if (!state.me) return;
  let view = location.hash.slice(1) in loaders ? location.hash.slice(1) : 'dashboard';
  if (minRole[view] && !can(minRole[view])) view = 'dashboard';
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${view}`));
  document.querySelectorAll('#nav a').forEach((a) => a.classList.toggle('active', a.getAttribute('href') === `#${view}`));
  loaders[view]().catch((err) => toast(err.message, true));
}
window.addEventListener('hashchange', route);
refreshMe().then(route).catch(() => {});
setInterval(() => { if (state.me && $('view-dashboard').classList.contains('active')) loadDashboard().catch(() => {}); }, 10000);
