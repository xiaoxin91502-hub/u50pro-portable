// U50 Pro 控制台 — 浏览器端逻辑（无任何第三方依赖）。
// 接口与认证流程与开源项目 U50PRO-CON 的 src/services/router-client.js
// 及 docs/router-api-inventory.md 一致：
//   登录：GET /index.html → 读 wa_inner_version/cr_version → 读 LD →
//         password = SHA256(SHA256(明文密码) + LD)（大写十六进制）→ POST LOGIN → 读 loginfo
//   写接口：除 LOGIN 外需 AD = SHA256(SHA256(wa_inner_version + cr_version) + RD)，RD 现读。
//   读：GET /goform/goform_get_cmd_process?isTest=false&multi_data=1&cmd=字段1,字段2...
//   写：POST /goform/goform_set_cmd_process（application/x-www-form-urlencoded）。
// 所有请求默认走本机代理 /router-api（server.js），由代理注入 Origin/Referer、
// 透传 Cookie、重写 Set-Cookie。目标路由器地址经 X-Router-Target 头传入，
// 代理只允许局域网地址。直连模式（v1.7.0 随身版，跑在原厂页面里）则直接
// 调同源 goform 接口，不走代理（见下面的 DIRECT_MODE）。密码只存在内存变量里，不写 localStorage、不写文件。
'use strict';

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- 状态 ----------
let routerUrl = localStorage.getItem('u50pro-router-url') || 'http://192.168.0.1';

// ---------- 直连模式（v1.7.0 随身版） ----------
// 直连模式 = 控制台直接跑在原厂页面（http://192.168.0.1）里，和路由器同源，
// 手机浏览器直接调 goform 接口，不走电脑上的 Node 代理。开启方式：
//   window.__U50PRO_DIRECT__ = true（注入器在加载 app.js 之前设置）
//   或 URL 带 ?direct=1（测试用）。
// 密码同样只存在内存变量里；登录会话 cookie 由浏览器自己管（不经过代理）。
// 直连模式下路由器地址固定为当前页面 origin，改地址的入口会被锁住。
const DIRECT_MODE = (typeof window !== 'undefined' && window.__U50PRO_DIRECT__ === true)
  || (typeof location !== 'undefined' && new URLSearchParams(location.search).get('direct') === '1');
if (DIRECT_MODE && typeof location !== 'undefined' && location.origin && location.origin !== 'null') routerUrl = location.origin;
let password = ''; // 只放内存，页面关掉就没了
let accessIdSeed = '';
let loggedIn = false;
let polling = false;
let pollTimer = null;
let lastDash = null;
let writeQueue = Promise.resolve();
let qciProbed = false;
// v1.3.0 新增页面共用的状态（只放内存，不持久化）
let developerReady = false; // 开发者会话是否已建立（锁频段/锁小区用）
let aclState = { AclMode: '', BlackMacList: [], BlackNameList: [] };
let hostNames = []; // hostNameList 返回的自定义设备名 [{mac, hostname}]
let apnState = { mode: '', profiles: [], currentName: '', currentIndex: 0 };
let wifiAps = []; // queryAccessPointInfo 的 ResponseList
let cellCandidates = []; // 邻区候选（含当前服务小区）
let netState = { bearer: '', ppp: '', roam: '' };

// ---------- 工具 ----------
function toast(text, ok) {
  const el = $('toast');
  $('toast-text').textContent = text;
  el.classList.toggle('ok', !!ok);
  el.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove('show'), 3200);
}
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function num(v) {
  const n = parseFloat(v);
  return Number.isFinite(n) ? n : null;
}
function fmtBytes(bytes) {
  const b = num(bytes);
  if (b == null) return '—';
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(2)} MB`;
  return `${(b / 1024 ** 3).toFixed(2)} GB`;
}
function fmtRate(bytesPerSec) {
  const b = num(bytesPerSec);
  if (b == null) return '—';
  if (b < 1024) return `${b.toFixed(0)} B/s`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB/s`;
  return `${(b / 1024 ** 2).toFixed(2)} MB/s`;
}
function fmtSeconds(sec) {
  const s = num(sec);
  if (s == null) return '—';
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h} 小时 ${m} 分钟`;
  if (m > 0) return `${m} 分钟`;
  return `${Math.floor(s)} 秒`;
}
function fmtMinutes(min) {
  if (min == null) return '—';
  if (min < 60) return `约 ${Math.round(min)} 分钟`;
  const h = Math.floor(min / 60), m = Math.round(min % 60);
  return `约 ${h} 小时${m ? ` ${m} 分钟` : ''}`;
}

// ---------- SHA256 ----------
// 首选 Web Crypto；手机用局域网 IP（http://192.168.x.x）打开时不是安全上下文，
// crypto.subtle 不可用，改走下面的纯 JS 实现（输出与 Web Crypto 完全一致，
// 大写十六进制；已用 Node crypto 对照验证过）。
async function sha256Hex(text) {
  if (window.crypto && crypto.subtle) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(text)));
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }
  return sha256Js(text);
}
function sha256Js(text) {
  const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  const rr = (v, a) => ((v >>> a) | (v << (32 - a))) >>> 0;
  const bytes = new TextEncoder().encode(String(text));
  const bitLen = bytes.length * 8;
  const paddedLen = (((bytes.length + 9 + 63) >> 6) << 6);
  const m = new Uint8Array(paddedLen);
  m.set(bytes);
  m[bytes.length] = 0x80;
  const dv = new DataView(m.buffer);
  dv.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000));
  dv.setUint32(paddedLen - 4, bitLen >>> 0);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);
  for (let off = 0; off < paddedLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = (rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
      const s1 = (rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = (rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  return [h0, h1, h2, h3, h4, h5, h6, h7].map((x) => x.toString(16).padStart(8, '0')).join('').toUpperCase();
}

// ---------- 路由器请求（走本机代理） ----------
function apiHeaders(extra) {
  return { 'X-Router-Target': routerUrl, ...(extra || {}) };
}
async function requestRouter(path, options = {}) {
  const headers = {
    Accept: 'application/json, text/javascript, */*; q=0.01',
    'X-Requested-With': 'XMLHttpRequest',
    ...(options.headers || {})
  };
  // 直连模式（v1.7.0 随身版）：页面本身就跑在原厂页面里，和路由器同源，
  // 直接调 goform 接口，不走 /router-api 代理，也不带 X-Router-Target。
  const url = DIRECT_MODE ? path : `/router-api${path}`;
  const res = await fetch(url, {
    method: options.method || 'GET',
    headers: DIRECT_MODE ? headers : apiHeaders(headers),
    body: options.body,
    credentials: 'same-origin'
  });
  const text = await res.text();
  if (res.status < 200 || res.status >= 300) throw new Error(`路由器返回 HTTP ${res.status}`);
  try { return JSON.parse(text); } catch { return text; }
}
function qs(values) {
  return Object.entries(values)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v == null ? '' : String(v))}`)
    .join('&');
}
async function getFields(fields, extra = {}) {
  const query = qs({ isTest: 'false', multi_data: '1', cmd: fields.join(','), _: Date.now(), ...extra });
  return requestRouter(`/goform/goform_get_cmd_process?${query}`);
}
async function getCommand(cmd, params = {}) {
  const query = qs({ isTest: 'false', cmd, ...params, _: Date.now() });
  return requestRouter(`/goform/goform_get_cmd_process?${query}`);
}
async function accessibleId() {
  if (!accessIdSeed) {
    const version = await getFields(['wa_inner_version', 'cr_version']);
    accessIdSeed = `${version.wa_inner_version || ''}${version.cr_version || ''}`;
  }
  const token = await getFields(['RD']);
  if (!token.RD) throw new Error('固件未返回写接口动态令牌 RD');
  return sha256Hex((await sha256Hex(accessIdSeed)) + token.RD);
}
function setGoform(goformId, data = {}) {
  const task = async () => {
    const values = { isTest: 'false', goformId, ...data };
    if (goformId !== 'LOGIN' && goformId !== 'SET_WEB_LANGUAGE') values.AD = await accessibleId();
    const res = await requestRouter('/goform/goform_set_cmd_process', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
      body: qs(values)
    });
    return typeof res === 'string' ? safeJson(res) : res;
  };
  const pending = writeQueue.then(task, task);
  writeQueue = pending.catch(() => {});
  return pending;
}
function safeJson(v) { try { return JSON.parse(v); } catch { return { raw: v }; } }
function assertSuccess(result, label) {
  const ok = ['success', '0', '4', 0, 4, true].includes(result?.result) || result?.result === true;
  if (!ok) throw new Error(`固件拒绝${label}：${result?.result || JSON.stringify(result)}`);
}

// ---------- 开发者会话（锁频段 / 锁小区需要，与 U50PRO-CON 一致） ----------
// 先查 developer_option_loginfo；没建会话就用登录密码建一个（主登录先刷新一次，
// 再用新 LD 算一次 DEVELOPER_OPTION_LOGIN，最多等 6×150ms）。
async function developerLogin() {
  const cur = await getFields(['developer_option_loginfo']).catch(() => ({}));
  if (cur.developer_option_loginfo === 'ok') { developerReady = true; return; }
  await doLoginSilent();
  const token = await getFields(['LD']);
  const hashed = await sha256Hex((await sha256Hex(password)) + (token.LD || ''));
  const result = await setGoform('DEVELOPER_OPTION_LOGIN', { password: hashed });
  for (let i = 0; i < 6; i++) {
    const st = await getFields(['developer_option_loginfo']).catch(() => ({}));
    if (st.developer_option_loginfo === 'ok') { developerReady = true; return; }
    await sleep(150);
  }
  throw new Error(`开发者认证失败：${result?.result ?? '未知响应'}`);
}
async function ensureDeveloperAccess() {
  if (developerReady) {
    const st = await getFields(['developer_option_loginfo']).catch(() => ({}));
    if (st.developer_option_loginfo === 'ok') return;
    developerReady = false;
  }
  await developerLogin();
}

// ---------- Base64（UTF-8 安全；Wi-Fi 密码按官方接口要求用 Base64 传） ----------
function b64encode(str) {
  const bytes = new TextEncoder().encode(String(str));
  let bin = '';
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
  return btoa(bin);
}

// ---------- IP 校验（LAN/DHCP 表单用，与 UFI-TOOLS 的校验逻辑一致） ----------
function ipToInt(ip) {
  return String(ip || '').split('.').reduce((a, x) => (a * 256) + Number(x), 0);
}
function isValidIP(ip) {
  const p = String(ip || '').split('.');
  return p.length === 4 && p.every((x) => /^\d+$/.test(x) && Number(x) >= 0 && Number(x) <= 255);
}
function isValidMask(mask) {
  if (!isValidIP(mask)) return false;
  const n = ipToInt(mask) >>> 0;
  const inv = (~n) >>> 0;
  return n !== 0 && (inv & (inv + 1)) === 0;
}
function sameSubnet(a, b, mask) {
  return (ipToInt(a) & ipToInt(mask)) === (ipToInt(b) & ipToInt(mask));
}
function networkAddr(ip, mask) {
  const n = (ipToInt(ip) & ipToInt(mask)) >>> 0;
  return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
}
function broadcastAddr(ip, mask) {
  const n = ((ipToInt(ip) & ipToInt(mask)) | (~ipToInt(mask))) >>> 0;
  return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
}

// ---------- 登录（v1.6.0：无确认按钮，输对密码自动进） ----------
// 输密码时停下 800ms 自动试一次：对了直接进主界面，错了在密码框下面显示
// “密码错误”，用户继续改，不用点什么。防刷：只在密码长度 ≥4 且和上次试
// 过的值不一样时才自动试，避免每敲一个键都去撞路由器。回车键也直接登录。
// 其余逻辑不动（LD + SHA256、服务端 cookie 罐、密码不保存）。
let loginInFlight = false;
let lastLoginKey = '';
let loginTimer = null;
function loginStatus(show) { $('login-status').classList.toggle('show', !!show); }
function showLoginError(msg) {
  const errEl = $('login-err');
  errEl.textContent = msg;
  errEl.classList.add('show');
}
function hideLoginError() { $('login-err').classList.remove('show'); }
function loginKey(addr, pass) { return `${addr}\n${pass}`; }
function scheduleAutoLogin() {
  hideLoginError();
  clearTimeout(loginTimer);
  loginTimer = setTimeout(() => {
    const addr = $('login-addr').value.trim();
    const pass = $('login-pass').value;
    if (pass.length < 4 || loginInFlight) return;
    if (loginKey(addr, pass) === lastLoginKey) return;
    doLogin();
  }, 800);
}
async function doLogin() {
  const addr = $('login-addr').value.trim();
  const pass = $('login-pass').value;
  if (!addr) { showLoginError('请先填路由器地址。'); return; }
  if (!pass) { showLoginError('请先填登录密码。'); return; }
  if (loginInFlight) return;
  loginInFlight = true;
  lastLoginKey = loginKey(addr, pass);
  hideLoginError();
  loginStatus(true);
  routerUrl = addr.replace(/\/$/, '');
  password = pass;
  localStorage.setItem('u50pro-router-url', routerUrl);
  let step = '连接路由器';
  let wrongPassword = false;
  try {
    step = '打开路由器首页';
    await requestRouter('/index.html');
    step = '读取固件版本';
    const version = await getFields(['Language', 'cr_version', 'wa_inner_version']);
    accessIdSeed = `${version.wa_inner_version || ''}${version.cr_version || ''}`;
    step = '读取登录令牌 LD';
    const token = await getFields(['LD']);
    const hashed = await sha256Hex((await sha256Hex(password)) + (token.LD || ''));
    step = '提交登录';
    const result = await setGoform('LOGIN', { password: hashed });
    step = '确认登录状态';
    const log = await getFields(['loginfo']);
    const ok = ['0', '4', 0, 4].includes(result?.result) || log.loginfo === 'ok';
    if (!ok) { wrongPassword = true; throw new Error('LOGIN_REJECTED'); }
    loggedIn = true;
    enterApp(version.wa_inner_version || version.cr_version || '');
    toast('登录成功', true);
  } catch (e) {
    if (wrongPassword) showLoginError('密码错误');
    else showLoginError(`登录失败（${step}）：${e.message}。` + (DIRECT_MODE ? '请检查密码和手机是否连着 U50 Pro 的 Wi-Fi。' : '请检查路由器地址、密码，以及电脑是否连上了 U50 Pro 的 Wi-Fi。'));
  } finally {
    loginInFlight = false;
    loginStatus(false);
  }
}
async function ensureLogin() {
  let status = await getFields(['loginfo']).catch(() => ({ loginfo: '' }));
  if (status.loginfo !== 'ok') {
    if (!password) throw new Error('会话已过期，请重新登录');
    await doLoginSilent();
  }
  status = await getFields(['loginfo']).catch(() => ({ loginfo: '' }));
  if (status.loginfo !== 'ok') throw new Error('路由器登录失败，请重新登录');
}
async function doLoginSilent() {
  await requestRouter('/index.html');
  const version = await getFields(['Language', 'cr_version', 'wa_inner_version']);
  accessIdSeed = `${version.wa_inner_version || ''}${version.cr_version || ''}`;
  const token = await getFields(['LD']);
  const hashed = await sha256Hex((await sha256Hex(password)) + (token.LD || ''));
  const result = await setGoform('LOGIN', { password: hashed });
  const log = await getFields(['loginfo']);
  if (!(['0', '4', 0, 4].includes(result?.result) || log.loginfo === 'ok')) {
    throw new Error('自动重新登录失败');
  }
}
function enterApp(fw) {
  $('login-view').hidden = true;
  $('app-view').hidden = false;
  $('conn-dot').className = 'dot on';
  $('conn-text').textContent = `已连接 ${routerUrl}`;
  $('set-addr').value = routerUrl;
  if (fw) $('ov-fw').textContent = fw;
  startPolling();
  refreshAll(true);
}
function exitApp(message) {
  loggedIn = false;
  stopPolling();
  password = '';
  accessIdSeed = '';
  // 代理模式：清掉服务端保存的路由器会话 Cookie，下次登录用全新会话。
  // 直连模式：没有服务端，cookie 由浏览器自己管，退出时不调这一步
  //（/logout-session 在原厂页面不存在，调了只会 404）。
  if (!DIRECT_MODE) fetch('/logout-session', { method: 'POST' }).catch(() => {});
  $('login-view').hidden = false;
  $('app-view').hidden = true;
  $('login-pass').value = '';
  if (message) {
    const errEl = $('login-err');
    errEl.textContent = message;
    errEl.classList.add('show');
  }
}

// ---------- 字段表（与 U50PRO-CON 的 router-client.js 一致） ----------
const signalFields = ['network_type', 'network_provider', 'Operator', 'rmcc', 'rmnc', 'mdm_mcc', 'mdm_mnc', 'rssi', 'lte_rssi', 'rscp', 'lte_rsrp', 'lte_rsrq', 'lte_snr', 'ecio', 'Z5g_snr', 'Z5g_SINR', 'Z5g_rsrp', 'Z5g_rsrq', 'Z5g_rssi', 'signalbar', 'wan_lte_ca', 'nr_ca_dl_state', 'nr_ca_ul_state', 'lte_pci', 'cell_id', 'wan_active_band', 'wan_active_channel', 'bandwidth', 'lte_ca_pcell_arfcn', 'lte_ca_pcell_band', 'lte_ca_pcell_bandwidth', 'lte_ca_scell_arfcn', 'lte_ca_scell_band', 'lte_ca_scell_bandwidth', 'lte_ca_scell_info', 'lte_multi_ca_scell_info', 'lte_multi_ca_scell_sig_info', 'nr5g_pci', 'nr5g_action_band', 'nr5g_action_channel', 'nr5g_cell_id', 'Z5g_CELL_ID', 'Z5g_dlEarfcn', 'nr5g_nsa_bandwidth', 'nr_multi_ca_scell_info'];
const statusFields = ['loginfo', 'modem_main_state', 'simcard_roam', 'sim_iccid', 'imei', 'imsi', 'sim_imsi', 'msisdn', 'sim_msisdn', 'phone_number', 'opms_wan_mode', 'opms_wan_auto_mode', 'ppp_status', 'wan_connect_status', 'wan_ipaddr', 'ipv6_wan_ipaddr', 'lan_ipaddr', 'wifi_mac_address', 'wa_inner_version', 'wa_version', 'hardware_version', 'web_version', 'realtime_tx_bytes', 'realtime_rx_bytes', 'realtime_tx_thrpt', 'realtime_rx_thrpt', 'realtime_time', 'monthly_rx_bytes', 'monthly_tx_bytes', 'monthly_time', 'date_month', 'wifi_onoff_state', 'wifi_lbd_enable', 'wifi_chip1_ssid1_ssid', 'wifi_chip2_ssid1_ssid', 'wifi_chip1_ssid1_access_sta_num', 'wifi_chip2_ssid1_access_sta_num', 'wifi_access_sta_num', 'battery_temp', 'battery_value', 'battery_vol_percent', 'battery_charging', 'battery_charg_type', 'external_charging_flag', 'battery_pers', 'battery_customer_mode', 'battery_time', 'battery_remain_time', 'battery_remaining_time', 'battery_capacity', 'battery_health', 'battery_voltage', 'battery_current', 'sms_unread_num'];
const featureFields = ['data_volume_limit_switch', 'data_volume_limit_unit', 'data_volume_limit_size', 'data_volume_alert_percent', 'wan_auto_clear_flow_data_switch', 'traffic_clear_date'];
const temperatureFields = ['battery_temp', 'wifi_chip_temp', 'wifi_temp_level_1', 'wifi_temp_level_2', 'pm_sensor_pa1', 'pm_sensor_mdm', 'pm_modem_5g', 'therm_pa_level', 'therm_pa_frl_level', 'therm_tj_level', 'OOM_TEMP_PRO', 'cpu_temp', 'cpu_temperature', 'soc_temp', 'board_temp', 'modem_temp'];
const resourceFields = ['cpu_usage', 'cpu_load', 'cpu_percent', 'mem_usage', 'memory_usage', 'memory_percent', 'mem_total', 'mem_free', 'MemTotal', 'MemFree', 'ram_total', 'ram_free', 'loadavg'];
const lockFields = ['nr5g_cell_lock', 'lte_band_lock', 'lte_freq_lock', 'lte_pci_lock', 'lte_earfcn_lock', 'nr5g_band_lock', 'nr5g_sa_band_lock', 'nr5g_nsa_band_lock', 'operate_mode'];

// ---------- 仪表盘 ----------
async function fetchDashboard() {
  await ensureLogin();
  const [status, signal, temperature, resources, locks, stations, cable, features] = await Promise.all([
    getFields(statusFields),
    getFields(signalFields),
    getFields(temperatureFields),
    getFields(resourceFields),
    getFields(lockFields),
    getCommand('station_list').catch(() => ({ station_list: [] })),
    getCommand('lan_station_list').catch(() => ({ lan_station_list: [] })),
    getFields(featureFields).catch(() => ({}))
  ]);
  const battery = batterySummary(status);
  recordBattery(status, temperature);
  return { timestamp: Date.now(), status, signal, temperature, resources, locks, stations: normList(stations.station_list), cableStations: normList(cable.lan_station_list || cable.station_list), features, battery };
}
function normList(v) {
  if (Array.isArray(v)) return v;
  if (!v || typeof v !== 'object') return [];
  return Object.values(v).filter((x) => x && typeof x === 'object');
}
function pick(obj, keys) {
  for (const k of keys) {
    const v = obj?.[k];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return '';
}
function renderDashboard(d) {
  lastDash = d;
  const s = d.status, g = d.signal, t = d.temperature, r = d.resources;
  // 网络
  const net = pick(g, ['network_type']) || '—';
  $('ov-net').textContent = net;
  $('ov-band').textContent = pick(g, ['wan_active_band', 'nr5g_action_band']) ? `· ${pick(g, ['wan_active_band', 'nr5g_action_band'])}` : '';
  const op = pick(g, ['network_provider', 'Operator']) || pick(s, ['network_provider']) || '—';
  $('ov-operator').textContent = `${op} · MCC ${pick(g, ['rmcc', 'mdm_mcc']) || '—'} / MNC ${pick(g, ['rmnc', 'mdm_mnc']) || '—'}`;
  const pill = $('ov-net-pill');
  const connected = String(s.wan_connect_status || s.ppp_status || '').toLowerCase();
  if (connected.includes('connect') || s.ppp_status === 'ppp_connected') { pill.className = 'pill green'; pill.textContent = '已联网'; }
  else { pill.className = 'pill gray'; pill.textContent = s.wan_connect_status || s.ppp_status || '状态未知'; }
  const roam = $('ov-roam');
  const roamV = String(s.simcard_roam || '');
  if (roamV && roamV !== 'Internal' && roamV.toLowerCase() !== 'home') { roam.hidden = false; roam.textContent = `漫游 ${roamV}`; }
  else roam.hidden = true;
  // 信号格
  const bars = num(g.signalbar);
  [...$('ov-bars').children].forEach((el, i) => el.classList.toggle('dim', bars == null ? true : i >= bars));
  $('ov-bars-n').textContent = bars == null ? '—' : `${bars} / 5`;
  // 速率
  $('ov-dl').textContent = fmtRate(g.Z5g_rsrp !== undefined ? s.realtime_rx_thrpt : s.realtime_rx_thrpt);
  $('ov-ul').textContent = fmtRate(s.realtime_tx_thrpt);
  const is5g = /5g|nr|sa|nsa/i.test(net);
  $('ov-rsrp').textContent = fmtDbm(is5g ? pick(g, ['Z5g_rsrp']) : pick(g, ['lte_rsrp']));
  $('ov-sinr').textContent = fmtDb(is5g ? pick(g, ['Z5g_SINR', 'Z5g_snr']) : pick(g, ['lte_snr']));
  $('ov-rsrq').textContent = fmtDb(is5g ? pick(g, ['Z5g_rsrq']) : pick(g, ['lte_rsrq']));
  // 总览三块摘要：接入设备 / 当前网络 / 实时速率（只汇总已有数据，不多请求）
  const wifiN = num(s.wifi_access_sta_num);
  const lanN = d.cableStations ? d.cableStations.length : null;
  const totalDev = (wifiN == null && lanN == null) ? null : (wifiN || 0) + (lanN || 0);
  $('ov-sum-dev').textContent = totalDev == null ? '—' : `${totalDev} 台`;
  $('ov-sum-dev-sub').textContent = `Wi-Fi ${wifiN == null ? '—' : wifiN + ' 台'} · 有线 ${lanN == null ? '—' : lanN + ' 台'}`;
  $('ov-sum-net').textContent = `${net}${pick(g, ['wan_active_band', 'nr5g_action_band']) ? ` · ${pick(g, ['wan_active_band', 'nr5g_action_band'])}` : ''}`;
  const sumRsrp = is5g ? pick(g, ['Z5g_rsrp']) : pick(g, ['lte_rsrp']);
  $('ov-sum-sig').textContent = `RSRP ${sumRsrp || '—'} dBm · 信号 ${bars == null ? '—' : bars + ' / 5 格'}`;
  $('ov-sum-rate').textContent = `↓ ${fmtRate(s.realtime_rx_thrpt)} · ↑ ${fmtRate(s.realtime_tx_thrpt)}`;
  $('ov-sum-time').textContent = `本次会话 ${fmtSeconds(s.realtime_time)}`;
  // 设备信息
  $('ov-wan4').textContent = s.wan_ipaddr || '—';
  $('ov-wan6').textContent = s.ipv6_wan_ipaddr || '—';
  $('ov-lan').textContent = s.lan_ipaddr || routerUrl;
  $('ov-imei').textContent = s.imei || '—';
  $('ov-iccid').textContent = s.sim_iccid || '—';
  $('ov-phone').textContent = pick(s, ['msisdn', 'sim_msisdn', 'phone_number']) || '—';
  $('ov-fw').textContent = pick(s, ['wa_inner_version', 'wa_version']) || '—';
  $('ov-hw').textContent = s.hardware_version || '—';
  $('ov-cpu').textContent = fmtPct(pick(r, ['cpu_usage', 'cpu_percent']));
  $('ov-mem').textContent = fmtPct(pick(r, ['mem_usage', 'memory_usage', 'memory_percent']));
  // 温度（只显示有值的）
  const tempPairs = [
    ['电池', t.battery_temp], ['Wi-Fi 芯片', t.wifi_chip_temp],
    ['射频 PA', t.pm_sensor_pa1], ['Modem', t.pm_sensor_mdm], ['5G Modem', t.pm_modem_5g],
    ['CPU', pick(t, ['cpu_temp', 'cpu_temperature'])], ['SoC', t.soc_temp], ['主板', t.board_temp]
  ].filter(([, v]) => num(v) != null);
  $('ov-temps').textContent = tempPairs.length
    ? '温度：' + tempPairs.map(([k, v]) => `${k} ${v}°C`).join(' · ')
    : '温度：设备未返回温度字段。';
  // 服务小区
  const pci = pick(g, ['nr5g_pci', 'lte_pci']);
  const cellId = pick(g, ['nr5g_cell_id', 'Z5g_CELL_ID', 'cell_id']);
  const arfcn = pick(g, ['nr5g_action_channel', 'Z5g_dlEarfcn', 'wan_active_channel']);
  $('ov-cell').textContent = (pci || cellId || arfcn)
    ? `服务小区：PCI ${pci || '—'} · 小区 ID ${cellId || '—'} · 信道/ARFCN ${arfcn || '—'} · 带宽 ${pick(g, ['bandwidth', 'nr5g_nsa_bandwidth']) || '—'} MHz`
    : '服务小区：设备未返回小区信息。';
  const ca = [];
  if (g.wan_lte_ca) ca.push(`LTE CA ${g.wan_lte_ca}`);
  if (g.nr_ca_dl_state) ca.push(`NR CA 下行 ${g.nr_ca_dl_state}`);
  if (g.nr_ca_ul_state) ca.push(`NR CA 上行 ${g.nr_ca_ul_state}`);
  $('ov-ca').textContent = ca.length ? `载波聚合：${ca.join(' · ')}` : '载波聚合：无数据。';
  // 联网状态
  const pppMap = { ppp_connected: '已连接', ppp_connecting: '拨号中', ppp_disconnected: '未连接', ppp_failed: '拨号失败' };
  $('ov-ppp').textContent = pppMap[s.ppp_status] || s.ppp_status || s.wan_connect_status || '—';
  $('ov-wanmode').textContent = s.opms_wan_mode || '—';
  $('ov-opmode').textContent = pick(d.locks, ['operate_mode']) || '—';
  $('ov-wifi').textContent = s.wifi_onoff_state === '1' ? '开启' : s.wifi_onoff_state === '0' ? '关闭' : '—';
  $('ov-sta24').textContent = s.wifi_chip1_ssid1_access_sta_num ?? '—';
  $('ov-sta5').textContent = s.wifi_chip2_ssid1_access_sta_num ?? '—';
  $('ov-updated').textContent = new Date(d.timestamp).toLocaleTimeString('zh-CN');
  // 流量
  const mDl = num(s.monthly_rx_bytes), mUl = num(s.monthly_tx_bytes);
  $('tr-month-total').textContent = (mDl == null && mUl == null) ? '—' : fmtBytes((mDl || 0) + (mUl || 0));
  $('tr-month-dl').textContent = fmtBytes(s.monthly_rx_bytes);
  $('tr-month-ul').textContent = fmtBytes(s.monthly_tx_bytes);
  $('tr-month-time').textContent = fmtSeconds(s.monthly_time);
  $('tr-sess-dl').textContent = fmtBytes(s.realtime_rx_bytes);
  $('tr-sess-ul').textContent = fmtBytes(s.realtime_tx_bytes);
  $('tr-sess-time').textContent = fmtSeconds(s.realtime_time);
  renderTrafficPlan(d.features, mDl, mUl);
  // 电池
  renderBattery(d.battery, s, t);
  // 未读短信角标（标签页 + 总览快捷操作同步）
  const unread = num(s.sms_unread_num);
  const badge = $('sms-badge');
  const qaBadge = $('qa-sms-badge');
  if (unread != null && unread > 0) {
    badge.hidden = false; badge.textContent = unread;
    qaBadge.hidden = false; qaBadge.textContent = unread;
  } else {
    badge.hidden = true;
    qaBadge.hidden = true;
  }
  // 设备
  renderDevices(d.stations, d.cableStations);
  // 设置页 Wi-Fi 状态
  $('set-wifi-state').textContent = s.wifi_onoff_state === '1' ? '开启' : s.wifi_onoff_state === '0' ? '关闭' : '—';
  // QCI 相关字段
  $('qci-net').textContent = net;
  $('qci-band').textContent = pick(g, ['wan_active_band', 'nr5g_action_band']) || '—';
  $('qci-apn').textContent = s.opms_wan_mode || '—';
  $('qci-op').textContent = op;
  renderBatteryTemps(t);
}
function fmtDbm(v) { const n = num(v); return n == null ? '—' : `${n} dBm`; }
function fmtDb(v) { const n = num(v); return n == null ? '—' : `${n} dB`; }
function fmtPct(v) { const n = num(v); return n == null ? '—' : `${n}%`; }

// ---------- 流量套餐 ----------
function planSizeGb(features) {
  const raw = String(features?.data_volume_limit_size || '');
  const m = raw.match(/^([\d.]+)_1024$/);
  return m ? Number(m[1]) : null;
}
function renderTrafficPlan(f, mDl, mUl) {
  const on = f?.data_volume_limit_switch === '1';
  const sizeGb = planSizeGb(f);
  const usedGb = (mDl == null && mUl == null) ? null : ((mDl || 0) + (mUl || 0)) / 1024 ** 3;
  if (!on || sizeGb == null) {
    $('tr-plan-summary').textContent = on
      ? '套餐限制已开启，但路由器未返回套餐大小。'
      : '套餐限制未开启。';
    $('tr-plan-bar').style.width = '0%';
    $('tr-plan-bar').className = '';
  } else {
    const pct = Math.min(100, Math.max(0, ((usedGb || 0) / sizeGb) * 100));
    const remain = Math.max(0, sizeGb - (usedGb || 0));
    $('tr-plan-summary').innerHTML = `套餐 <b>${sizeGb} GB</b> · 已用 <b>${usedGb == null ? '—' : usedGb.toFixed(2) + ' GB'}</b> · 剩余 <b>${remain.toFixed(2)} GB</b> · 提醒 ${f.data_volume_alert_percent ?? '—'}% · 每月 ${f.traffic_clear_date || '—'} 号清零${f.wan_auto_clear_flow_data_switch === 'on' ? '（自动）' : ''}`;
    const bar = $('tr-plan-bar');
    bar.style.width = `${pct}%`;
    bar.className = pct >= 90 ? 'red' : pct >= 70 ? 'amber' : '';
  }
  // 表单回填（只在用户没打开表单时）
  if ($('tr-plan-form').hidden) {
    $('tr-plan-on').checked = on;
    $('tr-plan-size').value = sizeGb ?? '';
    $('tr-plan-alert').value = f?.data_volume_alert_percent ?? '';
    $('tr-plan-autoclear').checked = f?.wan_auto_clear_flow_data_switch === 'on';
    $('tr-plan-date').value = f?.traffic_clear_date ?? '';
  }
}
async function saveTrafficPlan() {
  const size = Number($('tr-plan-size').value);
  if (!Number.isFinite(size) || size < 0) { toast('套餐流量必须是大于等于 0 的数字'); return; }
  const alert = Number($('tr-plan-alert').value);
  if (!Number.isFinite(alert) || alert < 0 || alert > 100) { toast('提醒百分比必须在 0–100 之间'); return; }
  const clearDate = String($('tr-plan-date').value || '').trim();
  if (clearDate && (!/^\d{1,2}$/.test(clearDate) || Number(clearDate) < 1 || Number(clearDate) > 31)) { toast('清零日期必须是 1–31'); return; }
  const sizeStr = `${Math.round(size * 100) / 100}_1024`;
  try {
    const res = await setGoform('DATA_LIMIT_SETTING', {
      data_volume_limit_switch: $('tr-plan-on').checked ? '1' : '0',
      data_volume_limit_unit: 'data',
      data_volume_limit_size: sizeStr,
      data_volume_alert_percent: String(Math.round(alert)),
      wan_auto_clear_flow_data_switch: $('tr-plan-autoclear').checked ? 'on' : 'off',
      traffic_clear_date: clearDate || '1'
    });
    assertSuccess(res, '流量设置');
    $('tr-plan-form').hidden = true;
    toast('套餐设置已保存', true);
    refreshAll(true);
  } catch (e) { toast(`保存失败：${e.message}`); }
}
async function saveCalibration() {
  const gb = Number($('tr-cal-gb').value);
  if (!Number.isFinite(gb) || gb < 0) { toast('已用流量必须是大于等于 0 的数字'); return; }
  try {
    const res = await setGoform('FLOW_CALIBRATION_MANUAL', {
      calibration_way: 'data', data: String(Math.round(gb * 1024 ** 3)), time: '0'
    });
    assertSuccess(res, '已用流量校准');
    $('tr-cal-form').hidden = true;
    toast('已用流量已校准', true);
    refreshAll(true);
  } catch (e) { toast(`校准失败：${e.message}`); }
}

// ---------- 电池 ----------
const BT_KEY = 'u50pro-battery-history';
const BT_WINDOW_MS = 12 * 60 * 60 * 1000;
const BT_MAX = 725;
function loadBtHistory() {
  try {
    const v = JSON.parse(localStorage.getItem(BT_KEY) || '[]');
    return Array.isArray(v) ? v : [];
  } catch { return []; }
}
function saveBtHistory(list) {
  try { localStorage.setItem(BT_KEY, JSON.stringify(list)); } catch {}
}
let btHistory = loadBtHistory();
function recordBattery(status, temperature) {
  const pct = num(status.battery_vol_percent || status.battery_value);
  if (pct == null) return;
  const now = Date.now();
  const charging = status.battery_charging === '1' || status.external_charging_flag === '1';
  const last = btHistory.at(-1);
  if (last && now - last.timestamp < 60000 && last.charging === charging) return;
  btHistory.push({
    timestamp: now, percent: pct, charging,
    temperature: num(temperature.battery_temp),
    chargeType: status.battery_charg_type || '',
    externalPower: status.external_charging_flag === '1',
    voltage: status.battery_voltage || '', current: status.battery_current || '',
    capacity: status.battery_capacity || '', health: status.battery_health || ''
  });
  const cutoff = now - BT_WINDOW_MS;
  btHistory = btHistory.filter((x) => x.timestamp >= cutoff).slice(-BT_MAX);
  saveBtHistory(btHistory);
}
function batterySummary(status) {
  const pct = num(status.battery_vol_percent || status.battery_value);
  const charging = status.battery_charging === '1' || status.external_charging_flag === '1';
  const recent = [];
  const cutoff = Date.now() - BT_WINDOW_MS;
  for (let i = btHistory.length - 1; i >= 0; i--) {
    const item = btHistory[i];
    if (item.timestamp < cutoff || item.charging !== charging) break;
    recent.unshift(item);
  }
  let ratePerHour = null;
  if (recent.length >= 2) {
    const first = recent[0], last = recent.at(-1);
    const hours = (last.timestamp - first.timestamp) / 3600000;
    const delta = charging ? last.percent - first.percent : first.percent - last.percent;
    if (hours >= 0.15 && delta > 0) ratePerHour = delta / hours;
  }
  const remainingHours = ratePerHour && pct != null
    ? (charging ? Math.max(0, (100 - pct) / ratePerHour) : Math.max(0, pct / ratePerHour))
    : null;
  return { percent: pct, charging, ratePerHour, remainingHours };
}
function renderBattery(b, s, t) {
  $('bt-pct').textContent = b.percent == null ? '—' : Math.round(b.percent);
  const state = $('bt-state');
  if (b.charging) { state.className = 'pill green'; state.textContent = '充电中'; }
  else if (b.percent == null) { state.className = 'pill gray'; state.textContent = '状态未知'; }
  else { state.className = 'pill gray'; state.textContent = '电池供电'; }
  const bits = [];
  if (s.battery_charg_type) bits.push(`充电类型 ${s.battery_charg_type}`);
  if (s.external_charging_flag === '1') bits.push('外接电源');
  if (s.battery_customer_mode) bits.push(`模式 ${s.battery_customer_mode}`);
  $('bt-detail').textContent = bits.length ? bits.join(' · ') : '—';
  $('bt-temp').textContent = num(t.battery_temp) == null ? '—' : `${t.battery_temp}°C`;
  $('bt-rate').textContent = b.ratePerHour == null ? '—' : `${b.ratePerHour.toFixed(1)}% / 小时`;
  $('bt-remain').textContent = b.remainingHours == null ? '—' : (b.charging ? `充满 ${fmtMinutes(Math.round(b.remainingHours * 60))}` : `用完 ${fmtMinutes(Math.round(b.remainingHours * 60))}`);
  $('bt-volt').textContent = s.battery_voltage ? `${s.battery_voltage}` : '—';
  $('bt-curr').textContent = s.battery_current ? `${s.battery_current}` : '—';
  $('bt-health').textContent = s.battery_health || '—';
  drawBtChart();
}
function renderBatteryTemps(t) {
  const pairs = [
    ['Wi-Fi 芯片', t.wifi_chip_temp], ['射频 PA', t.pm_sensor_pa1], ['Modem', t.pm_sensor_mdm],
    ['5G Modem', t.pm_modem_5g], ['CPU', pick(t, ['cpu_temp', 'cpu_temperature'])],
    ['SoC', t.soc_temp], ['主板', t.board_temp], ['Wi-Fi 温度 1', t.wifi_temp_level_1],
    ['Wi-Fi 温度 2', t.wifi_temp_level_2]
  ].filter(([, v]) => num(v) != null);
  $('bt-temps').innerHTML = pairs.length
    ? pairs.map(([k, v]) => `<div class="stat"><div class="k">${esc(k)}</div><div class="v">${esc(v)}<small> °C</small></div></div>`).join('')
    : '<div class="sub">设备未返回温度字段。</div>';
}
function drawBtChart() {
  const svg = $('bt-chart');
  const note = $('bt-chart-note');
  const data = btHistory.filter((x) => Date.now() - x.timestamp <= BT_WINDOW_MS);
  if (data.length < 2) {
    svg.innerHTML = '';
    note.textContent = data.length === 1 ? '只有 1 个采样点，再等等就有曲线了。' : '暂无采样数据。';
    return;
  }
  const W = 600, H = 120, PAD = 8;
  const t0 = data[0].timestamp, t1 = data.at(-1).timestamp;
  const span = Math.max(1, t1 - t0);
  const pts = data.map((d) => {
    const x = PAD + ((d.timestamp - t0) / span) * (W - PAD * 2);
    const y = H - PAD - (Math.max(0, Math.min(100, d.percent)) / 100) * (H - PAD * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const first = data[0], last = data.at(-1);
  svg.innerHTML = `
    <line x1="${PAD}" y1="${H - PAD}" x2="${W - PAD}" y2="${H - PAD}" stroke="#e5e5e3" stroke-width="1"/>
    <line x1="${PAD}" y1="${PAD}" x2="${W - PAD}" y2="${PAD}" stroke="#e5e5e3" stroke-width="1"/>
    <polyline points="${pts}" fill="none" stroke="#2e9e57" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
    <circle cx="${PAD}" cy="${H - PAD - (first.percent / 100) * (H - PAD * 2)}" r="3" fill="#2e9e57"/>
    <circle cx="${W - PAD}" cy="${H - PAD - (last.percent / 100) * (H - PAD * 2)}" r="3" fill="#2e9e57"/>`;
  note.textContent = `${data.length} 个采样点 · ${new Date(first.timestamp).toLocaleTimeString('zh-CN')} → ${new Date(last.timestamp).toLocaleTimeString('zh-CN')} · 当前 ${Math.round(last.percent)}%`;
}

// ---------- 短信 ----------
function decodeSmsHex(value) {
  if (!value || !/^[0-9a-f]+$/i.test(value)) return value || '';
  let out = '';
  for (let i = 0; i < value.length; i += 4) {
    const code = parseInt(value.slice(i, i + 4), 16);
    if (code && code !== 9) out += String.fromCharCode(code);
  }
  return out;
}
function encodeSmsHex(value) {
  let out = '';
  for (let i = 0; i < value.length; i++) out += value.charCodeAt(i).toString(16).toUpperCase().padStart(4, '0');
  return out;
}
function smsTime() {
  const d = new Date();
  const two = (v) => String(v).padStart(2, '0');
  const zone = -d.getTimezoneOffset() / 60;
  return `${String(d.getFullYear()).slice(-2)};${two(d.getMonth() + 1)};${two(d.getDate())};${two(d.getHours())};${two(d.getMinutes())};${two(d.getSeconds())};${zone >= 0 ? '+' : ''}${zone}`;
}
function findCode(text) {
  const m = String(text || '').match(/(?:验证码|code|Code|CODE)[^\d]{0,10}(\d{4,8})|(\d{4,8})/);
  return m ? (m[1] || m[2]) : null;
}
function copyText(text, btn) {
  const done = () => { if (btn) btn.textContent = '已复制'; setTimeout(() => { if (btn) btn.textContent = '复制'; }, 1500); toast('已复制', true); };
  if (navigator.clipboard?.writeText) { navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done)); }
  else fallbackCopy(text, done);
}
function fallbackCopy(text, done) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); done(); } catch { toast('复制失败，请手动长按复制'); }
  document.body.removeChild(ta);
}
async function loadSms() {
  const listEl = $('sms-list');
  listEl.innerHTML = '<div class="empty"><span class="spin"></span> 正在读取短信…</div>';
  $('sms-empty').hidden = true;
  try {
    await ensureLogin();
    const ready = await getCommand('sms_cmd_status_info', { sms_cmd: 1 });
    if (ready.sms_cmd_status_result !== '3') {
      listEl.innerHTML = '';
      $('sms-empty').hidden = false;
      $('sms-empty').textContent = '短信模块未就绪，请稍后再试。';
      $('sms-capacity').textContent = '短信模块状态：未就绪';
      return;
    }
    const [list, capacity] = await Promise.all([
      getCommand('sms_data_total', { page: 0, data_per_page: 500, mem_store: 1, tags: 10, order_by: 'order by id desc' }),
      getCommand('sms_capacity_info')
    ]);
    const msgs = normList(list.messages).map((m) => ({ ...m, content: decodeSmsHex(m.content) }));
    const cap = capacity || {};
    $('sms-capacity').textContent = `容量：${cap.sms_nv_total ?? cap.total ?? '—'} 条 · 已用 ${cap.sms_nv_used ?? cap.used ?? '—'} 条`;
    if (!msgs.length) {
      listEl.innerHTML = '';
      $('sms-empty').hidden = false;
      $('sms-empty').textContent = '暂无短信。';
      return;
    }
    listEl.innerHTML = msgs.map((m) => {
      const code = findCode(m.content);
      const num_ = esc(m.number || m.num || '—');
      const date = esc(m.date || '');
      const unread = String(m.tag) === '1';
      return `<div class="item" data-sms-id="${esc(m.id ?? '')}">
        <div class="row"><div class="t1">${num_}</div><div class="spacer"></div><span class="muted">${date}</span>${unread ? ' <span class="pill red">未读</span>' : ''}</div>
        <div class="sms-body">${esc(m.content || '')}</div>
        ${code ? `<div><span class="code-chip">验证码 ${esc(code)} <button type="button" data-copy="${esc(code)}">复制</button></span></div>` : ''}
        <div class="row mt8">${unread ? `<button class="btn ghost small" type="button" data-read="${esc(m.id ?? '')}">标为已读</button>` : ''}<button class="btn ghost small" type="button" data-del="${esc(m.id ?? '')}">删除</button></div>
      </div>`;
    }).join('');
    listEl.querySelectorAll('[data-copy]').forEach((b) => b.addEventListener('click', () => copyText(b.dataset.copy, b)));
    listEl.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', () => deleteSms(b.dataset.del, b)));
    listEl.querySelectorAll('[data-read]').forEach((b) => b.addEventListener('click', () => markSmsRead(b.dataset.read, b)));
    // 未读角标：有未读才显示“全部标为已读”
    $('sms-read-all').hidden = !msgs.some((m) => String(m.tag) === '1');
    applySmsFilter();
  } catch (e) {
    listEl.innerHTML = '';
    $('sms-empty').hidden = false;
    $('sms-empty').textContent = `读取短信失败：${e.message}`;
  }
  loadSmsSettings();
}
// 短信收件箱搜索：按号码或内容过滤已渲染的条目。
function applySmsFilter() {
  const q = ($('sms-filter')?.value || '').trim().toLowerCase();
  let shown = 0;
  document.querySelectorAll('#sms-list .item').forEach((el) => {
    const hit = !q || el.textContent.toLowerCase().includes(q);
    el.style.display = hit ? '' : 'none';
    if (hit) shown++;
  });
  const empty = $('sms-empty');
  if (q && shown === 0 && document.querySelectorAll('#sms-list .item').length > 0) {
    empty.hidden = false;
    empty.textContent = '没有匹配的短信，换个关键词试试。';
  } else if (!document.querySelectorAll('#sms-list .item').length) {
    // 列表本身为空时保持 loadSms 写好的文案
  } else {
    empty.hidden = true;
  }
}
// 短信标为已读：SET_MSG_READ，逐条调用（UFI-TOOLS 的做法）。
async function markSmsRead(id, btn) {
  if (!id) return;
  if (btn) { btn.disabled = true; btn.textContent = '处理中…'; }
  try {
    const res = await setGoform('SET_MSG_READ', { msg_id: String(id), notCallback: 'true' });
    assertSuccess(res, '标记已读');
    toast('已标为已读', true);
    loadSms();
  } catch (e) {
    toast(`标记失败：${e.message}`);
    if (btn) { btn.disabled = false; btn.textContent = '标为已读'; }
  }
}
async function markAllSmsRead() {
  const btn = $('sms-read-all');
  const ids = [...document.querySelectorAll('#sms-list [data-read]')].map((b) => b.dataset.read).filter(Boolean);
  if (!ids.length) { toast('没有未读短信'); return; }
  btn.disabled = true;
  try {
    for (const id of ids) {
      const res = await setGoform('SET_MSG_READ', { msg_id: String(id), notCallback: 'true' });
      assertSuccess(res, '标记已读');
    }
    toast(`已标为已读（${ids.length} 条）`, true);
    loadSms();
  } catch (e) {
    toast(`标记失败：${e.message}`);
    loadSms();
  } finally {
    btn.disabled = false;
  }
}
async function deleteSms(id, btn) {
  if (!id) return;
  if (btn.dataset.armed) {
    btn.disabled = true;
    btn.textContent = '删除中…';
    try {
      const res = await setGoform('DELETE_SMS', { msg_id: `${id};` });
      assertSuccess(res, '删除短信');
      for (let i = 0; i < 20; i++) {
        await sleep(500);
        const st = await getCommand('sms_cmd_status_info', { sms_cmd: 6 });
        if (st.sms_cmd_status_result === '3') { toast('短信已删除', true); loadSms(); return; }
        if (st.sms_cmd_status_result === '2') throw new Error('路由器删除短信失败');
      }
      throw new Error('删除状态确认超时，请刷新列表确认');
    } catch (e) { toast(`删除失败：${e.message}`); btn.disabled = false; btn.textContent = '删除'; delete btn.dataset.armed; }
    return;
  }
  btn.dataset.armed = '1';
  btn.textContent = '确认删除？';
  setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = '删除'; } }, 5000);
}
async function sendSms() {
  const to = $('sms-to').value.trim();
  const body = $('sms-body').value;
  if (!/^\+?\d{3,20}$/.test(to)) { toast('手机号格式不正确'); return; }
  if (!body || body.length > 670) { toast('短信内容长度必须为 1 到 670 个字符'); return; }
  const btn = $('sms-send');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> 发送中…';
  try {
    await ensureLogin();
    const res = await setGoform('SEND_SMS', { Number: to, sms_time: smsTime(), MessageBody: encodeSmsHex(body), ID: -1, encode_type: 'UNICODE' });
    if (res.result !== 'success') throw new Error(`路由器拒绝发送：${res.result ?? JSON.stringify(res)}`);
    for (let i = 0; i < 12; i++) {
      await sleep(500);
      const st = await getCommand('sms_cmd_status_info', { sms_cmd: 4 });
      if (st.sms_cmd_status_result === '3') { toast('短信已发送', true); $('sms-body').value = ''; $('sms-count').textContent = '0'; loadSms(); return; }
      if (st.sms_cmd_status_result === '2') throw new Error('路由器发送短信失败');
    }
    toast('发送状态未确认，请刷新列表查看');
  } catch (e) { toast(`发送失败：${e.message}`); }
  finally { btn.disabled = false; btn.textContent = '发送'; }
}

// ---------- 连接设备 ----------
// 自定义名（hostNameList）优先于路由器上报的主机名；黑名单按 MAC 匹配。
function devDisplayName(d) {
  const mac = String(d.mac_addr || d.macAddress || '').toUpperCase();
  const custom = hostNames.find((h) => String(h.mac || '').toUpperCase() === mac);
  return custom?.hostname || d.hostname || d.hostName || d.mac_addr || d.macAddress || '未知设备';
}
function isBlacklisted(mac) {
  return aclState.BlackMacList.some((m) => String(m).toUpperCase() === String(mac || '').toUpperCase());
}
function renderDevices(wifi, lan) {
  const row = (d) => {
    const name = esc(devDisplayName(d));
    const ip = esc(d.ip_addr || d.ipAddress || '—');
    const mac = esc(d.mac_addr || d.macAddress || '—');
    const ssid = d.ssid_index !== undefined ? ` · SSID ${esc(d.ssid_index)}` : '';
    const blocked = isBlacklisted(d.mac_addr || d.macAddress);
    return `<tr><td>${name}${blocked ? ' <span class="pill red">已拉黑</span>' : ''}</td><td>${ip}</td><td>${mac}</td><td>${ssid || '—'}</td><td><button class="btn ghost small" type="button" data-rename="${esc(d.mac_addr || d.macAddress || '')}" data-name="${esc(devDisplayName(d))}">改名</button> <button class="btn ghost small" type="button" data-block="${esc(d.mac_addr || d.macAddress || '')}" data-name="${esc(devDisplayName(d))}">${blocked ? '取消拉黑' : '拉黑'}</button></td></tr>`;
  };
  $('dev-wifi-count').textContent = wifi.length ? `（${wifi.length} 台）` : '';
  $('dev-wifi').innerHTML = wifi.length
    ? `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>设备</th><th>IP</th><th>MAC</th><th>备注</th><th>操作</th></tr></thead><tbody>${wifi.map(row).join('')}</tbody></table></div>`
    : '<div class="empty">暂无无线连接设备。</div>';
  $('dev-lan-count').textContent = lan.length ? `（${lan.length} 台）` : '';
  $('dev-lan').innerHTML = lan.length
    ? `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>设备</th><th>IP</th><th>MAC</th><th>备注</th><th>操作</th></tr></thead><tbody>${lan.map(row).join('')}</tbody></table></div>`
    : '<div class="empty">暂无有线连接设备。</div>';
  document.querySelectorAll('#page-devices [data-rename]').forEach((b) => b.addEventListener('click', () => renameDevice(b.dataset.rename, b.dataset.name, b)));
  document.querySelectorAll('#page-devices [data-block]').forEach((b) => b.addEventListener('click', () => toggleBlacklist(b.dataset.block, b.dataset.name, b)));
  renderBlacklist();
  applyDevFilter();
}
function renderBlacklist() {
  const list = aclState.BlackMacList.filter(Boolean);
  $('dev-black-count').textContent = list.length ? `（${list.length} 个）` : '';
  $('dev-black-mode').textContent = `黑名单模式 AclMode：${aclState.AclMode === '' ? '（设备未返回）' : aclState.AclMode}。提交时按设备返回的原值带回，只改名单本身；如果拉黑后设备仍能上网，说明这台固件没有启用黑名单模式。`;
  $('dev-black').innerHTML = list.length
    ? `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>设备</th><th>MAC</th><th>操作</th></tr></thead><tbody>${list.map((mac, i) => `<tr><td>${esc(aclState.BlackNameList[i] || '—')}</td><td>${esc(mac)}</td><td><button class="btn ghost small" type="button" data-unblock="${esc(mac)}">取消拉黑</button></td></tr>`).join('')}</tbody></table></div>`
    : '<div class="empty">黑名单是空的。</div>';
  document.querySelectorAll('#page-security [data-unblock]').forEach((b) => b.addEventListener('click', () => toggleBlacklist(b.dataset.unblock, '', b)));
}
// 打开连接设备页时拉一次黑名单 + 自定义名（不在 2 秒轮询里，避免多余请求）。
async function loadAcl() {
  try {
    await ensureLogin();
    const [acl, names] = await Promise.all([
      getCommand('queryDeviceAccessControlList').catch(() => ({})),
      getCommand('hostNameList').catch(() => ({}))
    ]);
    aclState = {
      AclMode: acl.AclMode ?? '',
      BlackMacList: acl.BlackMacList ? String(acl.BlackMacList).split(';').filter(Boolean) : [],
      BlackNameList: acl.BlackNameList ? String(acl.BlackNameList).split(';') : []
    };
    const rawNames = normList(names.hostNameList || names.devices || names);
    hostNames = rawNames.map((h) => ({ mac: h.mac || h.mac_addr || '', hostname: h.hostname || h.hostName || h.name || '' })).filter((h) => h.mac);
    if (lastDash) renderDevices(lastDash.stations, lastDash.cableStations);
    else renderBlacklist();
  } catch (e) {
    // 读不到黑名单不影响看设备列表
  }
}
async function renameDevice(mac, oldName, btn) {
  if (!mac) return;
  // 行内改名：把按钮换成输入框 + 保存/取消（不用 prompt 弹窗）
  const cell = btn.parentElement;
  cell.innerHTML = `<input class="input small" type="text" value="${esc(oldName)}" maxlength="32" style="width:130px"> <button class="btn small" type="button" data-save-rename>保存</button> <button class="btn ghost small" type="button" data-cancel-rename>取消</button>`;
  const input = cell.querySelector('input');
  input.focus();
  input.select();
  cell.querySelector('[data-cancel-rename]').addEventListener('click', () => { if (lastDash) renderDevices(lastDash.stations, lastDash.cableStations); });
  cell.querySelector('[data-save-rename]').addEventListener('click', async () => {
    const next = input.value.trim();
    if (!next) { toast('名字不能为空'); return; }
    try {
      const res = await setGoform('EDIT_HOSTNAME', { mac, hostname: next });
      assertSuccess(res, '改名');
      hostNames = hostNames.filter((h) => String(h.mac).toUpperCase() !== String(mac).toUpperCase());
      hostNames.push({ mac, hostname: next });
      toast('已改名', true);
      if (lastDash) renderDevices(lastDash.stations, lastDash.cableStations);
    } catch (e) { toast(`改名失败：${e.message}`); }
  });
}
async function toggleBlacklist(mac, name, btn) {
  if (!mac) return;
  const blocked = isBlacklisted(mac);
  const nextMacs = blocked
    ? aclState.BlackMacList.filter((m) => String(m).toUpperCase() !== String(mac).toUpperCase())
    : [...aclState.BlackMacList, mac];
  const nextNames = blocked
    ? aclState.BlackMacList.map((m, i) => ({ m, n: aclState.BlackNameList[i] || '' })).filter((x) => String(x.m).toUpperCase() !== String(mac).toUpperCase()).map((x) => x.n)
    : [...aclState.BlackNameList.slice(0, aclState.BlackMacList.length), name || ''];
  btn.disabled = true;
  try {
    const res = await setGoform('setDeviceAccessControlList', {
      AclMode: String(aclState.AclMode ?? ''),
      WhiteMacList: '',
      BlackMacList: nextMacs.join(';'),
      WhiteNameList: '',
      BlackNameList: nextNames.join(';')
    });
    assertSuccess(res, blocked ? '取消拉黑' : '拉黑');
    aclState.BlackMacList = nextMacs;
    aclState.BlackNameList = nextNames;
    toast(blocked ? '已取消拉黑' : '已拉黑', true);
    if (lastDash) renderDevices(lastDash.stations, lastDash.cableStations);
  } catch (e) {
    toast(`${blocked ? '取消拉黑' : '拉黑'}失败：${e.message}`);
    btn.disabled = false;
  }
}
// 连接设备搜索：按设备名、IP 或 MAC 过滤两张表的行。
function applyDevFilter() {
  const q = ($('dev-filter')?.value || '').trim().toLowerCase();
  document.querySelectorAll('#page-devices table.tbl tbody tr').forEach((tr) => {
    tr.style.display = !q || tr.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

// ---------- QCI 现场验证 ----------
// 参考文档已探测过 qci/QCI/qos/qos_info/5qi/5QI，均未返回。这里在用户打开 QCI 页时
// 再实地查一次：只要有一个返回非空值就如实显示；都没有就保持“设备未返回 QCI”。
async function probeQci() {
  if (qciProbed) return;
  qciProbed = true;
  const note = $('qci-result');
  try {
    const res = await getFields(['qci', 'QCI', 'qos', 'qos_info', '5qi', '5QI']);
    const found = Object.entries(res || {}).filter(([, v]) => v !== undefined && v !== null && String(v).trim() !== '');
    if (found.length) {
      note.innerHTML = `<b>路由器返回了 QoS 相关字段：</b><br>${found.map(([k, v]) => `<code>${esc(k)}</code> = ${esc(String(v))}`).join('<br>')}<br>注意：这些是接口原样返回的值，不一定就是签约 QCI；QCI 由核心网按承载下发，HTTP 接口通常不直接给。`;
      toast('QCI 字段已查到返回值', true);
    }
  } catch (e) {
    // 查失败不改文案，保持“设备未返回 QCI”的说明。
  }
}

// ---------- 网络页 ----------
// 接口依据：
//   网络模式 SET_BEARER_PREFERENCE{ BearerPreference }，当前值读 net_select；
//   漫游 SET_CONNECTION_MODE{ ConnectionMode:'auto_dial', roam_setting_option, dial_roam_setting_option }；
//   数据开关 CONNECT_NETWORK / DISCONNECT_NETWORK；
//   APN APN_PROC_EX（UFI-TOOLS 前端实际用法：apn_mode auto/manual，apn_action
//     save/delete/set_default；配置串 APN_configN 以 '($)' 分隔，[0]名 [1]APN
//     [4]鉴权 [5]用户名 [6]密码 [7]PDP）；
//   锁频段 U50PRO-CON：LTE 用 BAND_SELECT，5G 用 WAN_PERFORM_NR5G_SANSA_BAND_LOCK
//    （type 1=NSA/0=SA），旧固件回退 WAN_PERFORM_NR5G_BAND_LOCK；
//   锁小区 U50PRO-CON：NR5G_LOCK_CELL_SET / LTE_LOCK_CELL_SET，邻区格式见
//     buildCellCandidates（NR：pci,arfcn,rsrp,rsrq,band；LTE：arfcn,pci,rsrq,rsrp,band）。
const LTE_BANDS = [1, 3, 5, 7, 8, 20, 28, 34, 38, 39, 40, 41];
const NR_BANDS = [1, 3, 5, 8, 28, 41, 77, 78];
const LTE_BAND_MASKS = { 1: '0x000000001', 3: '0x000000004', 5: '0x000000010', 7: '0x000000040', 8: '0x000000080', 20: '0x000080000', 28: '0x008000000', 34: '0x200000000', 38: '0x2000000000', 39: '0x4000000000', 40: '0x8000000000', 41: '0x10000000000' };
const bandSel = { lte: new Set(), nsa: new Set(), sa: new Set() };
const APN_READ_FIELDS = ['apn_interface_version', ...Array.from({ length: 20 }, (_, i) => `APN_config${i}`), ...Array.from({ length: 20 }, (_, i) => `ipv6_APN_config${i}`), 'apn_m_profile_name', 'profile_name', 'apn_wan_dial', 'apn_select', 'apn_pdp_type', 'apn_pdp_select', 'apn_pdp_addr', 'index', 'apn_Current_index', 'apn_auto_config', 'apn_ipv6_apn_auto_config', 'apn_mode', 'apn_wan_apn', 'apn_ppp_auth_mode', 'apn_ppp_username', 'apn_ppp_passwd', 'dns_mode', 'prefer_dns_manual', 'standby_dns_manual', 'apn_ipv6_wan_apn', 'apn_ipv6_pdp_type', 'apn_ipv6_ppp_auth_mode', 'apn_ipv6_ppp_username', 'apn_ipv6_ppp_passwd', 'ipv6_dns_mode', 'ipv6_prefer_dns_manual', 'ipv6_standby_dns_manual', 'apn_num_preset'];
const BEARER_LABELS = { WL_AND_5G: '5G / 4G / 3G（自动）', LTE_AND_5G: '5G NSA', Only_5G: '5G SA（仅 5G 独立组网）', Only_LTE: '仅 4G' };

async function loadNetwork() {
  try {
    await ensureLogin();
    const [mode, apn, neighbors] = await Promise.all([
      getFields(['net_select', 'roam_setting_option', 'dial_roam_setting_option', 'ppp_status', 'wan_connect_status', 'opms_wan_mode', 'network_type', 'pin_status', 'pinnumber', 'puknumber', 'modem_main_state', 'new_version_state', 'current_upgrade_state', 'upgrade_result', 'lte_band_lock', 'nr5g_band_lock', 'nr5g_sa_band_lock', 'nr5g_nsa_band_lock', 'nr5g_cell_lock', 'lte_pci_lock', 'lte_earfcn_lock', 'operate_mode']).catch(() => ({})),
      getFields(APN_READ_FIELDS).catch(() => null),
      getFields(['network_type', 'lte_ngbr_cell_info_ext', 'sa_ngbr_cell_manual_result_ext']).catch(() => ({}))
    ]);
    netState = { bearer: mode.net_select || '', ppp: mode.ppp_status || '', roam: mode.roam_setting_option || '' };
    // 网络模式 / 数据 / 漫游
    $('net-mode-cur').textContent = `${BEARER_LABELS[mode.net_select] || mode.net_select || '—'}（${mode.network_type || '—'} · ${mode.opms_wan_mode || ''}）`;
    if (mode.net_select && $('net-mode').value !== mode.net_select) $('net-mode').value = mode.net_select;
    const connected = /connect/i.test(String(mode.ppp_status || mode.wan_connect_status || ''));
    $('net-data-state').textContent = connected ? '已连接' : (mode.ppp_status || mode.wan_connect_status || '—');
    $('net-data-toggle').textContent = connected ? '断开蜂窝数据' : '连接蜂窝数据';
    const roamOn = mode.roam_setting_option === 'on';
    $('net-roam-state').textContent = roamOn ? '已开启' : '已关闭';
    $('net-roam-toggle').textContent = roamOn ? '关闭数据漫游' : '开启数据漫游';
    // SIM / 固件更新（只读）
    const pinMap = { 0: '未设置 PIN', 1: 'PIN 已启用', 2: 'PIN 已锁定（需 PUK）', 3: 'PIN 错误', 4: '无 SIM 卡' };
    $('sim-pin').textContent = pinMap[mode.pin_status] || (mode.pin_status ?? '—');
    $('sim-pin-left').textContent = mode.pinnumber ?? '—';
    $('sim-puk-left').textContent = mode.puknumber ?? '—';
    const modemMap = { modem_waitpin: '等待输入 PIN', modem_waitpuk: '等待输入 PUK', modem_init_complete: '正常' };
    $('sim-modem').textContent = modemMap[mode.modem_main_state] || mode.modem_main_state || '—';
    $('fw-new').textContent = mode.new_version_state || '—';
    $('fw-cur').textContent = mode.current_upgrade_state || '—';
    $('fw-result').textContent = mode.upgrade_result || '—';
    $('about-fw').textContent = `固件更新状态：新版本 ${mode.new_version_state || '—'} · 当前 ${mode.current_upgrade_state || '—'}。`;
    // 频段锁定当前值
    const lteLock = mode.lte_band_lock ? `LTE 掩码 ${mode.lte_band_lock}` : '';
    const nrLock = [mode.nr5g_sa_band_lock ? `SA ${mode.nr5g_sa_band_lock}` : '', mode.nr5g_nsa_band_lock ? `NSA ${mode.nr5g_nsa_band_lock}` : '', mode.nr5g_band_lock ? `5G ${mode.nr5g_band_lock}` : ''].filter(Boolean).join(' · ');
    $('band-cur').textContent = [lteLock, nrLock].filter(Boolean).join('；') || '无锁定';
    syncBandChipsFromLocks(mode);
    // 小区锁定当前值
    const cellLock = [mode.nr5g_cell_lock ? `5G ${mode.nr5g_cell_lock}` : '', (mode.lte_pci_lock || mode.lte_earfcn_lock) ? `LTE PCI ${mode.lte_pci_lock || '—'} / EARFCN ${mode.lte_earfcn_lock || '—'}` : ''].filter(Boolean).join('；');
    $('cell-cur').textContent = cellLock || '无锁定';
    // APN
    if (apn) renderApn(apn);
    else { $('apn-summary').textContent = 'APN 信息读取失败，请点“刷新”重试。'; }
    // 邻区
    const signal = lastDash?.signal || (await getFields(signalFields).catch(() => ({})));
    renderCellCandidates(signal, neighbors);
    // USSD 默认运营商：用当前网络信号里的运营商名（USSD_operator 取值未在文件里出现）。
    if (!$('ussd-op').value) $('ussd-op').value = signal.network_provider || signal.Operator || '';
  } catch (e) {
    toast(`网络页加载失败：${e.message}`);
  }
}
function syncBandChipsFromLocks(mode) {
  // LTE：掩码反推已选频段
  bandSel.lte = new Set();
  try {
    const mask = mode.lte_band_lock ? BigInt(mode.lte_band_lock) : 0n;
    for (const b of LTE_BANDS) if ((mask & BigInt(LTE_BAND_MASKS[b])) !== 0n) bandSel.lte.add(b);
  } catch {}
  const parseNr = (v) => String(v ?? '').split(/[;,]/).map((x) => Number(String(x).trim().replace(/^n/i, ''))).filter((x) => Number.isInteger(x) && x >= 1 && x <= 261);
  bandSel.nsa = new Set(parseNr(mode.nr5g_nsa_band_lock));
  bandSel.sa = new Set(parseNr(mode.nr5g_sa_band_lock));
  renderBandChips();
}
function renderBandChips() {
  const mk = (el, list, sel, key) => {
    $(el).innerHTML = list.map((b) => `<button type="button" class="chip${sel.has(b) ? ' on' : ''}" data-band="${b}" data-group="${key}">${key === 'lte' ? 'B' : 'n'}${b}</button>`).join('');
  };
  mk('band-lte', LTE_BANDS, bandSel.lte, 'lte');
  mk('band-nsa', NR_BANDS, bandSel.nsa, 'nsa');
  mk('band-sa', NR_BANDS, bandSel.sa, 'sa');
  document.querySelectorAll('#page-network .chip').forEach((c) => c.addEventListener('click', () => {
    const g = c.dataset.group, b = Number(c.dataset.band);
    if (bandSel[g].has(b)) bandSel[g].delete(b); else bandSel[g].add(b);
    c.classList.toggle('on');
  }));
}
function parseNrExtra() {
  return String($('band-nr-extra').value || '').split(/[，,、;\s]+/).map((x) => Number(String(x).trim().replace(/^n/i, ''))).filter((x) => Number.isInteger(x) && x >= 1 && x <= 261);
}
async function saveLteBands() {
  const btn = $('band-lte-save');
  btn.disabled = true;
  try {
    await ensureDeveloperAccess();
    let mask = 0n;
    bandSel.lte.forEach((b) => { mask |= BigInt(LTE_BAND_MASKS[b]); });
    const res = await setGoform('BAND_SELECT', { is_gw_band: 0, gw_band_mask: 0, is_lte_band: 1, lte_band_mask: `0x${mask.toString(16).padStart(16, '0')}` });
    assertSuccess(res, 'LTE 锁频段');
    await verifyLteBandMask(mask);
    toast('LTE 频段已保存', true);
    loadNetwork();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function verifyLteBandMask(expected) {
  let actual = '';
  for (let i = 0; i < 3; i++) {
    const st = await getFields(['lte_band_lock']);
    actual = String(st.lte_band_lock ?? '').trim();
    try { if ((actual === '' ? 0n : BigInt(actual)) === expected) return; } catch {}
    await sleep(350);
  }
  throw new Error(`路由器未确认 LTE 频段已保存（返回：${actual || '空'}）`);
}
async function saveNrBands(type) {
  const btn = $(type === 'nsa' ? 'band-nsa-save' : 'band-sa-save');
  btn.disabled = true;
  try {
    await ensureDeveloperAccess();
    const extra = parseNrExtra();
    const values = [...new Set([...bandSel[type], ...extra])].sort((a, b) => a - b);
    const mask = values.length ? values.join(',') : '0';
    let lastErr = null;
    for (const ep of [
      { id: 'WAN_PERFORM_NR5G_SANSA_BAND_LOCK', payload: { nr5g_band_mask: mask, type: type === 'nsa' ? '1' : '0' } },
      { id: 'WAN_PERFORM_NR5G_BAND_LOCK', payload: { nr5g_band_mask: mask } }
    ]) {
      try {
        const res = await setGoform(ep.id, ep.payload);
        assertSuccess(res, `5G ${type.toUpperCase()} 锁频段`);
        await verifyNrBandList(type, values);
        toast(`5G ${type.toUpperCase()} 频段已保存`, true);
        loadNetwork();
        return;
      } catch (e) { lastErr = e; }
    }
    throw lastErr || new Error('保存失败');
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function verifyNrBandList(type, expected) {
  const field = type === 'nsa' ? 'nr5g_nsa_band_lock' : 'nr5g_sa_band_lock';
  const exp = [...expected].sort((a, b) => a - b);
  let actual = '';
  for (let i = 0; i < 3; i++) {
    const st = await getFields([field, 'nr5g_band_lock']);
    const raw = st[field] !== undefined ? st[field] : st.nr5g_band_lock;
    actual = String(raw ?? '').trim();
    const got = String(raw ?? '').split(/[;,]/).map((x) => Number(String(x).trim().replace(/^n/i, ''))).filter(Number.isFinite).sort((a, b) => a - b);
    if (got.length === exp.length && got.every((v, j) => v === exp[j])) return;
    await sleep(500);
  }
  throw new Error(`路由器未确认 5G ${type.toUpperCase()} 频段已保存（返回：${actual || '空'}）`);
}
async function clearBands(kind) {
  if (kind === 'lte') { bandSel.lte = new Set(); renderBandChips(); await saveLteBands(); return; }
  bandSel[kind] = new Set();
  if (kind === 'nsa' || kind === 'sa') { renderBandChips(); await saveNrBands(kind); }
}
// ---- 邻区候选（U50PRO-CON src/utils/cells.js 的逻辑） ----
function inferScs(band) { return [41, 77, 78, 79].includes(Number(band)) ? 30 : 15; }
function nrPciDecimal(raw) {
  const text = String(raw || '').trim();
  if (!text) return null;
  const parsed = Number.parseInt(text, /[a-f]/i.test(text) ? 16 : 10);
  return Number.isInteger(parsed) ? parsed : null;
}
function normBand(raw) {
  const m = String(raw || '').match(/\d+/);
  return m ? Number(m[0]) : null;
}
function buildCellCandidates(signal, neighbors) {
  const network = String(signal.network_type || neighbors.network_type || '').toUpperCase();
  const rows = [];
  if (network.includes('SA') || network.includes('NR5G') || signal.nr5g_action_channel) {
    const band = normBand(signal.nr5g_action_band);
    rows.push({ rat: 'NR', pci: nrPciDecimal(signal.nr5g_pci), arfcn: num(signal.nr5g_action_channel || signal.Z5g_dlEarfcn), band, scs: inferScs(band), rsrp: num(signal.Z5g_rsrp), rsrq: num(signal.Z5g_rsrq), serving: true });
    String(neighbors.sa_ngbr_cell_manual_result_ext || '').split(';').filter(Boolean).forEach((item) => {
      const v = item.split(',');
      const b = normBand(v[4]);
      rows.push({ rat: 'NR', pci: num(v[0]), arfcn: num(v[1]), rsrp: num(v[2]), rsrq: num(v[3]), band: b, scs: inferScs(b), serving: false });
    });
  } else {
    const band = normBand(signal.lte_ca_pcell_band || signal.wan_active_band);
    rows.push({ rat: 'LTE', pci: num(signal.lte_pci), arfcn: num(signal.lte_ca_pcell_arfcn || signal.wan_active_channel), band, rsrp: num(signal.lte_rsrp), rsrq: num(signal.lte_rsrq), serving: true });
    String(neighbors.lte_ngbr_cell_info_ext || '').split(';').filter(Boolean).forEach((item) => {
      const v = item.split(',');
      rows.push({ rat: 'LTE', arfcn: num(v[0]), pci: num(v[1]), rsrq: num(v[2]), rsrp: num(v[3]), band: normBand(v[4]), serving: false });
    });
  }
  const dedup = new Map();
  rows.filter((x) => x.pci != null && x.arfcn != null && x.band != null).forEach((x) => {
    const key = `${x.rat}-${x.pci}-${x.arfcn}-${x.band}`;
    const prev = dedup.get(key);
    if (!prev || (x.rsrp ?? -999) > (prev.rsrp ?? -999)) dedup.set(key, { ...prev, ...x, serving: x.serving || prev?.serving, key });
  });
  return [...dedup.values()].sort((a, b) => (b.rsrp ?? -999) - (a.rsrp ?? -999));
}
function renderCellCandidates(signal, neighbors) {
  cellCandidates = buildCellCandidates(signal || {}, neighbors || {});
  applyCellFilter();
  if (cellCandidates.length) selectCellCandidate(cellCandidates[0].key, false);
}
function applyCellFilter() {
  const q = ($('cell-filter')?.value || '').trim().toLowerCase();
  const list = cellCandidates.filter((c) => !q || `${c.rat} ${c.band} ${c.pci} ${c.arfcn} ${c.rsrp ?? ''} ${c.rsrq ?? ''}`.toLowerCase().includes(q));
  $('cell-empty').hidden = list.length > 0;
  $('cell-list').innerHTML = list.map((c, i) => `<div class="item cand${cellCandidates[0]?.key === c.key ? ' sel' : ''}" data-cell-key="${esc(c.key)}">
    <div class="row"><div class="t1">${c.serving ? '当前服务小区' : `${c.rat} 候选小区`}</div><div class="spacer"></div><span class="muted">#${i + 1}</span></div>
    <div class="t2">${c.rat === 'NR' ? 'n' : 'B'}${esc(c.band)} · PCI ${esc(c.pci)} · ARFCN ${esc(c.arfcn)}${c.rat === 'NR' ? ` · SCS ${esc(c.scs)}` : ''}</div>
    <div class="t2">RSRP ${c.rsrp ?? '—'} dBm · RSRQ ${c.rsrq ?? '—'} dB</div>
  </div>`).join('');
  document.querySelectorAll('#cell-list .cand').forEach((el) => el.addEventListener('click', () => selectCellCandidate(el.dataset.cellKey, true)));
}
function selectCellCandidate(key, scroll) {
  const c = cellCandidates.find((x) => x.key === key) || cellCandidates[0];
  if (!c) return;
  document.querySelectorAll('#cell-list .cand').forEach((el) => el.classList.toggle('sel', el.dataset.cellKey === c.key));
  $('cell-rat').value = c.rat;
  $('cell-pci').value = c.pci ?? '';
  $('cell-arfcn').value = c.arfcn ?? '';
  $('cell-band').value = c.band ?? '';
  $('cell-scs').value = c.scs ?? inferScs(c.band);
  $('cell-scs-wrap').style.display = c.rat === 'NR' ? '' : 'none';
  if (scroll) $('cell-lock').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
async function lockSelectedCell() {
  const rat = $('cell-rat').value;
  const pci = Number($('cell-pci').value), arfcn = Number($('cell-arfcn').value), band = Number($('cell-band').value);
  const scs = Number($('cell-scs').value);
  if (rat === 'NR') {
    if (!Number.isInteger(pci) || pci < 0 || pci > 1007) { toast('5G PCI 必须在 0–1007 之间'); return; }
    if (!Number.isInteger(arfcn) || arfcn < 0 || arfcn > 800000) { toast('5G NR-ARFCN 必须在 0–800000 之间'); return; }
    if (!Number.isInteger(band) || band < 1 || band > 261) { toast('5G Band 必须在 1–261 之间'); return; }
    if (!Number.isInteger(scs) || scs < 15 || scs > 120) { toast('SCS 必须在 15–120 之间'); return; }
  } else {
    if (!Number.isInteger(pci) || pci < 0 || pci > 503) { toast('LTE PCI 必须在 0–503 之间'); return; }
    if (!Number.isInteger(arfcn) || arfcn < 0 || arfcn > 68935) { toast('LTE EARFCN 必须在 0–68935 之间'); return; }
  }
  const btn = $('cell-lock');
  btn.disabled = true;
  try {
    await ensureDeveloperAccess();
    const res = rat === 'NR'
      ? await setGoform('NR5G_LOCK_CELL_SET', { nr5g_cell_lock: `${pci},${arfcn},${band},${scs}` })
      : await setGoform('LTE_LOCK_CELL_SET', { lte_pci_lock: pci, lte_earfcn_lock: arfcn });
    assertSuccess(res, rat === 'NR' ? '5G 锁小区' : 'LTE 锁小区');
    toast('小区已锁定', true);
    loadNetwork();
  } catch (e) { toast(`锁定失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function unlockAllCells() {
  const btn = $('cell-unlock');
  btn.disabled = true;
  try {
    await ensureDeveloperAccess();
    const errors = [];
    for (const task of [
      () => setGoform('NR5G_LOCK_CELL_SET', { nr5g_cell_lock: '1,1,1,1' }),
      () => setGoform('LTE_LOCK_CELL_SET', { lte_pci_lock: '', lte_earfcn_lock: '' })
    ]) {
      try { await task(); } catch (e) { errors.push(e.message); }
    }
    if (errors.length === 2) throw new Error(errors[0]);
    toast('小区锁定已解除', true);
    loadNetwork();
  } catch (e) { toast(`解除失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function scanNeighbors() {
  const btn = $('cell-scan');
  btn.disabled = true;
  btn.textContent = '扫描中…';
  try {
    await ensureLogin();
    await setGoform('SCAN_NR5G_NEIGHBOR_CELL');
    toast('已触发邻区扫描，3 秒后刷新结果', true);
    setTimeout(loadNetwork, 3000);
  } catch (e) { toast(`扫描失败：${e.message}`); }
  finally { btn.disabled = false; btn.textContent = '重新扫描邻区'; }
}
// ---- APN ----
function parseApnProfiles(apn) {
  const list = [];
  for (let i = 0; i < 20; i++) {
    const raw = apn[`APN_config${i}`];
    if (!raw) continue;
    const c = String(raw).split('($)');
    if (!c.length || !c[0]) continue;
    list.push({ index: i, profile_name: c[0] || '', apn: c[1] || '', auth: c[4] || '', user: c[5] || '', pass: c[6] || '', pdp: c[7] || '' });
  }
  return list;
}
function renderApn(apn) {
  const profiles = parseApnProfiles(apn);
  const currentName = apn.apn_m_profile_name || apn.m_profile_name || apn.profile_name || '';
  const mode = String(apn.apn_mode || '').toLowerCase() === 'auto' ? 'auto' : 'manual';
  const curIdx = profiles.findIndex((p) => p.profile_name === currentName);
  apnState = { mode, profiles, currentName, currentIndex: curIdx >= 0 ? curIdx : (Number(apn.apn_Current_index) || 0) };
  $('apn-summary').textContent = `模式：${mode === 'auto' ? '自动' : '手动'} · 当前配置：${currentName || '—'} · 已保存 ${profiles.length} 个配置`;
  $('apn-mode').value = mode;
  const sel = $('apn-profile');
  sel.innerHTML = profiles.length
    ? profiles.map((p, i) => `<option value="${i}"${i === apnState.currentIndex ? ' selected' : ''}>${esc(p.profile_name)}（${esc(p.apn)}）</option>`).join('')
    : '<option value="">（无已保存配置）</option>';
  const cur = profiles[apnState.currentIndex];
  $('apn-note').textContent = cur
    ? `当前 APN：${cur.profile_name} · APN ${cur.apn || '—'} · 鉴权 ${cur.auth || '—'} · PDP ${cur.pdp || '—'}`
    : '当前 APN：—';
}
function apnFormData(index) {
  const name = $('apn-f-name').value.trim();
  const apn = $('apn-f-apn').value.trim();
  if (!name || !apn) return null;
  const auth = $('apn-f-auth').value || 'none';
  const user = $('apn-f-user').value.trim();
  const pass = $('apn-f-pass').value;
  const pdp = $('apn-f-pdp').value || 'IPv4v6';
  return {
    profile_name: name, wan_dial: '*99#', apn_wan_dial: '*99#', apn_select: 'manual',
    apn_pdp_type: pdp, pdp_type: pdp, apn_pdp_select: 'auto', apn_pdp_addr: '', pdp_select: 'auto', pdp_addr: '',
    index,
    apn_wan_apn: apn, apn_ppp_auth_mode: auth, apn_ppp_username: user, apn_ppp_passwd: pass,
    wan_apn: apn, ppp_auth_mode: auth, ppp_username: user, ppp_passwd: pass,
    dns_mode: 'auto', prefer_dns_manual: '', standby_dns_manual: '',
    apn_ipv6_wan_apn: apn, apn_ipv6_ppp_auth_mode: auth, apn_ipv6_ppp_username: user, apn_ipv6_ppp_passwd: pass,
    ipv6_dns_mode: 'auto', ipv6_prefer_dns_manual: '', ipv6_standby_dns_manual: ''
  };
}
async function applyApnMode() {
  const mode = $('apn-mode').value;
  const idx = Number($('apn-profile').value);
  const btn = $('apn-apply');
  btn.disabled = true;
  try {
    await ensureLogin();
    let res;
    if (mode === 'auto') {
      res = await setGoform('APN_PROC_EX', { apn_mode: 'auto' });
    } else {
      if (!Number.isInteger(idx) || idx < 0) { toast('请先选一个手动配置'); return; }
      res = await setGoform('APN_PROC_EX', { apn_mode: 'manual', apn_action: 'set_default', set_default_flag: '1', apn_pdp_type: '', index: idx });
    }
    assertSuccess(res, '切换 APN');
    toast('APN 已应用', true);
    loadNetwork();
  } catch (e) { toast(`应用失败：${e.message}`); }
  finally { btn.disabled = false; }
}
function openApnForm(kind) {
  const form = $('apn-form');
  form.hidden = false;
  form.dataset.kind = kind;
  if (kind === 'edit') {
    const p = apnState.profiles[Number($('apn-profile').value)];
    if (!p) { toast('请先选一个配置'); form.hidden = true; return; }
    form.dataset.index = String(p.index);
    $('apn-f-name').value = p.profile_name;
    $('apn-f-apn').value = p.apn;
    $('apn-f-auth').value = (p.auth || 'none').toLowerCase();
    $('apn-f-user').value = p.user;
    $('apn-f-pass').value = p.pass;
    $('apn-f-pdp').value = p.pdp || 'IPv4v6';
  } else {
    form.dataset.index = String(apnState.profiles.length);
    $('apn-f-name').value = '';
    $('apn-f-apn').value = '';
    $('apn-f-auth').value = 'none';
    $('apn-f-user').value = '';
    $('apn-f-pass').value = '';
    $('apn-f-pdp').value = 'IPv4v6';
  }
  $('apn-f-name').focus();
}
async function saveApnForm() {
  const kind = $('apn-form').dataset.kind || 'add';
  const index = Number($('apn-form').dataset.index || 0);
  const data = apnFormData(index);
  if (!data) { toast('配置名称和 APN 都是必填的'); return; }
  const btn = $('apn-form-save');
  btn.disabled = true;
  try {
    const res = await setGoform('APN_PROC_EX', { apn_mode: 'manual', apn_action: 'save', ...data });
    assertSuccess(res, '保存 APN');
    $('apn-form').hidden = true;
    toast(kind === 'add' ? 'APN 配置已新增' : 'APN 配置已保存', true);
    loadNetwork();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function deleteApn(btn) {
  const idx = Number($('apn-profile').value);
  if (!Number.isInteger(idx) || idx < 0) { toast('请先选一个配置'); return; }
  const p = apnState.profiles[idx];
  if (btn.dataset.armed) {
    delete btn.dataset.armed;
    btn.textContent = '删除选中';
    btn.disabled = true;
    try {
      const res = await setGoform('APN_PROC_EX', { index: idx, apn_mode: 'manual', apn_action: 'delete' });
      assertSuccess(res, '删除 APN');
      toast(`已删除 ${p?.profile_name || ''}`, true);
      loadNetwork();
    } catch (e) { toast(`删除失败：${e.message}`); }
    finally { btn.disabled = false; }
    return;
  }
  btn.dataset.armed = '1';
  btn.textContent = `确认删除 ${p?.profile_name || ''}？`;
  setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = '删除选中'; } }, 5000);
}
// ---- 网络模式 / 数据 / 漫游 ----
async function saveNetMode() {
  const v = $('net-mode').value;
  const btn = $('net-mode-save');
  btn.disabled = true;
  try {
    const res = await setGoform('SET_BEARER_PREFERENCE', { BearerPreference: v });
    assertSuccess(res, '切换网络模式');
    toast('网络模式已切换，正在重新注册网络', true);
    setTimeout(loadNetwork, 3000);
  } catch (e) { toast(`切换失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function toggleCellularData() {
  const connected = /connect/i.test(String(netState.ppp || ''));
  const btn = $('net-data-toggle');
  btn.disabled = true;
  try {
    const res = await setGoform(connected ? 'DISCONNECT_NETWORK' : 'CONNECT_NETWORK', {});
    assertSuccess(res, connected ? '断开蜂窝数据' : '连接蜂窝数据');
    toast(connected ? '蜂窝数据已断开' : '正在连接蜂窝数据', true);
    setTimeout(loadNetwork, 2000);
  } catch (e) { toast(`操作失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function toggleRoam() {
  const on = netState.roam === 'on';
  const next = on ? 'off' : 'on';
  const btn = $('net-roam-toggle');
  btn.disabled = true;
  try {
    const res = await setGoform('SET_CONNECTION_MODE', { ConnectionMode: 'auto_dial', roam_setting_option: next, dial_roam_setting_option: next });
    assertSuccess(res, next === 'on' ? '开启漫游' : '关闭漫游');
    toast(next === 'on' ? '数据漫游已开启' : '数据漫游已关闭', true);
    loadNetwork();
  } catch (e) { toast(`操作失败：${e.message}`); }
  finally { btn.disabled = false; }
}

// ---------- PIN / PUK（v1.5.0，实机 service.js：ENTER_PIN / ENTER_PUK / ENABLE_PIN / DISABLE_PIN） ----------
// 风险：原厂固件对 PIN 尝试次数的判定有 bug，输错可能锁卡；页面上已写明，
// 剩余次数如实显示（pinnumber / puknumber），PIN/PUK 只进内存，不保存。
function pinDigits(v) { return /^\d{4,8}$/.test(String(v || '').trim()); }
async function enterPin() {
  const pin = $('pin-enter').value.trim();
  if (!pinDigits(pin)) { toast('PIN 是 4–8 位数字'); return; }
  const btn = $('pin-enter-btn');
  btn.disabled = true;
  try {
    const res = await setGoform('ENTER_PIN', { PinNumber: pin });
    assertSuccess(res, '输入 PIN');
    $('pin-enter').value = '';
    toast('PIN 已提交', true);
    loadNetwork();
  } catch (e) { toast(`提交失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function changePin() {
  const oldPin = $('pin-old').value.trim();
  const newPin = $('pin-new').value.trim();
  if (!pinDigits(oldPin) || !pinDigits(newPin)) { toast('当前 PIN 和新 PIN 都要是 4–8 位数字'); return; }
  if (oldPin === newPin) { toast('新 PIN 和当前 PIN 一样'); return; }
  const btn = $('pin-change-btn');
  btn.disabled = true;
  try {
    const res = await setGoform('ENABLE_PIN', { OldPinNumber: oldPin, NewPinNumber: newPin });
    assertSuccess(res, '修改 PIN');
    $('pin-old').value = ''; $('pin-new').value = '';
    toast('PIN 已修改', true);
    loadNetwork();
  } catch (e) { toast(`修改失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function disablePin(btn) {
  const oldPin = $('pin-disable-old').value.trim();
  if (!pinDigits(oldPin)) { toast('当前 PIN 是 4–8 位数字'); return; }
  if (!btn.dataset.armed) {
    btn.dataset.armed = '1';
    btn.textContent = '确认关闭 PIN 校验？';
    setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = '关闭 PIN 校验'; } }, 5000);
    return;
  }
  delete btn.dataset.armed;
  btn.textContent = '关闭 PIN 校验';
  btn.disabled = true;
  try {
    const res = await setGoform('DISABLE_PIN', { OldPinNumber: oldPin });
    assertSuccess(res, '关闭 PIN');
    $('pin-disable-old').value = '';
    toast('PIN 校验已关闭', true);
    loadNetwork();
  } catch (e) { toast(`关闭失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function enterPuk(btn) {
  const puk = $('puk-code').value.trim();
  const newPin = $('puk-new-pin').value.trim();
  if (!/^\d{8}$/.test(puk)) { toast('PUK 是 8 位数字'); return; }
  if (!pinDigits(newPin)) { toast('新 PIN 是 4–8 位数字'); return; }
  if (!btn.dataset.armed) {
    btn.dataset.armed = '1';
    btn.textContent = '确认用 PUK 解锁？PUK 输错 10 次卡就作废';
    setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = 'PUK 解锁'; } }, 5000);
    return;
  }
  delete btn.dataset.armed;
  btn.textContent = 'PUK 解锁';
  btn.disabled = true;
  try {
    const res = await setGoform('ENTER_PUK', { PUKNumber: puk, PinNumber: newPin });
    assertSuccess(res, 'PUK 解锁');
    $('puk-code').value = ''; $('puk-new-pin').value = '';
    toast('PUK 解锁已提交', true);
    loadNetwork();
  } catch (e) { toast(`解锁失败：${e.message}`); }
  finally { btn.disabled = false; }
}

// ---------- USSD（v1.5.0，实机 service.js：USSD_PROCESS + ussd_write_flag 轮询） ----------
// ussd_write_flag：15 还在写（1 秒后再查），16/13 完成（读 ussd_data_info），
// 1 无服务，2 网络终止，3/4 超时，10 重试，99 不支持，41 操作不支持。
function ussdOperator() {
  const v = $('ussd-op').value.trim();
  if (v) return v;
  const g = lastDash?.signal || {};
  return g.network_provider || g.Operator || '';
}
async function sendUssd() {
  const cmd = $('ussd-cmd').value.trim();
  if (!cmd) { toast('请先填 USSD 代码'); return; }
  const btn = $('ussd-send');
  btn.disabled = true;
  $('ussd-result').textContent = '正在发送…';
  try {
    await ensureLogin();
    const res = await setGoform('USSD_PROCESS', { USSD_operator: ussdOperator(), USSD_send_number: cmd, notCallback: 'true' });
    assertSuccess(res, '发送 USSD');
    $('ussd-reply-wrap').hidden = true;
    $('ussd-reply-row').hidden = true;
    await pollUssdResult();
  } catch (e) {
    $('ussd-result').textContent = `发送失败：${e.message}`;
    toast(`发送失败：${e.message}`);
  } finally { btn.disabled = false; }
}
async function pollUssdResult() {
  try {
    for (let i = 0; i < 30; i++) {
      await sleep(1000);
      const st = await getFields(['ussd_write_flag']).catch(() => ({}));
      const flag = String(st.ussd_write_flag ?? '');
      if (flag === '15') continue;
      if (flag === '16' || flag === '13') {
        const data = await getFields(['ussd_data_info']).catch(() => ({}));
        // ussd_data_info 在 multi_data 响应里可能是嵌套对象，也可能是扁平字段。
        const info = (data.ussd_data_info && typeof data.ussd_data_info === 'object') ? data.ussd_data_info : data;
        const text = info.ussd_data || (typeof data.ussd_data_info === 'string' ? data.ussd_data_info : '') || '';
        $('ussd-result').textContent = text ? String(text) : '运营商返回了空内容。';
        if (info.ussd_action) { $('ussd-reply-wrap').hidden = false; $('ussd-reply-row').hidden = false; }
        return;
      }
      const failMap = { '1': '无服务', '2': '网络终止', '3': '超时', '4': '超时', '10': '请重试', '99': '运营商不支持 USSD', '41': '操作不支持' };
      if (failMap[flag]) { $('ussd-result').textContent = `USSD 失败：${failMap[flag]}（flag=${flag}）`; return; }
    }
    $('ussd-result').textContent = 'USSD 超时（30 秒没等到回复），请重试。';
  } catch (e) {
    $('ussd-result').textContent = `查询 USSD 结果失败：${e.message}`;
  }
}
async function replyUssd() {
  const text = $('ussd-reply').value.trim();
  if (!text) { toast('请先填回复内容'); return; }
  const btn = $('ussd-reply-btn');
  btn.disabled = true;
  try {
    const res = await setGoform('USSD_PROCESS', { USSD_operator: ussdOperator(), USSD_reply_number: text, notCallback: 'true' });
    assertSuccess(res, '回复 USSD');
    await pollUssdResult();
  } catch (e) { toast(`回复失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function cancelUssd() {
  try {
    await setGoform('USSD_PROCESS', { USSD_operator: 'ussd_cancel' });
    $('ussd-result').textContent = '已取消 USSD。';
    $('ussd-reply-wrap').hidden = true;
    $('ussd-reply-row').hidden = true;
    toast('已取消 USSD', true);
  } catch (e) { toast(`取消失败：${e.message}`); }
}

// ---------- Wi-Fi 页 ----------
// 读：queryAccessPointInfo（ResponseList：SSID/AuthMode/EncrypType/Password(base64)/
//   ApMaxStationNumber/ApBroadcastDisabled/ApIsolate/ChipIndex/AccessPointIndex/
//   AccessPointSwitchStatus/Channel/BandWidth/Band）；
// 写：setAccessPointInfo（同名字段，Password 传 Base64；OPEN 时 EncrypType=NONE 且不传密码）。
function apLabel(ap) {
  const chip = String(ap.ChipIndex ?? ap.chipIndex ?? '0');
  const idx = String(ap.AccessPointIndex ?? ap.accessPointIndex ?? '0');
  if (chip === '0' && idx === '0') return '2.4G 主网络';
  if (chip === '1' && idx === '0') return '5G 主网络';
  if (chip === '0') return '2.4G 访客网络';
  return '5G 访客网络';
}
async function loadWifi() {
  try {
    await ensureLogin();
    const [apRes, extra] = await Promise.all([
      getCommand('queryAccessPointInfo').catch(() => ({})),
      getFields(['queryWiFiModuleSwitch', 'sysIdleTimeToSleep', 'wifi_lbd_enable']).catch(() => ({}))
    ]);
    const list = normList(apRes.ResponseList || apRes);
    wifiAps = list.filter((a) => a && (a.SSID !== undefined || a.ChipIndex !== undefined));
    renderWifiList();
    const sel = $('wifi-ap');
    sel.innerHTML = wifiAps.map((a, i) => `<option value="${i}">${esc(apLabel(a))}（${esc(a.SSID || '—')}）</option>`).join('');
    if (wifiAps.length) fillWifiForm(0);
    const sleep = extra.sysIdleTimeToSleep;
    if (sleep !== undefined && sleep !== null && sleep !== '') $('wifi-sleep').value = String(sleep);
    const lbd = extra.wifi_lbd_enable;
    if (lbd !== undefined && lbd !== null && lbd !== '') {
      $('lbd-on').checked = String(lbd) === '1';
      $('lbd-cur').textContent = String(lbd) === '1' ? '已开启（2.4G 和 5G 共用一个 Wi-Fi 名）' : '已关闭（2.4G 和 5G 分开）';
    }
    if (!wifiAps.length) $('wifi-empty').hidden = false;
  } catch (e) {
    toast(`Wi-Fi 信息加载失败：${e.message}`);
  }
  loadWps();
}
function renderWifiList() {
  const el = $('wifi-list');
  if (!wifiAps.length) { el.innerHTML = ''; $('wifi-empty').hidden = false; return; }
  $('wifi-empty').hidden = true;
  el.innerHTML = wifiAps.map((a) => {
    const on = String(a.AccessPointSwitchStatus ?? '1') === '1';
    return `<div class="item">
      <div class="row"><div class="t1">${esc(apLabel(a))} · ${esc(a.SSID || '—')}</div><div class="spacer"></div><span class="pill ${on ? 'green' : 'gray'}">${on ? '开启' : '关闭'}</span></div>
      <div class="t2">加密 ${esc(a.AuthMode || '—')}${a.EncrypType ? ` / ${esc(a.EncrypType)}` : ''} · 已连 ${esc(a.CurrentStationNumber ?? '—')} / 最多 ${esc(a.ApMaxStationNumber ?? '—')} 台${String(a.ApBroadcastDisabled) === '1' ? ' · 已隐藏 SSID' : ''}${String(a.ApIsolate) === '1' ? ' · 客户端隔离' : ''}</div>
      <div class="t2">${a.Band ? `频段 ${esc(a.Band)}` : ''}${a.Channel !== undefined && a.Channel !== '' ? ` · 信道 ${esc(a.Channel)}` : ''}${a.BandWidth ? ` · 带宽 ${esc(a.BandWidth)}` : ''}${a.WirelessMode ? ` · 模式 ${esc(a.WirelessMode)}` : ''}</div>
    </div>`;
  }).join('');
}
function fillWifiForm(i) {
  const a = wifiAps[i];
  if (!a) return;
  $('wifi-ap').value = String(i);
  $('wifi-ssid').value = a.SSID || '';
  $('wifi-auth').value = a.AuthMode || 'WPA2PSK';
  $('wifi-pass').value = '';
  $('wifi-max').value = a.ApMaxStationNumber ?? '';
  $('wifi-hide').checked = String(a.ApBroadcastDisabled) === '1';
  $('wifi-isolate').checked = String(a.ApIsolate) === '1';
  $('wifi-pass-wrap').style.display = $('wifi-auth').value === 'OPEN' ? 'none' : '';
}
async function saveWifi() {
  const a = wifiAps[Number($('wifi-ap').value)];
  if (!a) { toast('请先选一个 Wi-Fi 网络'); return; }
  const ssid = $('wifi-ssid').value.trim();
  const auth = $('wifi-auth').value;
  const pass = $('wifi-pass').value;
  const max = Number($('wifi-max').value);
  if (!ssid) { toast('Wi-Fi 名称不能为空'); return; }
  if (ssid.length > 32) { toast('Wi-Fi 名称不能超过 32 个字符'); return; }
  if (auth !== 'OPEN' && pass.length < 8) { toast('Wi-Fi 密码至少 8 位（每次保存都要重新输入）'); return; }
  if (!Number.isInteger(max) || max < 1 || max > 64) { toast('最大连接数必须是 1–64'); return; }
  const btn = $('wifi-save');
  btn.disabled = true;
  try {
    const data = {
      SSID: ssid, AuthMode: auth, EncrypType: auth === 'OPEN' ? 'NONE' : 'CCMP',
      ApMaxStationNumber: max, ApBroadcastDisabled: $('wifi-hide').checked ? 1 : 0,
      ApIsolate: $('wifi-isolate').checked ? 1 : 0,
      ChipIndex: Number(a.ChipIndex ?? 0), AccessPointIndex: Number(a.AccessPointIndex ?? 0)
    };
    if (auth !== 'OPEN') data.Password = b64encode(pass);
    const res = await setGoform('setAccessPointInfo', data);
    assertSuccess(res, '保存 Wi-Fi 设置');
    toast('Wi-Fi 设置已保存，Wi-Fi 正在重启，请用新名称 / 密码重新连接', true);
    $('wifi-pass').value = '';
    loadWifi();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function saveWifiSleep() {
  const btn = $('wifi-sleep-save');
  btn.disabled = true;
  try {
    // 实机 service.js：SET_WIFI_SLEEP_INFO 要的是 sysIdleTimeToSleep
    //（v1.3.0 传的 sleep_sysIdleTimeToSleep 是错的字段名，v1.5.0 已改回）。
    const res = await setGoform('SET_WIFI_SLEEP_INFO', { sysIdleTimeToSleep: $('wifi-sleep').value });
    assertSuccess(res, '保存 Wi-Fi 休眠');
    toast('Wi-Fi 休眠设置已保存', true);
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}

// ---------- 双频合一（v1.6.0，实机 service.js：switchWiFiModule） ----------
// 原厂函数：SwitchOption 为空时按 "0"；SwitchOption=="1" 时才带 wifi_lbd_enable。
// wifi_lbd_enable=="1" = 频段引导开（2.4G/5G 共用一个 SSID），原厂 home.js
// 的 bandSteeringEnabled 就是按这个字段读的；"0" = 分开，5G SSID 一般是主
// 名称后面加 _5G。SwitchOption 取值含义是按函数结构推断的，真机上以实际为准。
async function saveLbd() {
  const on = $('lbd-on').checked;
  const btn = $('lbd-save');
  btn.disabled = true;
  try {
    const data = { SwitchOption: on ? '1' : '0' };
    if (on) data.wifi_lbd_enable = '1';
    const res = await setGoform('switchWiFiModule', data);
    assertSuccess(res, '双频合一');
    const back = await getFields(['wifi_lbd_enable']).catch(() => ({}));
    const v = back.wifi_lbd_enable;
    if (v !== undefined && v !== null && v !== '') {
      $('lbd-on').checked = String(v) === '1';
      $('lbd-cur').textContent = String(v) === '1' ? '已开启（2.4G 和 5G 共用一个 Wi-Fi 名）' : '已关闭（2.4G 和 5G 分开）';
    }
    toast(on ? '双频合一已开启，Wi-Fi 会重启一次' : '双频合一已关闭，Wi-Fi 会重启一次', true);
    await loadWifi();
  } catch (e) {
    toast(`双频合一保存失败：${e.message}`);
  } finally {
    btn.disabled = false;
  }
}

// ---------- WPS（v1.5.0，实机 service.js：WIFI_WPS_SET + startWps） ----------
// 流程：先 WIFI_WPS_SET 设模式（WPS_SSID / wps_mode / wifi_wps_index，从读接口取），
// 再 startWps 启动（ChipIndex 0=2.4G / 1=5G，ActiveWpsAccessPointIndex 0=主网络）。
let wpsState = { ssid: '', index: '' };
async function loadWps() {
  try {
    await ensureLogin();
    const r = await getFields(['wifi_wps_index', 'WscModeOption', 'AuthMode', 'wifi_onoff_state', 'EncrypType', 'wps_mode', 'WPS_SSID', 'm_ssid_enable', 'SSID1', 'm_SSID', 'm_EncrypType', 'm_AuthMode']).catch(() => ({}));
    wpsState = { ssid: r.WPS_SSID || r.SSID1 || '', index: r.wifi_wps_index ?? '' };
    $('wps-cur').textContent = `模式 ${r.wps_mode || '—'} · SSID ${wpsState.ssid || '—'} · Wi-Fi ${r.wifi_onoff_state === '1' ? '开启' : '关闭'}`;
    if (r.wps_mode === 'PIN' || r.wps_mode === 'PBC') $('wps-mode').value = r.wps_mode;
    $('wps-pin-wrap').hidden = $('wps-mode').value !== 'PIN';
  } catch (e) { /* 读不到不影响配对 */ }
  try {
    const st = await getCommand('queryWpsStatus').catch(() => ({}));
    if (st && (st.wpsStatus || st.status)) $('wps-status').textContent = `状态：${st.wpsStatus || st.status}`;
  } catch {}
}
async function startWps() {
  const mode = $('wps-mode').value;
  const pin = $('wps-pin').value.trim();
  const chip = Number($('wps-band').value);
  if (mode === 'PIN' && !/^\d{8}$/.test(pin)) { toast('PIN 模式要填 8 位 PIN'); return; }
  const btn = $('wps-start');
  btn.disabled = true;
  $('wps-status').textContent = '状态：正在启动配对…';
  try {
    await ensureLogin();
    const cfg = { WPS_SSID: wpsState.ssid, wps_mode: mode, wifi_wps_index: wpsState.index };
    if (mode === 'PIN') cfg.wps_pin = pin;
    const r1 = await setGoform('WIFI_WPS_SET', cfg);
    assertSuccess(r1, '配置 WPS');
    const start = { ChipIndex: chip, ActiveWpsAccessPointIndex: 0, WpsMode: mode };
    if (mode === 'PIN') start.WpsPin = pin;
    const r2 = await setGoform('startWps', start);
    assertSuccess(r2, '启动 WPS');
    $('wps-status').textContent = mode === 'PBC'
      ? '状态：配对已启动（2 分钟内按设备上的 WPS 键）。'
      : '状态：配对已启动（在设备上输入 PIN，或等设备提示）。';
    toast('WPS 配对已启动', true);
    setTimeout(loadWps, 5000);
  } catch (e) {
    $('wps-status').textContent = `状态：启动失败：${e.message}`;
    toast(`启动失败：${e.message}`);
  } finally { btn.disabled = false; }
}

// ---------- 短信中心设置（v1.5.0，实机 service.js：SET_MESSAGE_CENTER） ----------
// 读 sms_parameter_info → sms_para_sca（中心号码）、sms_para_mem_store、
// sms_para_status_report（送达报告）、sms_para_validity_period
// （143=12 小时，167=1 天，173=1 周，244/255=最长）。
const SMS_VALIDITY = { 143: 'twelve_hours', 167: 'one_day', 173: 'one_week', 244: 'largest', 255: 'largest' };
const SMS_VALIDITY_LABEL = { twelve_hours: '12 小时', one_day: '1 天', one_week: '1 周', largest: '最长' };
async function loadSmsSettings() {
  try {
    await ensureLogin();
    const r = await getFields(['sms_parameter_info']).catch(() => ({}));
    // sms_parameter_info 在 multi_data 响应里可能是嵌套对象，也可能是扁平字段。
    const info = (r.sms_parameter_info && typeof r.sms_parameter_info === 'object') ? r.sms_parameter_info : r;
    const center = info.sms_para_sca || '';
    const validity = SMS_VALIDITY[Number(info.sms_para_validity_period)] || 'twelve_hours';
    const report = String(info.sms_para_status_report) === '1';
    if (center) $('sms-center').value = center;
    $('sms-validity').value = validity;
    $('sms-report').checked = report;
    $('sms-set-cur').textContent = `中心号码 ${center || '—'} · 有效期 ${SMS_VALIDITY_LABEL[validity]} · 送达报告 ${report ? '开' : '关'} · 存储 ${info.sms_para_mem_store || '—'}`;
  } catch (e) { /* 读不到不影响发送 */ }
}
async function saveSmsSettings() {
  const center = $('sms-center').value.trim();
  if (!center) { toast('请先填短信中心号码'); return; }
  const btn = $('sms-set-save');
  btn.disabled = true;
  try {
    const res = await setGoform('SET_MESSAGE_CENTER', {
      save_time: $('sms-validity').value,
      MessageCenter: center,
      status_save: $('sms-report').checked ? '1' : '0',
      save_location: 'native',
      notCallback: 'true'
    });
    assertSuccess(res, '保存短信设置');
    toast('短信中心设置已保存', true);
    loadSmsSettings();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}

// ---------- 安全页（防火墙状态只读 + 黑名单） ----------
// 字段依据：PlayFaster/ha-zte-router-5g-monitor（MC7010/MC888 Pro 实测，
// 从 ZTE 同系固件 Web UI JS 里挖到的字段名；MU5120 上是否返回需实测，
// 空值照实显示“—”）。规则串（IPPortFilterRules_N 等）的内部格式在公开
// 资料里没有说明，只原样展示，不解析。写接口在三个开源项目里都不存在，
// 本页不提供任何改动入口。
const FW_RULE_SLOTS = Array.from({ length: 10 }, (_, i) => i);
const FW_RULE_SLOTS20 = Array.from({ length: 20 }, (_, i) => i);
const FW_READ_FIELDS = ['firewall_switch', 'FirewallDisable', 'DefaultFirewallPolicy', 'ACL_mode', 'WANPingFilter',
  'websURLFilters', 'upnpEnabled', 'DMZEnable', 'DMZIPAddress', 'alg_sip_enable', 'RemoteManagement',
  'IPPortFilterEnable', ...FW_RULE_SLOTS.map((i) => `IPPortFilterRules_${i}`),
  'PortForwardEnable', ...FW_RULE_SLOTS20.map((i) => `PortForwardRules_${i}`),
  'PortMapEnable', ...FW_RULE_SLOTS20.map((i) => `PortMapRules_${i}`)];
// v1.5.0：端口过滤/转发/映射的当前值（保存时原样带回用）
let fwState = { policy: '', pfEnabled: '', fwdEnabled: '', mapEnabled: '' };
function fmtOnOff(v) {
  if (v === undefined || v === null || String(v).trim() === '') return '—';
  const s = String(v).toLowerCase();
  if (['1', 'on', 'enable', 'enabled', 'true'].includes(s)) return '开启';
  if (['0', 'off', 'disable', 'disabled', 'false'].includes(s)) return '关闭';
  return String(v);
}
function renderRuleList(el, rules, kind) {
  const items = (rules || [])
    .map((r, i) => ({ r, i }))
    .filter(({ r }) => r !== undefined && r !== null && String(r).trim() !== '');
  el.innerHTML = items.length
    ? items.map(({ r, i }) => `<div class="item"><div class="t2" style="margin-top:0">${esc(String(r))}</div><div class="row mt8"><button class="btn ghost small" type="button" data-del-fw="${kind}" data-idx="${i}">删除这条</button></div></div>`).join('')
    : '<div class="empty">未配置规则（或设备未返回）。</div>';
  el.querySelectorAll('[data-del-fw]').forEach((b) => b.addEventListener('click', () => deleteFwRule(b.dataset.delFw, Number(b.dataset.idx), b)));
  return items.length;
}
async function loadSecurity() {
  try {
    await ensureLogin();
    const r = await getFields(FW_READ_FIELDS).catch(() => ({}));
    fwState = {
      policy: r.DefaultFirewallPolicy ?? '',
      pfEnabled: r.IPPortFilterEnable ?? '',
      fwdEnabled: r.PortForwardEnable ?? '',
      mapEnabled: r.PortMapEnable ?? ''
    };
    // 只有读到了当前策略值，保存时才敢原样带回（策略取值未在文件里出现，不能编一个）。
    fwLoaded = r.DefaultFirewallPolicy !== undefined;
    $('fw-switch').textContent = fmtOnOff(r.firewall_switch);
    $('fw-disable').textContent = fmtOnOff(r.FirewallDisable);
    $('fw-policy').textContent = r.DefaultFirewallPolicy || '—';
    $('fw-acl').textContent = r.ACL_mode || '—';
    $('fw-ping').textContent = fmtOnOff(r.WANPingFilter);
    $('fw-enable').checked = String(r.IPPortFilterEnable) === '1' || String(r.firewall_switch) === '1';
    $('fw-pf-state').textContent = r.IPPortFilterEnable !== undefined && String(r.IPPortFilterEnable).trim() !== '' ? `（${fmtOnOff(r.IPPortFilterEnable)}）` : '';
    $('fw-fwd-enable').checked = String(r.PortForwardEnable) === '1';
    $('fw-fwd-state').textContent = r.PortForwardEnable !== undefined && String(r.PortForwardEnable).trim() !== '' ? `（${fmtOnOff(r.PortForwardEnable)}）` : '';
    $('fw-map-state').textContent = r.PortMapEnable !== undefined && String(r.PortMapEnable).trim() !== '' ? `（${fmtOnOff(r.PortMapEnable)}）` : '';
    const n1 = renderRuleList($('fw-pf-rules'), FW_RULE_SLOTS.map((i) => r[`IPPortFilterRules_${i}`]), 'filter');
    const n2 = renderRuleList($('fw-fwd-rules'), FW_RULE_SLOTS20.map((i) => r[`PortForwardRules_${i}`]), 'forward');
    const n3 = renderRuleList($('fw-map-rules'), FW_RULE_SLOTS20.map((i) => r[`PortMapRules_${i}`]), 'map');
    $('fw-rules-note').textContent = `共读到 ${n1 + n2 + n3} 条规则（过滤 ${n1} · 转发 ${n2} · 映射 ${n3}）；空的就是没配置或设备没返回。`;
    $('fw-url').textContent = r.websURLFilters || '—';
    $('fw-upnp').textContent = fmtOnOff(r.upnpEnabled);
    $('fw-dmz').textContent = fmtOnOff(r.DMZEnable);
    $('fw-dmzip').textContent = r.DMZIPAddress || '—';
    $('fw-sip').textContent = fmtOnOff(r.alg_sip_enable);
    $('upnp-on').checked = String(r.upnpEnabled) === '1';
    $('dmz-on').checked = String(r.DMZEnable) === '1';
    if (r.DMZIPAddress) $('dmz-ip').value = r.DMZIPAddress;
    $('sip-on').checked = String(r.alg_sip_enable) === '1';
    $('remote-on').checked = String(r.RemoteManagement) === '1';
    $('ping-on').checked = String(r.WANPingFilter) === '1';
  } catch (e) {
    toast(`安全页加载失败：${e.message}`);
  }
  loadAcl(); // 黑名单（在安全页展示）
  loadWhiteSite();
}

// ---------- 防火墙写操作（v1.5.0，实机 service.js） ----------
// 端口过滤：本固件 USE_IPV6_INTERFACE 为真，原厂用 ADD_IP_PORT_FILETER_V4V6
// （ip_version 取自页面 ipType；IPv4 规则先试 "4"），失败自动回退旧接口。
// defaultFirewallPolicy 的取值未在文件里出现：保存时把读到的当前值原样带回。
let fwLoaded = false;
function portNum(v, label) {
  if (v === '' || v == null) return '';
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error(`${label}必须是 1–65535 的端口号`);
  return String(n);
}
async function saveFirewall() {
  if (!fwLoaded) { toast('防火墙当前值没读到，请先刷新安全页再保存'); return; }
  const btn = $('fw-save');
  btn.disabled = true;
  try {
    const res = await setGoform('BASIC_SETTING', {
      portFilterEnabled: $('fw-enable').checked ? '1' : '0',
      defaultFirewallPolicy: fwState.policy
    });
    assertSuccess(res, '保存防火墙设置');
    toast('防火墙设置已保存', true);
    loadSecurity();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function addPortFilter() {
  const mac = $('pf-mac').value.trim();
  const sip = $('pf-sip').value.trim();
  const dip = $('pf-dip').value.trim();
  if (mac && !/^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/.test(mac)) { toast('MAC 地址格式不正确'); return; }
  if (sip && !isValidIP(sip)) { toast('源 IP 格式不正确'); return; }
  if (dip && !isValidIP(dip)) { toast('目标 IP 格式不正确'); return; }
  let sFrom, sTo, dFrom, dTo;
  try {
    sFrom = portNum($('pf-sport').value, '源端口（起）');
    sTo = portNum($('pf-sport2').value, '源端口（止）');
    dFrom = portNum($('pf-dport').value, '目标端口（起）');
    dTo = portNum($('pf-dport2').value, '目标端口（止）');
  } catch (e) { toast(e.message); return; }
  const data = {
    mac_address: mac, dip_address: dip, sip_address: sip,
    dFromPort: dFrom, dToPort: dTo, sFromPort: sFrom, sToPort: sTo,
    action: $('pf-action').value, protocol: $('pf-proto').value, comment: $('pf-comment').value.trim()
  };
  const btn = $('pf-add');
  btn.disabled = true;
  try {
    try {
      const res = await setGoform('ADD_IP_PORT_FILETER_V4V6', { ip_version: '4', ...data });
      assertSuccess(res, '新增端口过滤规则');
    } catch (e1) {
      const res = await setGoform('ADD_IP_PORT_FILETER', data);
      assertSuccess(res, '新增端口过滤规则');
    }
    toast('端口过滤规则已新增', true);
    loadSecurity();
  } catch (e) { toast(`新增失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function deleteFwRule(kind, idx, btn) {
  if (!btn.dataset.armed) {
    btn.dataset.armed = '1';
    btn.textContent = '确认删除？';
    setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = '删除这条'; } }, 5000);
    return;
  }
  btn.disabled = true;
  btn.textContent = '删除中…';
  try {
    const delId = `${idx};`;
    if (kind === 'filter') {
      try {
        const res = await setGoform('DEL_IP_PORT_FILETER_V4V6', { delete_id: delId, delete_id_v6: '' });
        assertSuccess(res, '删除端口过滤规则');
      } catch (e1) {
        const res = await setGoform('DEL_IP_PORT_FILETER', { delete_id: delId });
        assertSuccess(res, '删除端口过滤规则');
      }
    } else if (kind === 'forward') {
      const res = await setGoform('FW_FORWARD_DEL', { delete_id: delId });
      assertSuccess(res, '删除端口转发规则');
    } else {
      const res = await setGoform('DEL_PORT_MAP', { delete_id: delId });
      assertSuccess(res, '删除端口映射规则');
    }
    toast('规则已删除', true);
    loadSecurity();
  } catch (e) {
    toast(`删除失败：${e.message}`);
    btn.disabled = false; btn.textContent = '删除这条'; delete btn.dataset.armed;
  }
}
async function savePortForwardEnable() {
  const btn = $('fw-fwd-save');
  btn.disabled = true;
  try {
    const res = await setGoform('VIRTUAL_SERVER', { PortForwardEnable: $('fw-fwd-enable').checked ? '1' : '0' });
    assertSuccess(res, '保存端口转发开关');
    toast('端口转发开关已保存', true);
    loadSecurity();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function addPortForward() {
  const ip = $('fwd-ip').value.trim();
  if (!isValidIP(ip)) { toast('内网设备 IP 格式不正确'); return; }
  let p1, p2;
  try {
    p1 = portNum($('fwd-port').value, '外部端口（起）');
    p2 = portNum($('fwd-port2').value, '外部端口（止）');
  } catch (e) { toast(e.message); return; }
  if (!p1) { toast('外部端口（起）是必填的'); return; }
  const btn = $('fwd-add');
  btn.disabled = true;
  try {
    const res = await setGoform('FW_FORWARD_ADD', {
      ipAddress: ip, portStart: p1, portEnd: p2 || p1,
      protocol: $('fwd-proto').value, comment: $('fwd-comment').value.trim()
    });
    assertSuccess(res, '新增端口转发规则');
    toast('端口转发规则已新增', true);
    loadSecurity();
  } catch (e) { toast(`新增失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function addPortMap() {
  let fromPort, toPort;
  try {
    fromPort = portNum($('map-sport').value, '源端口');
    toPort = portNum($('map-dport').value, '目标端口');
  } catch (e) { toast(e.message); return; }
  if (!fromPort || !toPort) { toast('源端口和目标端口都是必填的'); return; }
  const dip = $('map-dip').value.trim();
  if (!isValidIP(dip)) { toast('目标 IP 格式不正确'); return; }
  const btn = $('map-add');
  btn.disabled = true;
  try {
    const res = await setGoform('ADD_PORT_MAP', {
      portMapEnabled: '1', fromPort, ip_address: dip, toPort,
      protocol: $('map-proto').value, comment: $('map-comment').value.trim()
    });
    assertSuccess(res, '新增端口映射规则');
    toast('端口映射规则已新增（端口映射已开启）', true);
    loadSecurity();
  } catch (e) { toast(`新增失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function saveUpnp() {
  const btn = $('upnp-save');
  btn.disabled = true;
  try {
    const res = await setGoform('UPNP_SETTING', { upnp_setting_option: $('upnp-on').checked ? '1' : '0' });
    assertSuccess(res, '保存 UPnP');
    toast('UPnP 已保存', true);
    loadSecurity();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function saveDmz() {
  const on = $('dmz-on').checked;
  const ip = $('dmz-ip').value.trim();
  if (on && !isValidIP(ip)) { toast('开启 DMZ 要先填一个正确的 DMZ 主机 IP'); return; }
  const btn = $('dmz-save');
  btn.disabled = true;
  try {
    const data = { DMZEnabled: on ? '1' : '0' };
    if (on) data.DMZIPAddress = ip;
    const res = await setGoform('DMZ_SETTING', data);
    assertSuccess(res, '保存 DMZ');
    toast('DMZ 已保存', true);
    loadSecurity();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function saveSip() {
  const btn = $('sip-save');
  btn.disabled = true;
  try {
    const res = await setGoform('ALG_SETTING', { alg_sip_enable: $('sip-on').checked ? '1' : '0' });
    assertSuccess(res, '保存 SIP ALG');
    toast('SIP ALG 已保存', true);
    loadSecurity();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function saveFwSys() {
  const btn = $('fw-sys-save');
  btn.disabled = true;
  try {
    const remote = $('remote-on').checked ? '1' : '0';
    const ping = $('ping-on').checked ? '1' : '0';
    // 原厂写法：同一值发两遍（remoteManagementEnabled/RemoteManagement 等）。
    const res = await setGoform('FW_SYS', {
      remoteManagementEnabled: remote, pingFrmWANFilterEnabled: ping,
      RemoteManagement: remote, WANPingFilter: ping
    });
    assertSuccess(res, '保存远程管理 / Ping 过滤');
    toast('远程管理 / Ping 过滤已保存', true);
    loadSecurity();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
// ---------- 上网白名单（v1.5.0，实机 service.js：ADD_WHITE_SITE / REMOVE_WHITE_SITE） ----------
// 列表格式：固件返回 site_white_list（字符串 "name,site;…" 或对象数组），
// 删除用条目 id（逗号连接可多删）。格式是按增/删签名推断的，真机上以实际返回为准。
async function loadWhiteSite() {
  try {
    await ensureLogin();
    const r = await getFields(['site_white_list']).catch(() => ({}));
    const raw = r.site_white_list ?? r.siteList ?? '';
    let items = [];
    if (Array.isArray(raw)) {
      items = raw.map((x, i) => ({ id: x.id ?? String(i), name: x.name || '', site: x.site || x.url || '' }));
    } else {
      items = String(raw).split(';').filter(Boolean).map((s, i) => {
        const parts = String(s).split(',');
        if (parts.length >= 3) return { id: parts[0], name: parts[1], site: parts.slice(2).join(',') };
        if (parts.length === 2) return { id: String(i), name: parts[0], site: parts[1] };
        return { id: String(i), name: '', site: s };
      });
    }
    $('site-white-list').innerHTML = items.length
      ? items.map((x) => `<div class="item"><div class="t1">${esc(x.name || x.site)}</div><div class="t2">${esc(x.site)}</div><div class="row mt8"><button class="btn ghost small" type="button" data-del-site="${esc(x.id)}">删除</button></div></div>`).join('')
      : '<div class="empty">白名单是空的（没有限制）。</div>';
    document.querySelectorAll('#page-security [data-del-site]').forEach((b) => b.addEventListener('click', () => deleteWhiteSite(b.dataset.delSite, b)));
  } catch (e) { /* 读不到不影响防火墙 */ }
}
async function addWhiteSite() {
  const name = $('site-white-name').value.trim();
  const site = $('site-white-site').value.trim();
  if (!name || !site) { toast('名称和网址都要填'); return; }
  const btn = $('site-white-add');
  btn.disabled = true;
  try {
    const res = await setGoform('ADD_WHITE_SITE', { name, site });
    assertSuccess(res, '新增白名单网址');
    $('site-white-name').value = ''; $('site-white-site').value = '';
    toast('白名单网址已新增', true);
    loadWhiteSite();
  } catch (e) { toast(`新增失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function deleteWhiteSite(id, btn) {
  if (!btn.dataset.armed) {
    btn.dataset.armed = '1';
    btn.textContent = '确认删除？';
    setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = '删除'; } }, 5000);
    return;
  }
  btn.disabled = true;
  try {
    const res = await setGoform('REMOVE_WHITE_SITE', { ids: String(id) });
    assertSuccess(res, '删除白名单网址');
    toast('白名单网址已删除', true);
    loadWhiteSite();
  } catch (e) {
    toast(`删除失败：${e.message}`);
    btn.disabled = false; btn.textContent = '删除'; delete btn.dataset.armed;
  }
}

// ---------- 高级页（DDNS / SNTP / VPN 状态 / 升级状态 / 重启规则 / 诊断，只读） ----------
// 字段依据同安全页（HA 项目从 ZTE 同系固件 Web UI JS 挖掘；MU5120 未验证，
// 空值照实显示）。写接口均无依据，本页不提供任何改动入口。
const ADV_READ_FIELDS = ['DDNS_Enable', 'DDNS_Mode', 'RemoteManagement',
  'sntp_server0', 'sntp_server1', 'sntp_server2', 'sntp_dst_enable', 'sntp_timezone', 'sntp_time_set_mode', 'sntp_server_list1', 'sntp_syn_done',
  'l2tp_local_ipaddr', 'l2tp_status', 'pptp_local_ipaddr', 'pptp_status', 'ipsec_enable', 'ipsec_status', 'gre_enable', 'vpn_conn_status',
  'current_upgrade_state', 'new_version_state', 'upgrade_result', 'detect_new_version', 'dm_new_version', 'dm_update_package_file_exist', 'dm_update_successful_time', 'GetUpgAutoSetting', 'UpgMode', 'UpgIntervalDay', 'UpgRoamPermission',
  'reboot_schedule_enable', 'reboot_schedule_mode', 'reboot_dow', 'reboot_dod', 'reboot_hour1', 'reboot_min1', 'reboot_hour2', 'reboot_min2',
  'DIAG_CHECK', 'DIAG_URL', 'LocalDomain', 'traceroute_flag', 'net_link_detect_ping_times'];
function fmtRebootRule(r) {
  if (r.reboot_schedule_enable === undefined || String(r.reboot_schedule_enable).trim() === '') return '设备未返回重启规则字段。';
  if (String(r.reboot_schedule_enable) === '0') return '固件里的重启规则未开启（控制台的每天定时重启在设置页）。';
  const mode = String(r.reboot_schedule_mode) === '2' ? '每月' : String(r.reboot_schedule_mode) === '1' ? '每周' : '定时';
  const dayNames = ['日', '一', '二', '三', '四', '五', '六'];
  const when = mode === '每月' ? `${r.reboot_dod || '—'} 号` : `星期${dayNames[Number(r.reboot_dow) - 1] || r.reboot_dow || '—'}`;
  const hh = (v) => (v === undefined || v === null || String(v).trim() === '') ? null : String(v).padStart(2, '0');
  const t1 = hh(r.reboot_hour1) && hh(r.reboot_min1) ? `${hh(r.reboot_hour1)}:${hh(r.reboot_min1)}` : '—';
  const t2 = hh(r.reboot_hour2) && hh(r.reboot_min2) ? `${hh(r.reboot_hour2)}:${hh(r.reboot_min2)}` : null;
  return `固件重启规则：${mode} ${when} · ${t1}${t2 && t2 !== t1 ? `、${t2}` : ''}`;
}
async function loadAdvanced() {
  try {
    await ensureLogin();
    const r = await getFields(ADV_READ_FIELDS).catch(() => ({}));
    $('adv-ddns').textContent = fmtOnOff(r.DDNS_Enable);
    $('adv-ddns-mode').textContent = r.DDNS_Mode || '—';
    $('adv-remote').textContent = fmtOnOff(r.RemoteManagement);
    $('adv-sntp0').textContent = r.sntp_server0 || '—';
    $('adv-sntp1').textContent = r.sntp_server1 || '—';
    $('adv-sntp2').textContent = r.sntp_server2 || '—';
    $('adv-sntp-dst').textContent = fmtOnOff(r.sntp_dst_enable);
    $('adv-sntp-tz').textContent = r.sntp_timezone || '—';
    $('adv-sntp-mode').textContent = r.sntp_time_set_mode || '—';
    const list1 = r.sntp_server_list1 || '';
    $('adv-sntp-note').textContent = `内置可选服务器：${list1 || '—'} · 上次对时完成：${r.sntp_syn_done === '1' ? '是' : r.sntp_syn_done === '0' ? '否' : '—'}`;
    $('adv-l2tp').textContent = `${r.l2tp_status || '—'}${r.l2tp_local_ipaddr ? `（${r.l2tp_local_ipaddr}）` : ''}`;
    $('adv-pptp').textContent = `${r.pptp_status || '—'}${r.pptp_local_ipaddr ? `（${r.pptp_local_ipaddr}）` : ''}`;
    $('adv-ipsec').textContent = `${fmtOnOff(r.ipsec_enable)}${r.ipsec_status ? ` / ${r.ipsec_status}` : ''}`;
    $('adv-gre').textContent = fmtOnOff(r.gre_enable);
    $('adv-vpn').textContent = r.vpn_conn_status || '—';
    $('adv-upg-new').textContent = r.detect_new_version === '1' ? `有新版本${r.dm_new_version ? `（${r.dm_new_version}）` : ''}` : r.new_version_state || '—';
    $('adv-upg-cur').textContent = r.current_upgrade_state || '—';
    $('adv-upg-result').textContent = r.upgrade_result || '—';
    $('adv-upg-pkg').textContent = r.dm_update_package_file_exist === '1' ? `有升级包${r.dm_update_successful_time ? `（上次升级 ${r.dm_update_successful_time}）` : ''}` : r.dm_update_package_file_exist === '0' ? '无升级包' : '—';
    $('adv-upg-auto').textContent = `${fmtOnOff(r.GetUpgAutoSetting)}${r.UpgMode ? ` · 模式 ${r.UpgMode}` : ''}${r.UpgIntervalDay ? ` · 间隔 ${r.UpgIntervalDay} 天` : ''}${r.UpgRoamPermission ? ` · 漫游 ${fmtOnOff(r.UpgRoamPermission)}` : ''}`;
    // 升级自动设置表单回填（UpgMode 取值未在文件里出现：读到的值若不在 0/1/2 里就不预选）。
    if (['0', '1', '2'].includes(String(r.UpgMode))) $('upg-mode').value = String(r.UpgMode);
    if (r.UpgIntervalDay) $('upg-interval').value = r.UpgIntervalDay;
    $('upg-roam').checked = String(r.UpgRoamPermission) === '1';
    $('adv-reboot').textContent = fmtRebootRule(r);
    $('adv-diag-check').textContent = r.DIAG_CHECK || '—';
    $('adv-diag-url').textContent = r.DIAG_URL || '—';
    $('adv-diag-domain').textContent = r.LocalDomain || '—';
    $('adv-diag-ping').textContent = r.net_link_detect_ping_times || '—';
  } catch (e) {
    toast(`高级页加载失败：${e.message}`);
  }
  // v1.5.0 可操作区（各自读自己的字段）
  loadVpn();
  loadPower();
  loadIms();
  loadSlice();
  loadTr069();
  loadMtu();
  loadAdvTemps();
}

// ---------- VPN 客户端（v1.5.0，实机 service.js：VPN_CLIENT_SET / VPN_CONNECT / VPN_DISCONNECT） ----------
// 只做 PPTP / L2TP / IPSec 三种常用类型；GRE / L2TPV3 的接口在文件里有，字段多且冷门，暂不做表单。
const VPN_READ_FIELDS = ['vpn_type', 'vpn_l2tp_passwd', 'vpn_account', 'vpn_passwd', 'vpn_server_ip', 'vpn_conn_status', 'vpn_auto_start', 'vpn_remote_ip', 'vpn_local_ip', 'l2tp_local_tunnel_id', 'l2tp_remote_tunnel_id', 'l2tp_local_ip', 'l2tp_remote_ip', 'l2tp_local_session_id', 'l2tp_remote_session_id', 'l2tp_eth0_ip', 'l2tp_type', 'l2tp_udp_sport', 'l2tp_udp_dport', 'l2tpv3_enable', 'gre_enable', 'gre_lvl', 'gre_dest_ip', 'gre_host_ip', 'gre_remote_ip', 'gre_remote_private_ip', 'gre_remote_private_port', 'ipsec_enable', 'ipsec_status'];
async function loadVpn() {
  try {
    await ensureLogin();
    const r = await getFields(VPN_READ_FIELDS).catch(() => ({}));
    const type = String(r.vpn_type || 'PPTP').toUpperCase();
    $('vpn-cur').textContent = `类型 ${type} · 连接 ${r.vpn_conn_status || '—'}${r.vpn_remote_ip ? ` · 远端 ${r.vpn_remote_ip}` : ''}${r.vpn_local_ip ? ` · 本地 ${r.vpn_local_ip}` : ''}`;
    if (['PPTP', 'L2TP', 'IPSEC'].includes(type)) $('vpn-type').value = type;
    if (r.vpn_server_ip) $('vpn-server').value = r.vpn_server_ip;
    if (r.vpn_account) $('vpn-account').value = r.vpn_account;
    if (r.vpn_passwd) $('vpn-pass').value = r.vpn_passwd;
    if (r.vpn_l2tp_passwd) $('vpn-l2tp-pass').value = r.vpn_l2tp_passwd;
    $('vpn-ipsec-on').checked = String(r.ipsec_enable) === '1';
    $('vpn-auto').checked = String(r.vpn_auto_start) === '1';
    syncVpnForm();
  } catch (e) { /* 读不到不影响配置 */ }
}
function syncVpnForm() {
  const type = $('vpn-type').value;
  $('vpn-account-wrap').style.display = type === 'IPSEC' ? 'none' : '';
  $('vpn-l2tp-pass-wrap').style.display = type === 'L2TP' ? '' : 'none';
  $('vpn-ipsec-wrap').style.display = type === 'L2TP' ? '' : 'none';
  $('vpn-ipsec-pass-wrap').style.display = type === 'L2TP' && $('vpn-ipsec-on').checked ? '' : 'none';
  $('vpn-server').placeholder = type === 'IPSEC' ? 'IPSec 服务器地址' : '例如 vpn.example.com 或 IP';
}
async function saveVpn() {
  const type = $('vpn-type').value;
  const server = $('vpn-server').value.trim();
  const account = $('vpn-account').value.trim();
  const pass = $('vpn-pass').value;
  if (!server) { toast('请先填服务器地址'); return; }
  if (type !== 'IPSEC' && (!account || !pass)) { toast('账号和密码都要填'); return; }
  if (type === 'IPSEC' && !pass) { toast('请先填 IPSec 密码'); return; }
  const btn = $('vpn-save');
  btn.disabled = true;
  try {
    const data = { vpn_type: type, vpn_auto_start: $('vpn-auto').checked ? '1' : '0' };
    if (type === 'PPTP' || type === 'L2TP') {
      data.vpn_account = account; data.vpn_passwd = pass; data.vpn_server_ip = server;
    }
    if (type === 'L2TP') {
      data.vpn_l2tp_passwd = $('vpn-l2tp-pass').value;
      data.ipsec_enable = $('vpn-ipsec-on').checked ? '1' : '0';
      if ($('vpn-ipsec-on').checked) data.ipsec_password = $('vpn-ipsec-pass').value;
    }
    if (type === 'IPSEC') {
      data.vpn_ipsec_server_ip = server;
      data.vpn_ipsec_password = pass;
    }
    const res = await setGoform('VPN_CLIENT_SET', data);
    assertSuccess(res, '保存 VPN 配置');
    toast('VPN 配置已保存', true);
    loadVpn();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function connectVpn() {
  const btn = $('vpn-connect');
  btn.disabled = true;
  try {
    const res = await setGoform('VPN_CONNECT', { notCallback: 'true' });
    assertSuccess(res, '连接 VPN');
    toast('正在连接 VPN…', true);
    setTimeout(loadVpn, 3000);
  } catch (e) { toast(`连接失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function disconnectVpn() {
  const btn = $('vpn-disconnect');
  btn.disabled = true;
  try {
    const res = await setGoform('VPN_DISCONNECT', { notCallback: 'true' });
    assertSuccess(res, '断开 VPN');
    toast('VPN 已断开', true);
    setTimeout(loadVpn, 2000);
  } catch (e) { toast(`断开失败：${e.message}`); }
  finally { btn.disabled = false; }
}

// ---------- 固件升级（v1.5.0，实机 service.js：IF_UPGRADE / SetUpgAutoSetting） ----------
// 注意：UpgMode 的取值（0/1/2 对应什么）未在文件里出现，下拉框按最常见的
// “0=不自动 / 1=自动安装 / 2=只提醒”推断；表单会先读当前值回填，
// 读到的值若不在 0/1/2 里就不预选，保存时以你选的为准。真机上以实际为准。
async function checkUpgrade() {
  const btn = $('upg-check');
  btn.disabled = true;
  btn.textContent = '正在检查…';
  try {
    const res = await setGoform('IF_UPGRADE', { select_op: 'check' });
    assertSuccess(res, '检查更新');
    toast('已发起检查更新，稍后刷新状态', true);
    setTimeout(loadAdvanced, 5000);
  } catch (e) { toast(`检查失败：${e.message}`); }
  finally { btn.disabled = false; btn.textContent = '检查更新'; }
}
async function saveUpgradeAuto() {
  const interval = Number($('upg-interval').value);
  if (!Number.isInteger(interval) || interval < 1 || interval > 30) { toast('检查间隔必须是 1–30 天'); return; }
  const btn = $('upg-save');
  btn.disabled = true;
  try {
    const res = await setGoform('SetUpgAutoSetting', {
      UpgMode: $('upg-mode').value,
      UpgIntervalDay: String(interval),
      UpgRoamPermission: $('upg-roam').checked ? '1' : '0'
    });
    assertSuccess(res, '保存自动升级设置');
    toast('自动升级设置已保存', true);
    loadAdvanced();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}

// ---------- 省电与开机（v1.5.0，实机 service.js） ----------
// 无服务自动重启（PS_NO_SERVICE_RESTART_SET）没有对应的读字段：
// 开关显示的是你上次保存的选择（存在浏览器本地），保存即按选择写入。
let powerState = { needHardReboot: '' };
const PS_RESTART_KEY = 'u50pro-psrestart';
async function loadPower() {
  try {
    await ensureLogin();
    const r = await getFields(['mgmt_quicken_power_on', 'need_hard_reboot', 'mc_low_current_mode', 'wifi_pcie_powersave_enable', 'thermal_control_enable', 'thermal_led_enable', 'night_mode_switch', 'night_mode_start_time', 'night_mode_end_time', 'night_mode_close_all_led', 'web_wake_switch', 'web_sleep_switch', 'web_wake_time', 'web_sleep_time', 'time_limited']).catch(() => ({}));
    powerState.needHardReboot = r.need_hard_reboot ?? '';
    $('fastboot-on').checked = String(r.mgmt_quicken_power_on) === '1';
    $('lowcurrent-on').checked = String(r.mc_low_current_mode) === '1';
    $('psrestart-on').checked = localStorage.getItem(PS_RESTART_KEY) === '1';
    $('pcie-on').checked = String(r.wifi_pcie_powersave_enable) === '1';
    $('thermal-on').checked = String(r.thermal_control_enable) === '1';
    $('thermal-led-on').checked = String(r.thermal_led_enable) === '1';
    $('led-night-on').checked = String(r.night_mode_switch) === '1';
    if (r.night_mode_start_time) $('led-start').value = r.night_mode_start_time;
    if (r.night_mode_end_time) $('led-end').value = r.night_mode_end_time;
    $('led-all-off').checked = String(r.night_mode_close_all_led) === '1';
    $('webwake-on').checked = String(r.web_wake_switch) === '1';
    if (r.web_wake_time) $('webwake-time').value = r.web_wake_time;
    $('websleep-on').checked = String(r.web_sleep_switch) === '1';
    if (r.web_sleep_time) $('websleep-time').value = r.web_sleep_time;
    if (r.time_limited !== undefined && r.time_limited !== null && String(r.time_limited) !== '') $('time-limited').value = r.time_limited;
  } catch (e) { /* 读不到不影响保存 */ }
}
async function savePower() {
  const btn = $('power-save');
  btn.disabled = true;
  try {
    const r1 = await setGoform('MGMT_CONTROL_POWER_ON_SPEED', {
      mgmt_quicken_power_on: $('fastboot-on').checked ? '1' : '0',
      need_hard_reboot: powerState.needHardReboot || '0'
    });
    assertSuccess(r1, '保存快速开机');
    const r2 = await setGoform('LOW_CURRENT_MODE_SWITCH', { mc_low_current_mode: $('lowcurrent-on').checked ? '1' : '0' });
    assertSuccess(r2, '保存小电流模式');
    const ps = $('psrestart-on').checked ? '1' : '0';
    const r3 = await setGoform('PS_NO_SERVICE_RESTART_SET', { ps_no_service_restart_flag: ps });
    assertSuccess(r3, '保存无服务自动重启');
    localStorage.setItem(PS_RESTART_KEY, ps);
    const r4 = await setGoform('PCIE_POWERSAVE_SWITCH', { wifi_pcie_powersave_enable: $('pcie-on').checked ? '1' : '0' });
    assertSuccess(r4, '保存 PCIe 省电');
    toast('省电设置已保存', true);
    loadPower();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function saveTsw() {
  const btn = $('tsw-save');
  btn.disabled = true;
  try {
    const wakeOn = $('webwake-on').checked ? '1' : '0';
    const sleepOn = $('websleep-on').checked ? '1' : '0';
    const data = { web_wake_switch: wakeOn, web_sleep_switch: sleepOn };
    if (wakeOn === '1') {
      data.web_wake_time = $('webwake-time').value || '07:00';
      data.web_sleep_time = $('websleep-time').value || '23:00';
    }
    const r1 = await setGoform('SAVE_TSW', data);
    assertSuccess(r1, '保存网页休眠');
    const tl = $('time-limited').value.trim();
    if (tl !== '') {
      const n = Number(tl);
      if (!Number.isInteger(n) || n < 0) { toast('限时上网必须是大于等于 0 的分钟数'); return; }
      const r2 = await setGoform('SAVE_TIME_LIMITED', { time_limited: String(n) });
      assertSuccess(r2, '保存限时上网');
    }
    toast('休眠 / 限时已保存', true);
    loadPower();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function saveThermal() {
  const btn = $('thermal-save');
  btn.disabled = true;
  try {
    const res = await setGoform('SET_THERMAL_CONTROL', {
      thermal_control_enable: $('thermal-on').checked ? '1' : '0',
      thermal_led_enable: $('thermal-led-on').checked ? '1' : '0'
    });
    assertSuccess(res, '保存温控');
    toast('温控已保存', true);
    loadPower();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function saveLed() {
  const btn = $('led-save');
  btn.disabled = true;
  try {
    const on = $('led-night-on').checked ? '1' : '0';
    const data = { night_mode_switch: on };
    if (on === '1') {
      data.night_mode_start_time = $('led-start').value || '22:00';
      data.night_mode_end_time = $('led-end').value || '07:00';
      data.night_mode_close_all_led = $('led-all-off').checked ? '1' : '0';
    }
    const res = await setGoform('SET_DEVICE_LED', data);
    assertSuccess(res, '保存夜间 LED');
    toast('夜间 LED 已保存', true);
    loadPower();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}

// ---------- IMS / 语音调试（v1.5.0，实机 service.js） ----------
async function loadIms() {
  try {
    await ensureLogin();
    const r = await getFields(['zte_voice_debug_ims_set', 'zte_voice_debug_voice_set', 'operate_mode']).catch(() => ({}));
    $('ims-on').checked = String(r.zte_voice_debug_ims_set) === '1';
    $('voice-on').checked = String(r.zte_voice_debug_voice_set) === '1';
    $('ims-cur').textContent = `IMS 调试 ${$('ims-on').checked ? '开' : '关'} · 语音调试 ${$('voice-on').checked ? '开' : '关'} · 运行模式 ${r.operate_mode || '—'}`;
  } catch (e) { /* 读不到不影响保存 */ }
}
async function saveIms() {
  const btn = $('ims-save');
  btn.disabled = true;
  try {
    const r1 = await setGoform('VOICE_DEBUG_IMS_SET', { zte_voice_debug_ims_set: $('ims-on').checked ? '1' : '0' });
    assertSuccess(r1, '保存 IMS 调试');
    const r2 = await setGoform('VOICE_DEBUG_VOICE_SET', { zte_voice_debug_voice_set: $('voice-on').checked ? '1' : '0' });
    assertSuccess(r2, '保存语音调试');
    toast('IMS / 语音调试已保存', true);
    loadIms();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}

// ---------- 网络切片（v1.5.0，实机 service.js：PPP_DIAL_MULTI_PDNS_PARAM_SET） ----------
// 只做 PDN3 / PDN4 的开关：读-改-写，MP_APN_config 等字段读回来原样带回，不改 APN 配置本身。
// MP_APN_config 的格式未在文件里出现，不提供编辑。
let sliceState = { mpApn3: '', mpApn4: '', vlanTmp: '', rule31: '', rule41: '' };
let sliceLoaded = false;
async function loadSlice() {
  try {
    await ensureLogin();
    const r = await getFields(['nssai_pdn3_switch', 'nssai_pdn4_switch', 'MP_APN_config3', 'MP_APN_config4', 'multi_vlan_pdns_map_tmp', 'multi_vlan_pdns_map_ip_rule_3_1', 'multi_vlan_pdns_map_ip_rule_4_1', 'multi_pdns_wan_ipaddr_3', 'multi_pdns_ipv6_wan_ipaddr_3', 'multi_pdns_wan_ipaddr_4', 'multi_pdns_ipv6_wan_ipaddr_4']).catch(() => ({}));
    sliceLoaded = r.nssai_pdn3_switch !== undefined || r.nssai_pdn4_switch !== undefined;
    sliceState = {
      mpApn3: r.MP_APN_config3 ?? '', mpApn4: r.MP_APN_config4 ?? '',
      vlanTmp: r.multi_vlan_pdns_map_tmp ?? '',
      rule31: r.multi_vlan_pdns_map_ip_rule_3_1 ?? '', rule41: r.multi_vlan_pdns_map_ip_rule_4_1 ?? ''
    };
    $('slice3-on').checked = String(r.nssai_pdn3_switch) === '1';
    $('slice4-on').checked = String(r.nssai_pdn4_switch) === '1';
    $('slice-cur').textContent = `PDN3 ${$('slice3-on').checked ? '开' : '关'}${r.multi_pdns_wan_ipaddr_3 ? `（${r.multi_pdns_wan_ipaddr_3}）` : ''} · PDN4 ${$('slice4-on').checked ? '开' : '关'}${r.multi_pdns_wan_ipaddr_4 ? `（${r.multi_pdns_wan_ipaddr_4}）` : ''}`;
  } catch (e) { /* 读不到不影响保存 */ }
}
async function saveSlice() {
  if (!sliceLoaded) { toast('切片当前配置没读到，请先刷新高级页再保存'); return; }
  const btn = $('slice-save');
  btn.disabled = true;
  try {
    const r1 = await setGoform('PPP_DIAL_MULTI_PDNS_PARAM_SET', {
      cid: '3', nssai_pdn_switch: $('slice3-on').checked ? '1' : '0',
      MP_APN_config: sliceState.mpApn3, multi_vlan_pdns_map_tmp: sliceState.vlanTmp,
      multi_vlan_pdns_map_ip_rule: sliceState.rule31
    });
    assertSuccess(r1, '保存切片 PDN3');
    const r2 = await setGoform('PPP_DIAL_MULTI_PDNS_PARAM_SET', {
      cid: '4', nssai_pdn_switch: $('slice4-on').checked ? '1' : '0',
      MP_APN_config: sliceState.mpApn4, multi_vlan_pdns_map_tmp: sliceState.vlanTmp,
      multi_vlan_pdns_map_ip_rule: sliceState.rule41
    });
    assertSuccess(r2, '保存切片 PDN4');
    toast('网络切片已保存', true);
    loadSlice();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}

// ---------- TR069（v1.5.0，实机 service.js：TR069_MODULE_SET / RESTORE_TR069_DEFAULT_PARA） ----------
// 完整配置的写（setTR069Configuration）是直通函数，goformId 在页面模块里，不做；
// 只做模块开关 + 恢复默认。
async function loadTr069() {
  try {
    await ensureLogin();
    const r = await getFields(['tr069_ReqURL', 'tr069_ServerURL', 'tr069_CPEPortNo', 'tr069_ServerUsername', 'tr069_ServerPassword', 'tr069_ConnectionRequestUname', 'tr069_ConnectionRequestPassword', 'wan_ipaddr', 'tr069_PeriodicInformEnable', 'tr069_PeriodicInformInterval', 'tr069_CertEnable', 'tr069_DataModule', 'tr069_Webui_DataModuleSupport', 'web_tr069_changed_flag']).catch(() => ({}));
    $('tr069-module-on').checked = String(r.tr069_DataModule) === '1';
    $('tr069-cur').textContent = `模块 ${$('tr069-module-on').checked ? '启用' : '关闭'} · 服务器 ${r.tr069_ServerURL || '—'} · 上报间隔 ${r.tr069_PeriodicInformInterval || '—'} 秒`;
  } catch (e) { /* 读不到不影响保存 */ }
}
async function saveTr069Module() {
  const btn = $('tr069-save');
  btn.disabled = true;
  try {
    const res = await setGoform('TR069_MODULE_SET', { tr069_DataModule: $('tr069-module-on').checked ? '1' : '0' });
    assertSuccess(res, '保存 TR069 模块');
    toast('TR069 模块已保存', true);
    loadTr069();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}
async function restoreTr069(btn) {
  if (!btn.dataset.armed) {
    btn.dataset.armed = '1';
    btn.textContent = '确认恢复 TR069 默认参数？';
    setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = '恢复 TR069 默认参数'; } }, 5000);
    return;
  }
  delete btn.dataset.armed;
  btn.textContent = '恢复 TR069 默认参数';
  btn.disabled = true;
  try {
    const res = await setGoform('RESTORE_TR069_DEFAULT_PARA', {});
    assertSuccess(res, '恢复 TR069 默认参数');
    toast('TR069 参数已恢复默认', true);
    loadTr069();
  } catch (e) { toast(`恢复失败：${e.message}`); }
  finally { btn.disabled = false; }
}

// ---------- 诊断（v1.5.0，实机 service.js：SIGNAL_QUALITY_DETECT_START） ----------
async function detectSignalQuality() {
  const btn = $('diag-detect');
  btn.disabled = true;
  btn.textContent = '检测中…';
  try {
    const res = await setGoform('SIGNAL_QUALITY_DETECT_START', {});
    assertSuccess(res, '信号质量检测');
    $('diag-detect-note').textContent = '信号质量检测已触发，结果体现在信号格和 RSRP/SINR 上（总览页看，稍等几秒刷新）。';
    toast('信号质量检测已触发', true);
    setTimeout(() => refreshAll(true), 3000);
  } catch (e) { toast(`检测失败：${e.message}`); }
  finally { btn.disabled = false; btn.textContent = '开始信号质量检测'; }
}
function loadAdvTemps() {
  const t = lastDash?.temperature || {};
  const pairs = [
    ['Wi-Fi 芯片', t.wifi_chip_temp], ['射频 PA', t.pm_sensor_pa1], ['Modem', t.pm_sensor_mdm],
    ['5G Modem', t.pm_modem_5g], ['CPU', pick(t, ['cpu_temp', 'cpu_temperature'])],
    ['SoC', t.soc_temp], ['主板', t.board_temp]
  ].filter(([, v]) => num(v) != null);
  $('adv-temps').innerHTML = pairs.length
    ? pairs.map(([k, v]) => `<div class="stat"><div class="k">${esc(k)}</div><div class="v">${esc(v)}<small> °C</small></div></div>`).join('')
    : '<div class="sub">设备未返回温度字段（总览页轮询时会更新）。</div>';
}
// ---------- MTU / MSS（v1.5.0，实机 service.js：SET_DEVICE_MTU） ----------
async function loadMtu() {
  try {
    await ensureLogin();
    const r = await getFields(['lan_ipaddr', 'lan_netmask', 'mac_address', 'dhcpEnabled', 'dhcpStart', 'dhcpEnd', 'dhcpLease_hour', 'mtu', 'tcp_mss']).catch(() => ({}));
    $('mtu-cur').textContent = `MTU ${r.mtu || '—'} · TCP MSS ${r.tcp_mss || '—'}`;
    if (r.mtu) $('mtu-val').value = r.mtu;
    if (r.tcp_mss) $('mss-val').value = r.tcp_mss;
  } catch (e) { /* 读不到不影响保存 */ }
}
async function saveMtu() {
  const mtu = Number($('mtu-val').value);
  const mss = Number($('mss-val').value);
  if (!Number.isInteger(mtu) || mtu < 576 || mtu > 1500) { toast('MTU 必须是 576–1500'); return; }
  if (!Number.isInteger(mss) || mss < 536 || mss > 1460) { toast('TCP MSS 必须是 536–1460'); return; }
  const btn = $('mtu-save');
  btn.disabled = true;
  try {
    const res = await setGoform('SET_DEVICE_MTU', { mtu: String(mtu), tcp_mss: String(mss) });
    assertSuccess(res, '保存 MTU / MSS');
    toast('MTU / MSS 已保存', true);
    loadMtu();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}

// ---------- 设置页扩展 ----------
// 改管理员密码：CHANGE_PASSWORD{ oldPassword: SHA256(旧), newPassword: SHA256(新) }
// （与登录同一套大写十六进制 SHA256）。成功后内存里的密码同步换成新的，
// 否则轮询的自动重登录会用旧密码失败。
async function changeAdminPassword(btn) {
  const oldPw = $('set-pw-old').value;
  const newPw = $('set-pw-new').value;
  const confirmPw = $('set-pw-confirm').value;
  if (!oldPw || !newPw || !confirmPw) { toast('三项都要填'); return; }
  if (newPw !== confirmPw) { toast('两次输入的新密码不一致'); return; }
  if (newPw === oldPw) { toast('新密码和当前密码一样'); return; }
  if (btn.dataset.armed) {
    delete btn.dataset.armed;
    btn.textContent = '修改密码';
    btn.disabled = true;
    try {
      const res = await setGoform('CHANGE_PASSWORD', { oldPassword: await sha256Hex(oldPw), newPassword: await sha256Hex(newPw) });
      assertSuccess(res, '修改管理员密码');
      password = newPw;
      $('set-pw-old').value = '';
      $('set-pw-new').value = '';
      $('set-pw-confirm').value = '';
      toast('管理员密码已修改，请记住新密码', true);
    } catch (e) { toast(`修改失败：${e.message}`); }
    finally { btn.disabled = false; }
    return;
  }
  btn.dataset.armed = '1';
  btn.textContent = '确认修改密码？';
  setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = '修改密码'; } }, 5000);
}
// 局域网 / DHCP：读 lan_ipaddr,lan_netmask,dhcpEnabled,dhcpStart,dhcpEnd,dhcpLease_hour；
// 写 DHCP_SETTING{ lanIp, lanNetmask, lanDhcpType, dhcpStart, dhcpEnd, dhcpLease,
//   dhcp_reboot_flag:'1', mac_ip_reset: 开启时 '1' / 关闭时 '0' }。
async function loadLanSettings() {
  try {
    await ensureLogin();
    const r = await getFields(['lan_ipaddr', 'lan_netmask', 'dhcpEnabled', 'dhcpStart', 'dhcpEnd', 'dhcpLease_hour', 'restart_schedule_switch', 'restart_time']).catch(() => ({}));
    $('lan-cur').textContent = `${r.lan_ipaddr || '—'} / ${r.lan_netmask || '—'} · DHCP ${r.dhcpEnabled === '1' ? `开启（${r.dhcpStart || '—'}–${r.dhcpEnd || '—'}，租期 ${String(r.dhcpLease_hour || '').replace('h', '') || '—'} 小时）` : '关闭'}`;
    if (r.lan_ipaddr) $('lan-ip').value = r.lan_ipaddr;
    if (r.lan_netmask) $('lan-mask').value = r.lan_netmask;
    $('lan-dhcp-type').value = r.dhcpEnabled === '1' ? 'SERVER' : 'DISABLE';
    if (r.dhcpStart) $('lan-dhcp-start').value = r.dhcpStart;
    if (r.dhcpEnd) $('lan-dhcp-end').value = r.dhcpEnd;
    if (r.dhcpLease_hour) $('lan-dhcp-lease').value = String(r.dhcpLease_hour).replace('h', '');
    $('reboot-sched-cur').textContent = r.restart_schedule_switch === '1' ? `已开启，每天 ${r.restart_time || '—'} 重启` : '未开启';
    $('reboot-sched-on').checked = r.restart_schedule_switch === '1';
    if (r.restart_time) $('reboot-sched-time').value = r.restart_time;
  } catch (e) { /* 读不到不影响其他设置 */ }
}
async function saveLanSettings(btn) {
  const lanIp = $('lan-ip').value.trim();
  const mask = $('lan-mask').value.trim();
  const type = $('lan-dhcp-type').value;
  const start = $('lan-dhcp-start').value.trim();
  const end = $('lan-dhcp-end').value.trim();
  const lease = $('lan-dhcp-lease').value.trim();
  if (!isValidIP(lanIp)) { toast('网关地址格式不正确'); return; }
  if (!isValidMask(mask)) { toast('子网掩码格式不正确'); return; }
  if (type === 'SERVER') {
    if (!isValidIP(start)) { toast('DHCP 起始地址格式不正确'); return; }
    if (!isValidIP(end)) { toast('DHCP 结束地址格式不正确'); return; }
    if (!sameSubnet(start, lanIp, mask)) { toast('DHCP 起始地址不在网关所在网段'); return; }
    if (!sameSubnet(end, lanIp, mask)) { toast('DHCP 结束地址不在网关所在网段'); return; }
    if (ipToInt(start) <= ipToInt(lanIp)) { toast('DHCP 起始地址必须大于网关地址'); return; }
    if (ipToInt(start) > ipToInt(end)) { toast('DHCP 起始地址不能大于结束地址'); return; }
    if (start === end) { toast('DHCP 起始和结束地址不能相同'); return; }
    if (!/^\d+$/.test(lease) || Number(lease) <= 0) { toast('DHCP 租期必须是大于 0 的小时数'); return; }
    const net = networkAddr(lanIp, mask), bc = broadcastAddr(lanIp, mask);
    if (lanIp === net || lanIp === bc) { toast('网关地址不能是网络地址或广播地址'); return; }
    if (start === net || start === bc || end === net || end === bc) { toast('DHCP 地址不能是网络地址或广播地址'); return; }
    const lanInt = ipToInt(lanIp);
    if (lanInt >= ipToInt(start) && lanInt <= ipToInt(end)) { toast('网关地址不能落在 DHCP 分配范围内'); return; }
  }
  if (btn.dataset.armed) {
    delete btn.dataset.armed;
    btn.textContent = '保存局域网设置';
    btn.disabled = true;
    try {
      const data = { lanIp, lanNetmask: mask, lanDhcpType: type, dhcpStart: type === 'SERVER' ? start : '', dhcpEnd: type === 'SERVER' ? end : '', dhcpLease: type === 'SERVER' ? lease : '', dhcp_reboot_flag: '1', mac_ip_reset: type === 'SERVER' ? '1' : '0' };
      const res = await setGoform('DHCP_SETTING', data);
      assertSuccess(res, '保存局域网设置');
      if (lanIp !== (lastDash?.status?.lan_ipaddr || '')) {
        const newUrl = `http://${lanIp}`;
        routerUrl = newUrl;
        localStorage.setItem('u50pro-router-url', newUrl);
        exitApp(`网关地址已改成 ${lanIp}，设备正在重启网络。请用新地址 ${newUrl} 重新登录（控制台本身的地址不变）。`);
      } else {
        toast('局域网设置已保存，网络正在重启', true);
        loadLanSettings();
      }
    } catch (e) { toast(`保存失败：${e.message}`); }
    finally { btn.disabled = false; }
    return;
  }
  btn.dataset.armed = '1';
  btn.textContent = '确认保存？网络会断开一次';
  setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = '保存局域网设置'; } }, 5000);
}
async function saveRebootSchedule() {
  const on = $('reboot-sched-on').checked;
  const time = $('reboot-sched-time').value;
  if (on && !/^\d{2}:\d{2}$/.test(time)) { toast('请先选一个重启时间'); return; }
  const btn = $('reboot-sched-save');
  btn.disabled = true;
  try {
    const res = await setGoform('RESTART_SCHEDULE_SETTING', { restart_schedule_switch: on ? '1' : '0', restart_time: time || '04:00' });
    assertSuccess(res, '保存定时重启');
    toast(on ? `定时重启已开启，每天 ${time} 重启` : '定时重启已关闭', true);
    loadLanSettings();
  } catch (e) { toast(`保存失败：${e.message}`); }
  finally { btn.disabled = false; }
}

// ---------- 设备控制 ----------
async function controlDevice(action, label) {
  try {
    await ensureLogin();
    const defs = {
      reboot: ['REBOOT_DEVICE', {}],
      shutdown: ['SHUTDOWN_DEVICE', {}],
      'wifi-on': ['SET_WIFI_INFO', { wifiEnabled: 1 }],
      'wifi-off': ['SET_WIFI_INFO', { wifiEnabled: 0 }]
    };
    if (!defs[action]) throw new Error('不支持的设备控制命令');
    const [goformId, values] = defs[action];
    const res = await setGoform(goformId, values);
    assertSuccess(res, label);
    toast(`${label}已执行`, true);
    if (action === 'wifi-on' || action === 'wifi-off') refreshAll(true);
    if (action === 'reboot' || action === 'shutdown') {
      stopPolling();
      $('conn-dot').className = 'dot off';
      $('conn-text').textContent = action === 'reboot' ? '设备正在重启…' : '设备已关闭';
    }
  } catch (e) { toast(`${label}失败：${e.message}`); }
}
// ---------- 恢复出厂设置（v1.5.0，实机 service.js：RESTORE_FACTORY_SETTINGS） ----------
// 恢复后设备会重启并清除配置；轮询 restore_flag 读到 "1" 即完成。
// RESULT_RESTORE 在文件里也有，但用途不明，恢复流程不用它。
async function factoryReset(btn) {
  if (!btn.dataset.armed) {
    btn.dataset.armed = '1';
    btn.textContent = '确认恢复出厂？所有设置都会被清除';
    setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = '恢复出厂设置'; } }, 5000);
    return;
  }
  delete btn.dataset.armed;
  btn.textContent = '恢复出厂设置';
  btn.disabled = true;
  try {
    const res = await setGoform('RESTORE_FACTORY_SETTINGS', {});
    assertSuccess(res, '恢复出厂设置');
    $('factory-reset-note').textContent = '恢复指令已发出，设备正在恢复…请勿断电，完成后需要重新登录。';
    for (let i = 0; i < 24; i++) {
      await sleep(5000);
      const r = await getFields(['restore_flag']).catch(() => ({}));
      if (String(r.restore_flag) === '1') break;
    }
    $('factory-reset-note').textContent = '恢复完成：设备将恢复到出厂状态（Wi-Fi 名称和密码都会变回贴纸上的默认），请重新登录。';
    toast('恢复出厂设置完成', true);
  } catch (e) {
    $('factory-reset-note').textContent = `恢复失败：${e.message}`;
    toast(`恢复失败：${e.message}`);
  } finally { btn.disabled = false; }
}

function armDanger(btn, label, action) {
  if (btn.dataset.armed) {
    delete btn.dataset.armed;
    btn.textContent = label;
    controlDevice(action, label);
    return;
  }
  btn.dataset.armed = '1';
  btn.textContent = `确认${label}？`;
  setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = label; } }, 5000);
}

// ---------- 轮询 ----------
function startPolling() {
  stopPolling();
  polling = true;
  pollTimer = setInterval(() => {
    if (!polling || !loggedIn || document.hidden) return;
    refreshAll(false);
  }, 2000);
}
function stopPolling() {
  polling = false;
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}
let refreshing = false;
async function refreshAll(manual) {
  if (!loggedIn || refreshing) return;
  refreshing = true;
  try {
    const d = await fetchDashboard();
    renderDashboard(d);
    if (manual) toast('已刷新', true);
  } catch (e) {
    if (manual) toast(`刷新失败：${e.message}`);
    if (/登录|会话|密码/.test(e.message)) exitApp(`会话已失效：${e.message}，请重新登录。`);
  } finally {
    refreshing = false;
  }
}

// ---------- 标签页 ----------
function switchPage(name) {
  document.querySelectorAll('.tab').forEach((t) => {
    const on = t.dataset.page === name;
    t.classList.toggle('active', on);
    // 手机上标签横滑时，把当前选中的滚到可见位置
    if (on) t.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
  });
  document.querySelectorAll('.page').forEach((p) => p.classList.toggle('active', p.id === `page-${name}`));
  window.scrollTo({ top: 0 });
  const loaders = { overview: fetchDashboard, sms: loadSms, devices: loadAcl, network: loadNetwork, wifi: loadWifi, security: loadSecurity, advanced: loadAdvanced, settings: loadLanSettings };
  if (loaders[name]) loaders[name]();
  // v1.5.0：QCI 页并进网络页（打开网络页时探一次），电池页并进总览（轮询里已画图）。
  if (name === 'network') probeQci();
}

// ---------- 事件 ----------
// ---------- 启动 ----------
// 包一层 bootU50Console()，因为注入器是在原厂页面 DOMContentLoaded 已触发
// 之后才把脚本加进来的，直接绑 DOMContentLoaded 永远不会触发。
// 直连模式下把路由器地址输入框锁死（地址固定为当前页面 origin，改不了）。
function bootU50Console() {
  if (DIRECT_MODE) {
    $('login-addr').value = routerUrl;
    $('login-addr').disabled = true;
    const setAddr = $('set-addr');
    if (setAddr) { setAddr.disabled = true; setAddr.value = routerUrl; }
    const setAddrSave = $('set-addr-save');
    if (setAddrSave) setAddrSave.disabled = true;
  } else {
    $('login-addr').value = routerUrl;
  }
  $('login-pass').addEventListener('input', scheduleAutoLogin);
  $('login-addr').addEventListener('input', scheduleAutoLogin);
  $('login-pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') doLogin(); });
  $('logout-btn').addEventListener('click', () => exitApp());
  $('refresh-btn').addEventListener('click', () => refreshAll(true));
  document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => switchPage(t.dataset.page)));
  document.addEventListener('visibilitychange', () => { if (!document.hidden && loggedIn) refreshAll(false); });
  // 流量
  $('tr-plan-edit').addEventListener('click', () => { $('tr-plan-form').hidden = false; $('tr-cal-form').hidden = true; });
  $('tr-cal-edit').addEventListener('click', () => { $('tr-cal-form').hidden = false; $('tr-plan-form').hidden = true; });
  $('tr-plan-cancel').addEventListener('click', () => { $('tr-plan-form').hidden = true; });
  $('tr-cal-cancel').addEventListener('click', () => { $('tr-cal-form').hidden = true; });
  $('tr-plan-save').addEventListener('click', saveTrafficPlan);
  $('tr-cal-save').addEventListener('click', saveCalibration);
  // 短信
  $('sms-refresh').addEventListener('click', loadSms);
  $('sms-send').addEventListener('click', sendSms);
  $('sms-body').addEventListener('input', () => { $('sms-count').textContent = String($('sms-body').value.length); });
  $('sms-filter').addEventListener('input', applySmsFilter);
  // 连接设备搜索
  $('dev-filter').addEventListener('input', applyDevFilter);
  // --- v1.3.0 短信：全部标为已读 ---
  $('sms-read-all').addEventListener('click', markAllSmsRead);
  // --- v1.3.0 网络页 ---
  $('net-mode-save').addEventListener('click', saveNetMode);
  $('net-data-toggle').addEventListener('click', toggleCellularData);
  $('net-roam-toggle').addEventListener('click', toggleRoam);
  $('apn-apply').addEventListener('click', applyApnMode);
  $('apn-add').addEventListener('click', () => openApnForm('add'));
  $('apn-edit').addEventListener('click', () => openApnForm('edit'));
  $('apn-del').addEventListener('click', (e) => deleteApn(e.currentTarget));
  $('apn-form-save').addEventListener('click', saveApnForm);
  $('apn-form-cancel').addEventListener('click', () => { $('apn-form').hidden = true; });
  $('apn-refresh').addEventListener('click', loadNetwork);
  $('wifi-refresh').addEventListener('click', loadWifi);
  $('band-lte-save').addEventListener('click', saveLteBands);
  $('band-nsa-save').addEventListener('click', () => saveNrBands('nsa'));
  $('band-sa-save').addEventListener('click', () => saveNrBands('sa'));
  $('band-lte-clear').addEventListener('click', () => clearBands('lte'));
  $('band-nsa-clear').addEventListener('click', () => clearBands('nsa'));
  $('band-sa-clear').addEventListener('click', () => clearBands('sa'));
  $('cell-scan').addEventListener('click', scanNeighbors);
  $('cell-filter').addEventListener('input', applyCellFilter);
  $('cell-rat').addEventListener('change', (e) => { $('cell-scs-wrap').style.display = e.target.value === 'NR' ? '' : 'none'; });
  $('cell-lock').addEventListener('click', lockSelectedCell);
  $('cell-unlock').addEventListener('click', unlockAllCells);
  // --- v1.3.0 Wi-Fi 页 ---
  $('wifi-ap').addEventListener('change', (e) => fillWifiForm(Number(e.target.value)));
  $('wifi-auth').addEventListener('change', (e) => { $('wifi-pass-wrap').style.display = e.target.value === 'OPEN' ? 'none' : ''; });
  $('wifi-save').addEventListener('click', saveWifi);
  $('wifi-sleep-save').addEventListener('click', saveWifiSleep);
  $('lbd-save').addEventListener('click', saveLbd);
  // --- v1.3.0 设置页：改密码 / 局域网 / 定时重启 ---
  $('set-pw-save').addEventListener('click', (e) => changeAdminPassword(e.currentTarget));
  $('lan-save').addEventListener('click', (e) => saveLanSettings(e.currentTarget));
  $('reboot-sched-save').addEventListener('click', saveRebootSchedule);
  // 总览快捷操作
  $('qa-sms').addEventListener('click', () => { switchPage('sms'); setTimeout(() => $('sms-to').focus(), 250); });
  $('qa-sms-inbox').addEventListener('click', () => switchPage('sms'));
  $('qa-refresh').addEventListener('click', () => refreshAll(true));
  $('qa-settings').addEventListener('click', () => switchPage('settings'));
  // 回到顶部
  const toTop = $('to-top');
  window.addEventListener('scroll', () => { toTop.hidden = window.scrollY < 400; }, { passive: true });
  toTop.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
  // 设置
  $('set-addr-save').addEventListener('click', () => {
    const addr = $('set-addr').value.trim();
    if (!addr) { toast('请先填路由器地址'); return; }
    routerUrl = addr.replace(/\/$/, '');
    localStorage.setItem('u50pro-router-url', routerUrl);
    exitApp('地址已保存，请重新登录。');
  });
  $('set-wifi-on').addEventListener('click', () => controlDevice('wifi-on', '开启 Wi-Fi'));
  $('set-wifi-off').addEventListener('click', () => controlDevice('wifi-off', '关闭 Wi-Fi'));
  $('set-reboot').addEventListener('click', (e) => armDanger(e.currentTarget, '重启设备', 'reboot'));
  $('set-shutdown').addEventListener('click', (e) => armDanger(e.currentTarget, '关闭设备', 'shutdown'));
  // --- v1.5.0 PIN / USSD / WPS / 短信中心 ---
  $('pin-enter-btn').addEventListener('click', enterPin);
  $('pin-change-btn').addEventListener('click', changePin);
  $('pin-disable-btn').addEventListener('click', (e) => disablePin(e.currentTarget));
  $('puk-btn').addEventListener('click', (e) => enterPuk(e.currentTarget));
  $('ussd-send').addEventListener('click', sendUssd);
  $('ussd-reply-btn').addEventListener('click', replyUssd);
  $('ussd-cancel').addEventListener('click', cancelUssd);
  $('wps-mode').addEventListener('change', (e) => { $('wps-pin-wrap').hidden = e.target.value !== 'PIN'; });
  $('wps-start').addEventListener('click', startWps);
  $('sms-set-save').addEventListener('click', saveSmsSettings);
  // --- v1.5.0 防火墙 / 白名单 ---
  $('fw-save').addEventListener('click', saveFirewall);
  $('pf-add').addEventListener('click', addPortFilter);
  $('fw-fwd-save').addEventListener('click', savePortForwardEnable);
  $('fwd-add').addEventListener('click', addPortForward);
  $('map-add').addEventListener('click', addPortMap);
  $('upnp-save').addEventListener('click', saveUpnp);
  $('dmz-save').addEventListener('click', saveDmz);
  $('sip-save').addEventListener('click', saveSip);
  $('fw-sys-save').addEventListener('click', saveFwSys);
  $('site-white-add').addEventListener('click', addWhiteSite);
  // --- v1.5.0 VPN / 升级 / 省电 / IMS / 切片 / TR069 / 诊断 / MTU ---
  $('vpn-type').addEventListener('change', syncVpnForm);
  $('vpn-ipsec-on').addEventListener('change', syncVpnForm);
  $('vpn-save').addEventListener('click', saveVpn);
  $('vpn-connect').addEventListener('click', connectVpn);
  $('vpn-disconnect').addEventListener('click', disconnectVpn);
  $('upg-check').addEventListener('click', checkUpgrade);
  $('upg-save').addEventListener('click', saveUpgradeAuto);
  $('power-save').addEventListener('click', savePower);
  $('tsw-save').addEventListener('click', saveTsw);
  $('thermal-save').addEventListener('click', saveThermal);
  $('led-save').addEventListener('click', saveLed);
  $('ims-save').addEventListener('click', saveIms);
  $('slice-save').addEventListener('click', saveSlice);
  $('tr069-save').addEventListener('click', saveTr069Module);
  $('tr069-restore').addEventListener('click', (e) => restoreTr069(e.currentTarget));
  $('diag-detect').addEventListener('click', detectSignalQuality);
  $('mtu-save').addEventListener('click', saveMtu);
  // --- v1.5.0 恢复出厂 ---
  $('set-factory-reset').addEventListener('click', (e) => factoryReset(e.currentTarget));
}

// 注入器在 DOMContentLoaded 已触发后才加脚本，所以不能只绑事件：
// 页面已经就绪就直接跑，还没就绪就等 DOMContentLoaded。
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bootU50Console);
else bootU50Console();
