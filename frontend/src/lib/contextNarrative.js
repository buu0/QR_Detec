/**
 * contextNarrative — builds a per-scan explanation from the REAL evidence returned by the backend.
 *
 * Nothing here is a fixed paragraph per alert code: every sentence is assembled from values found in
 * this specific result (host, decoded IDN characters, embedded redirect, IOC source and date, AI score
 * and top TreeSHAP factor, OCR context type, printed vs QR account/name/amount, Wi-Fi SSID, phone
 * number...). The backend remains the single source of truth for the risk level: this module never
 * derives, upgrades or downgrades `risk_level`; it only explains it.
 *
 * Output: { scenario, facts: string[], steps: string[] }
 */

// ─── Small display-only knowledge (used to explain, never to decide risk) ────────────────────────
const BRANDS = [
  { key: 'vietcombank', name: 'Vietcombank', domains: ['vietcombank.com.vn'], app: 'VCB Digibank' },
  { key: 'bidv', name: 'BIDV', domains: ['bidv.com.vn'], app: 'BIDV SmartBanking' },
  { key: 'techcombank', name: 'Techcombank', domains: ['techcombank.com', 'techcombank.com.vn'], app: 'Techcombank Mobile' },
  { key: 'vietinbank', name: 'VietinBank', domains: ['vietinbank.vn'], app: 'VietinBank iPay' },
  { key: 'agribank', name: 'Agribank', domains: ['agribank.com.vn'], app: 'Agribank Plus' },
  { key: 'mbbank', name: 'MB Bank', domains: ['mbbank.com.vn'], app: 'MB Bank' },
  { key: 'vpbank', name: 'VPBank', domains: ['vpbank.com.vn'], app: 'VPBank NEO' },
  { key: 'tpbank', name: 'TPBank', domains: ['tpb.vn', 'tpbank.vn'], app: 'TPBank Mobile' },
  { key: 'sacombank', name: 'Sacombank', domains: ['sacombank.com.vn'], app: 'Sacombank Pay' },
  { key: 'acb', name: 'ACB', domains: ['acb.com.vn'], app: 'ACB ONE' },
  { key: 'momo', name: 'Ví MoMo', domains: ['momo.vn'], app: 'MoMo' },
  { key: 'zalopay', name: 'ZaloPay', domains: ['zalopay.vn'], app: 'ZaloPay' },
  { key: 'shopee', name: 'Shopee', domains: ['shopee.vn', 'shopeefood.vn'], app: 'Shopee' },
  { key: 'lazada', name: 'Lazada', domains: ['lazada.vn'], app: 'Lazada' },
  { key: 'evn', name: 'Điện lực EVN', domains: ['evn.com.vn', 'evnhcmc.vn', 'evnhanoi.vn', 'evnspc.vn', 'evncpc.vn', 'evnnpc.vn'], app: 'EVNCSKH' },
  { key: 'csgt', name: 'Cục Cảnh sát giao thông', domains: ['csgt.vn'], app: 'VNeTraffic' },
  { key: 'dichvucong', name: 'Cổng Dịch vụ công', domains: ['dichvucong.gov.vn'], app: 'VNeID' },
  { key: 'vneid', name: 'VNeID', domains: ['vneid.gov.vn'], app: 'VNeID' },
  { key: 'paypal', name: 'PayPal', domains: ['paypal.com'], app: 'PayPal' },
  { key: 'facebook', name: 'Facebook', domains: ['facebook.com', 'fb.com'], app: 'Facebook' },
  { key: 'google', name: 'Google', domains: ['google.com', 'google.com.vn'], app: 'Google' },
  { key: 'grab', name: 'Grab', domains: ['grab.com', 'grab.vn'], app: 'Grab' },
];

const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.ly', 'rb.gy', 'shorturl.at', 'cutt.ly', 'is.gd', 's.id', 'tiny.cc', 'goo.gl', 'ow.ly', 'bitly.vn', 'urlr.me'];
const CHEAP_TLDS = ['top', 'xyz', 'click', 'icu', 'live', 'shop', 'online', 'site', 'buzz', 'cfd', 'sbs', 'rest', 'monster', 'cyou', 'vip', 'fun', 'lol', 'quest', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq'];

// [regex, plain meaning] — matched on the lower-cased host + path + query
const LURE_KEYWORDS = [
  [/(^|[^a-z])(login|signin|dang-?nhap)([^a-z]|$)/, 'đăng nhập'],
  [/(^|[^a-z])(verify|xac-?thuc|xac-?minh)/, 'xác thực tài khoản'],
  [/(^|[^a-z])otp([^a-z]|$)/, 'mã OTP'],
  [/(^|[^a-z])(update|cap-?nhat)/, 'cập nhật thông tin'],
  [/(sinh-?trac-?hoc|biometric|ekyc)/, 'sinh trắc học / eKYC'],
  [/(mo-?khoa|tam-?khoa|unlock|bi-?khoa)/, 'mở khóa tài khoản'],
  [/(nhan-?qua|trung-?thuong|tri-?an|qua-?tang|reward|gift)/, 'nhận quà / trúng thưởng'],
  [/(phat-?nguoi|nop-?phat|xu-?phat)/, 'nộp phạt'],
  [/(hoan-?tien|refund)/, 'hoàn tiền'],
  [/(tien-?dien|tien-?nuoc|hoa-?don)/, 'thanh toán hóa đơn'],
];

const CONFUSABLE = {
  'і': 'i', 'ı': 'i', 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'ԁ': 'd', 'ӏ': 'l', 'ѕ': 's', 'ј': 'j', 'һ': 'h', 'ԛ': 'q', 'ԝ': 'w', 'ɡ': 'g',
  'ä': 'a', 'á': 'a', 'à': 'a', 'â': 'a', 'ã': 'a', 'å': 'a', 'ë': 'e', 'é': 'e', 'è': 'e', 'ê': 'e',
  'ï': 'i', 'í': 'i', 'ì': 'i', 'ö': 'o', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'ü': 'u', 'ú': 'u', 'ù': 'u',
  'ν': 'v', 'ο': 'o', 'α': 'a', 'ρ': 'p', 'τ': 't', 'κ': 'k',
};

const CONTEXT_LABEL = {
  invoice: 'hóa đơn',
  donation: 'lời kêu gọi quyên góp / từ thiện',
  payment_info: 'biển thông tin thanh toán (standee)',
  general: 'ảnh có chữ nhưng không rõ là thông tin thanh toán',
  empty: 'ảnh chỉ có mã QR, không có chữ đi kèm',
};

// ─── Punycode (RFC 3492) decoder, display only ───────────────────────────────────────────────────
function adapt(delta, numPoints, firstTime) {
  let d = firstTime ? Math.floor(delta / 700) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > 455) { // ((36 - 1) * 26) >> 1
    d = Math.floor(d / 35);
    k += 36;
  }
  return k + Math.floor((36 * d) / (d + 38));
}

function punyDecodeLabel(input) {
  const output = [];
  let i = 0;
  let n = 128;
  let bias = 72;
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j += 1) {
    if (input.charCodeAt(j) >= 0x80) return null;
    output.push(input.charCodeAt(j));
  }
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
    const oldi = i;
    let w = 1;
    for (let k = 36; ; k += 36) {
      if (idx >= input.length) return null;
      const c = input.charCodeAt(idx);
      idx += 1;
      let digit = 36;
      if (c >= 48 && c <= 57) digit = c - 22;
      else if (c >= 65 && c <= 90) digit = c - 65;
      else if (c >= 97 && c <= 122) digit = c - 97;
      if (digit >= 36) return null;
      i += digit * w;
      const t = k <= bias ? 1 : (k >= bias + 26 ? 26 : k - bias);
      if (digit < t) break;
      w *= 36 - t;
    }
    const len = output.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    output.splice(i, 0, n);
    i += 1;
  }
  try {
    return String.fromCodePoint(...output);
  } catch {
    return null;
  }
}

export function decodeIdnHost(host) {
  const h = String(host || '').toLowerCase();
  if (!h.split('.').some((l) => l.startsWith('xn--'))) return h;
  return h
    .split('.')
    .map((label) => (label.startsWith('xn--') ? (punyDecodeLabel(label.slice(4)) ?? label) : label))
    .join('.');
}

function scriptName(cp) {
  if (cp >= 0x0400 && cp <= 0x04ff) return 'chữ Kirin (tiếng Nga)';
  if (cp >= 0x0370 && cp <= 0x03ff) return 'chữ Hy Lạp';
  if (cp >= 0x00c0 && cp <= 0x024f) return 'chữ Latin có dấu';
  return 'ký tự đặc biệt';
}

function nonAsciiChars(text) {
  const seen = new Map();
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp > 127 && !seen.has(ch)) seen.set(ch, cp);
  }
  return [...seen.entries()].map(([ch, cp]) => ({
    ch,
    code: `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`,
    script: scriptName(cp),
    looksLike: CONFUSABLE[ch] || null,
  }));
}

function skeleton(text) {
  return [...text].map((ch) => CONFUSABLE[ch] || ch).join('');
}

// ─── Generic helpers ────────────────────────────────────────────────────────────────────────────
function hostMatchesDomain(host, domain) {
  return host === domain || host.endsWith(`.${domain}`);
}

function findBrand(realHost, asciiHost) {
  const tokens = asciiHost.split(/[.-]/).filter(Boolean);
  for (const b of BRANDS) {
    // Official status is decided on the REAL (punycode) host, never on the look-alike skeleton.
    if (b.domains.some((d) => hostMatchesDomain(realHost, d))) return { brand: b, official: true };
  }
  for (const b of BRANDS) {
    const hit = b.key.length >= 5
      ? asciiHost.includes(b.key)
      : tokens.some((t) => t === b.key || t.startsWith(b.key));
    if (hit) return { brand: b, official: false };
  }
  return null;
}

function safeParseUrl(raw) {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function pct(v) {
  if (typeof v !== 'number' || !Number.isFinite(v)) return null;
  if (v >= 0.9995) return 'trên 99.9%';
  if (v > 0 && v < 0.0005) return 'dưới 0.1%';
  return `${(v * 100).toFixed(1)}%`;
}

function digitsToInt(v) {
  const n = Number.parseInt(String(v ?? '').replace(/[^\d]/g, ''), 10);
  return Number.isFinite(n) ? n : null;
}

function vnd(v) {
  const n = digitsToInt(v);
  return n == null ? null : `${n.toLocaleString('vi-VN')} đ`;
}

function uniq(list) {
  const seen = new Set();
  return list.filter((x) => x && !seen.has(x) && seen.add(x));
}

function reasonSet(result) {
  const raw = [...(result?.reason_codes || []), ...(result?.url_analysis?.reason_codes || [])];
  return new Set(raw.map((c) => String(c || '').toUpperCase()));
}

// ─── URL narrative ──────────────────────────────────────────────────────────────────────────────
function urlNarrative(result) {
  const ua = result?.url_analysis || {};
  const level = result?.risk_level;
  const reasons = reasonSet(result);
  const rawUrl = ua.original_url || result?.payload || '';
  const parsed = safeParseUrl(ua.normalized_url || rawUrl) || safeParseUrl(rawUrl);
  const host = String(ua.host || parsed?.hostname || '').toLowerCase();
  const decodedHost = decodeIdnHost(host);
  const asciiHost = skeleton(decodedHost);
  const scheme = String(ua.scheme || parsed?.protocol?.replace(':', '') || '').toLowerCase();
  const facts = [];
  const steps = [];
  const tags = new Set();
  let scenario = null;

  if (!host && scheme && !['http', 'https'].includes(scheme)) {
    facts.push(`Mã QR không mở trang web mà chạy lệnh dạng "${scheme}:" ngay trên trình duyệt hoặc ứng dụng.`);
    steps.push(`Không mở và không dán nội dung "${scheme}:..." vào trình duyệt; bỏ qua mã QR này.`);
    return { scenario: `Tình huống: mã QR chứa lệnh "${scheme}:"`, facts, steps };
  }

  // 1. Where does it really go?
  // The plain host is already shown in the URL block; only explain it when it LOOKS different.
  if (host && decodedHost !== host) {
    facts.push(`Tên miền hiện ra là "${decodedHost}" nhưng địa chỉ thật là "${host}".`);
  }
  if (scheme === 'http') {
    facts.push('Liên kết dùng http:// (không mã hóa): dữ liệu bạn nhập có thể bị đọc trộm trên đường truyền.');
    tags.add('http');
  }

  // 2. IDN / homograph characters, decoded from the real host
  if (decodedHost !== host) {
    const chars = nonAsciiChars(decodedHost);
    if (chars.length > 0) {
      const desc = chars
        .slice(0, 3)
        .map((c) => `"${c.ch}" (${c.code}, ${c.script}${c.looksLike ? `, nhìn giống chữ "${c.looksLike}"` : ''})`)
        .join(', ');
      facts.push(`Tên miền chứa ký tự ${desc}; mắt thường gần như không phân biệt được với chữ Latin.`);
      tags.add('idn');
    }
  }

  // 3. Brand mention vs official domain
  const brandHit = host ? findBrand(host, asciiHost) : null;
  if (brandHit && !brandHit.official) {
    const b = brandHit.brand;
    if (tags.has('idn')) {
      facts.push(`Tên miền được viết cho giống "${b.name}" nhưng thực chất là một tên miền khác, không phải ${b.domains.join(', ')}.`);
    } else if (level === 'no_known_risk') {
      facts.push(`Lưu ý: tên miền có chữ "${b.key}" gợi tới ${b.name} nhưng không phải tên miền chính thức (${b.domains.join(', ')}); hệ thống chưa có bằng chứng lừa đảo, bạn nên tự kiểm tra thêm.`);
    } else {
      facts.push(`Tên miền mượn tên "${b.name}" nhưng không thuộc tên miền chính thức (${b.domains.join(', ')}).`);
    }
    scenario = `Tình huống: liên kết mạo danh ${b.name}`;
    tags.add('brand_fake');
  } else if (brandHit && brandHit.official) {
    facts.push(`Tên miền thuộc trang chính thức của ${brandHit.brand.name} (${host}).`);
    tags.add('brand_official');
  }

  // 4. Structural tricks
  if (parsed?.username) {
    facts.push(`Phần "${safeDecode(parsed.username)}@" đứng trước tên miền chỉ để đánh lừa; trình duyệt thực ra mở "${host}".`);
    tags.add('userinfo');
  }
  if (parsed?.port) {
    facts.push(`Liên kết dùng cổng mạng lạ :${parsed.port}, trang web thông thường không cần ghi cổng.`);
  }
  if (reasons.has('PRIVATE_OR_LOCAL_HOST') || /^(127\.|10\.|192\.168\.|169\.254\.|localhost$)/.test(host)) {
    facts.push(`"${host}" là địa chỉ nội bộ / chính máy của bạn: mã QR dán nơi công cộng không có lý do gì để trỏ vào đây.`);
    tags.add('private');
  } else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    facts.push(`Liên kết dùng địa chỉ IP trần "${host}" thay vì tên miền, nên không thể biết ai sở hữu trang.`);
    tags.add('ip');
  }
  const shortener = SHORTENERS.find((d) => hostMatchesDomain(host, d));
  if (shortener) {
    facts.push(`Đây là liên kết rút gọn qua ${shortener}: trang đích thật bị giấu cho tới khi bạn bấm mở.`);
    tags.add('shortener');
  }
  const tld = host.includes('.') ? host.split('.').pop() : '';
  const aiExplainsTld = (ua.model?.shap_top_risk || []).some((it) => it.feature === 'is_suspicious_tld');
  if (CHEAP_TLDS.includes(tld) && !brandHit?.official && !aiExplainsTld) {
    facts.push(`Tên miền dùng đuôi ".${tld}", loại đuôi giá rẻ hay bị dùng để dựng trang lừa đảo tạm thời.`);
  }

  // 5. Lure words in host + path + query
  const lureText = `${asciiHost}${safeDecode(parsed ? parsed.pathname + parsed.search : '')}`.toLowerCase();
  const lures = uniq(LURE_KEYWORDS.filter(([re]) => re.test(lureText)).map(([, meaning]) => meaning));
  if (lures.length > 0) {
    facts.push(`Địa chỉ chứa từ khóa dụ dỗ: ${lures.map((l) => `"${l}"`).join(', ')}.`);
    tags.add('lure');
  }

  // 6. Embedded redirect
  const embedded = Array.isArray(ua.embedded_urls) ? ua.embedded_urls : [];
  if (embedded.length > 0) {
    const eHost = safeParseUrl(embedded[0])?.hostname || embedded[0];
    facts.push(`Bên trong liên kết có giấu địa chỉ chuyển tiếp tới "${eHost}"${brandHit?.official ? `, tức là trang thật ${brandHit.brand.name} bị lợi dụng làm bước đệm` : ''}.`);
    tags.add('redirect');
  }

  // 7. Local IOC evidence (source + date from provenance)
  const ti = ua.threat_intel || {};
  const tiStatus = String(ti.local_ti_status || '').toUpperCase();
  if (tiStatus === 'MATCH') {
    const prov = Array.isArray(ti.provenance) ? ti.provenance[0] : null;
    const src = (ti.sources || []).join(', ') || prov?.source || 'danh sách lừa đảo cục bộ';
    const what = ti.scope === 'ioc_embedded' ? 'Địa chỉ chuyển tiếp ẩn' : 'Địa chỉ này';
    const stale = ti.freshness === 'stale' ? ' (bản ghi đã cũ, chưa được xác nhận lại)' : '';
    facts.push(`${what} có trong danh sách lừa đảo "${src}"${stale} (chi tiết ở thẻ Local IOC).`);
    tags.add('ioc');
  }

  // 8. AI model + how it combined with the IOC layer (one sentence)
  const m = ua.model || {};
  if (m.model_status === 'READY' && typeof m.model_score === 'number') {
    const ai = `mô hình AI chấm mức nghi ngờ ${pct(m.model_score)} (ngưỡng cảnh báo ${pct(m.ml_threshold)})`;
    const structural = tags.has('private') || tags.has('ip') || tags.has('userinfo') || reasons.has('OBFUSCATED_HOST');
    if (tags.has('ioc') && m.ml_prediction === 0) {
      facts.push(`Riêng ${ai} chưa đủ để cảnh báo vì liên kết trông giống trang thật; danh sách lừa đảo mới là lớp bắt được, nên hệ thống cần cả hai lớp.`);
    } else if (tiStatus === 'NO_MATCH' && m.ml_prediction === 1 && !structural) {
      facts.push(`Địa chỉ chưa có trong danh sách lừa đảo đã biết (có thể là trang mới dựng), nhưng ${ai}, nên vẫn bị cảnh báo.`);
    } else if (!tags.has('ioc')) {
      const head = tiStatus === 'NO_MATCH' ? 'Địa chỉ chưa có trong danh sách lừa đảo đã biết; ' : '';
      const s = `${head}${ai}.`;
      facts.push(s.charAt(0).toUpperCase() + s.slice(1));
    }
  } else if (tiStatus === 'NO_MATCH' && level !== 'no_known_risk') {
    facts.push('Địa chỉ chưa có trong danh sách lừa đảo đã biết.');
  }

  // ─── Steps derived from the facts above (values plugged in) ───
  const b = brandHit?.brand;
  if (tags.has('brand_fake') || tags.has('idn')) {
    if (b) steps.push(`Cần giao dịch với ${b.name}? Mở ứng dụng ${b.app} hoặc tự gõ ${b.domains[0]}, không đi qua mã QR này.`);
    else steps.push('Tự gõ tên miền chính thức vào trình duyệt thay vì mở liên kết trong mã QR.');
  }
  if (tags.has('lure')) {
    steps.push(`Không thực hiện ${lures.join(', ')} trên trang mở từ mã QR này; tổ chức uy tín hiếm khi yêu cầu việc đó qua mã QR dán ngoài.`);
  }
  if (tags.has('redirect')) {
    steps.push('Đừng tin vì phần đầu liên kết là tên miền quen thuộc; hãy nhìn phần địa chỉ chuyển tiếp phía sau.');
  }
  if (tags.has('ioc')) {
    steps.push('Chụp lại mã QR và báo cho chủ địa điểm / quản trị viên để gỡ bỏ, tránh người khác bị lừa.');
  }
  if ((tags.has('brand_fake') || tags.has('ioc') || tags.has('lure')) && (level === 'danger' || level === 'warning')) {
    steps.push(`Nếu đã lỡ nhập thông tin: đổi mật khẩu ngay và gọi tổng đài ${b ? b.name : 'của tổ chức'} (số in ở mặt sau thẻ hoặc trên website chính thức) để khóa giao dịch.`);
  }
  if (tags.has('private')) steps.push('Không mở liên kết; báo cho người phụ trách vì đây có thể là mã QR thử tấn công mạng nội bộ.');
  if (tags.has('shortener')) steps.push('Chỉ mở nếu biết rõ người tạo mã; sau khi trang hiện ra, kiểm tra lại tên miền trên thanh địa chỉ.');
  if (tags.has('http') && !tags.has('brand_fake')) steps.push('Không nhập mật khẩu hay thông tin thẻ trên trang http:// không mã hóa.');
  if (tags.has('userinfo')) steps.push(`Đọc tên miền ở ngay sau dấu @ ("${host}"), đó mới là trang thật sẽ mở.`);
  if (level === 'no_known_risk' && tags.has('brand_official')) {
    steps.push(`Sau khi mở, kiểm tra thanh địa chỉ vẫn là "${host}" và có biểu tượng khóa trước khi đăng nhập.`);
  }

  if (!scenario) {
    if (tags.has('ioc')) scenario = 'Tình huống: liên kết nằm trong danh sách lừa đảo';
    else if (tags.has('redirect')) scenario = 'Tình huống: liên kết chuyển tiếp ẩn';
    else if (tags.has('private')) scenario = 'Tình huống: mã QR trỏ vào mạng nội bộ';
    else if (tags.has('shortener')) scenario = 'Tình huống: liên kết rút gọn';
    else if (host) scenario = `Tình huống: mã QR mở trang ${decodedHost}`;
  }
  return { scenario, facts, steps };
}

// ─── VietQR narrative ───────────────────────────────────────────────────────────────────────────
function rowOf(result, field) {
  return (result?.match_result?.checks || []).find((c) => c.field === field) || null;
}

function vietqrNarrative(result) {
  const v = result?.vietqr_data || {};
  const ocr = result?.ocr_data || {};
  const code = String(result?.alert_code || '').toUpperCase();
  const ctxType = ocr.context_type || 'empty';
  const ctxLabel = CONTEXT_LABEL[ctxType] || 'ảnh';
  const facts = [];
  const steps = [];

  if (!v.account_name && v.account_number) {
    facts.push('Mã QR không mang tên người nhận; chỉ ứng dụng ngân hàng mới hiện tên chủ tài khoản thật khi bạn quét.');
  }

  if (code === 'INVALID_PAYLOAD') {
    if (v.crc_valid === false) facts.push('Mã kiểm tra CRC-16 không khớp: dữ liệu trong mã QR đã bị sửa sau khi tạo.');
    if (Array.isArray(v.structure_errors) && v.structure_errors.length > 0) {
      facts.push(`Lỗi cấu trúc phát hiện: ${v.structure_errors.join(', ')}.`);
    }
    steps.push('Không dùng mã này; xin người nhận gửi lại mã QR tạo trực tiếp từ ứng dụng ngân hàng của họ.');
    return { scenario: 'Tình huống: mã VietQR bị lỗi hoặc bị chỉnh sửa cấu trúc', facts, steps };
  }

  // What the picture says
  const amountRow = rowOf(result, 'amount');
  const printed = [
    ocr.bank_names?.[0] || null,
    ocr.account_numbers?.[0] ? `STK ${ocr.account_numbers[0]}` : null,
    ocr.account_name || null,
    amountRow?.context_value || null,
  ].filter(Boolean);
  if (ctxType !== 'empty' && ctxType !== 'skipped') {
    if (printed.length === 0) facts.unshift(`Ảnh được nhận diện là ${ctxLabel} nhưng không đọc được thông tin thanh toán nào.`);
  } else {
    facts.push(`Đây là ${CONTEXT_LABEL.empty}, nên không có gì để đối chiếu với mã QR.`);
  }

  // Field-by-field comparison from backend rows
  const acc = rowOf(result, 'account');
  const bank = rowOf(result, 'bank');
  const name = rowOf(result, 'name');
  const amount = rowOf(result, 'amount');
  if (acc?.status === 'mismatch' && acc.context_value && acc.qr_value) {
    facts.push(`Số tài khoản lệch: chữ in ghi ${acc.context_value} nhưng mã QR chuyển tới ${acc.qr_value}.`);
  } else if (acc?.status === 'conflict') {
    facts.push(`Ảnh có nhiều số tài khoản khác nhau, trong khi mã QR chỉ chuyển tới ${acc.qr_value}.`);
  } else if (acc?.status === 'match') {
    facts.push(`Số tài khoản ${acc.qr_value} trùng giữa chữ in và mã QR.`);
  }
  if (bank?.status === 'mismatch' && bank.context_value && bank.qr_value) {
    const sameAcc = acc?.status === 'match';
    facts.push(`Ngân hàng lệch: chữ in ghi ${bank.context_value} nhưng mã QR thuộc ${bank.qr_value}${sameAcc ? '; cùng dãy số ở hai ngân hàng là hai tài khoản khác nhau' : ''}.`);
  }
  if (name?.status === 'mismatch' && name.context_value && name.qr_value) {
    facts.push(`Tên người nhận lệch: chữ in là "${name.context_value}", mã QR là "${name.qr_value}".`);
  }
  if (amount?.status === 'mismatch' && amount.qr_value) {
    const q = digitsToInt(amount.qr_value);
    const c = digitsToInt(amount.context_value);
    const ratio = q && c && q > c && q % c === 0 ? ` (gấp ${q / c} lần)` : '';
    facts.push(amount.context_value
      ? `Số tiền lệch: chữ in ghi ${amount.context_value} nhưng mã QR đòi ${amount.qr_value}${ratio}.`
      : `Mã QR đặt sẵn ${amount.qr_value} nhưng con số này không xuất hiện trên ảnh.`);
  }
  if (v.amount && (!amount || amount.status === 'unknown' || amount.status === 'na')) {
    facts.push(`Chưa đối chiếu được số tiền: mã QR đặt sẵn ${vnd(v.amount)} nhưng hệ thống chưa đọc được con số tương ứng trên ảnh.`);
  }
  if (Array.isArray(result?.reason_codes) && result.reason_codes.includes('PDF_HIDDEN_TEXT')) {
    facts.push('Tệp PDF có chữ bị giấu (chữ trắng / cỡ siêu nhỏ); phần chữ này đã bị loại khi đối chiếu.');
  }

  // Steps with real values
  const ctxAcc = acc?.context_value || ocr.account_numbers?.[0];
  const ctxBank = bank?.context_value || ocr.bank_names?.[0];
  const ctxName = ocr.account_name || name?.context_value;
  const matchedName = name && (name.status === 'match' || name.status === 'near') ? name.qr_value : null;
  if (code === 'CRITICAL_MISMATCH' || code === 'PARTIAL_MATCH') {
    steps.push('Kiểm tra xem mã QR có bị dán đè lên mã gốc hoặc bị in lại không.');
    const recipientWrong = [acc, bank, name].some((r) => r && (r.status === 'mismatch' || r.status === 'conflict'));
    if (ctxAcc && recipientWrong) {
      steps.push(`Nếu vẫn cần trả tiền, gọi hỏi lại ${ctxName ? `"${ctxName}"` : 'người nhận'} rồi tự nhập STK ${ctxAcc}${ctxBank ? ` (${ctxBank})` : ''}, xem tên hiện ra có đúng không.`);
    }
    if (amount?.status === 'mismatch' && amount.context_value) {
      steps.push(`Tự nhập số tiền ${amount.context_value} theo ${ctxLabel}, không dùng số tiền ${amount.qr_value} điền sẵn.`);
    }
    if (ctxType === 'donation') {
      steps.push('Tài khoản quyên góp chính thức thường đứng tên tổ chức; tra số tài khoản trên website / fanpage chính thức của tổ chức trước khi ủng hộ.');
    }
  } else if (code === 'CONTEXT_CONSISTENT') {
    steps.push(`Khi ứng dụng ngân hàng hiện tên chủ tài khoản, so với ${matchedName ? `"${matchedName}"` : 'người / cửa hàng bạn định trả tiền'} trước khi bấm chuyển.`);
    if (ctxType === 'invoice' && v.amount) steps.push(`Tự so ${vnd(v.amount)} trong mã QR với dòng "Tổng cộng" trên hóa đơn trước khi xác nhận.`);
  } else if (code === 'INSUFFICIENT_CONTEXT') {
    const where = [v.account_number ? `STK ${v.account_number}` : 'tài khoản này', v.bank_name ? `tại ${v.bank_name}` : null].filter(Boolean).join(' ');
    steps.push(`Hỏi trực tiếp người nhận tên chủ tài khoản, rồi xem ứng dụng có hiện đúng tên đó cho ${where} không.`);
    steps.push('Nếu mã được dán ở cửa hàng, chụp lại góc rộng để thấy cả biển tên và số tài khoản in bên cạnh.');
  }

  let scenario = 'Tình huống: mã QR chuyển tiền VietQR';
  if (ctxType === 'invoice') scenario = 'Tình huống: hóa đơn kèm mã VietQR';
  else if (ctxType === 'donation') scenario = 'Tình huống: lời kêu gọi quyên góp kèm mã VietQR';
  else if (ctxType === 'payment_info') scenario = 'Tình huống: biển thanh toán tại quầy / cửa hàng';
  return { scenario, facts, steps };
}

// ─── Non-web URI / text narrative (tel, sms, mailto, Wi-Fi, plain text) ─────────────────────────
function otherNarrative(result) {
  const payload = String(result?.payload || '');
  const low = payload.toLowerCase();
  const facts = [];
  const steps = [];

  if (low.startsWith('wifi:')) {
    const get = (k) => (payload.match(new RegExp(`${k}:((?:\\\\;|[^;])*)`, 'i')) || [])[1]?.replace(/\\;/g, ';') || '';
    const ssid = get('S');
    const sec = get('T').toUpperCase();
    const open = !sec || sec === 'NOPASS';
    facts.push(`Tên mạng: "${ssid || '(không tên)'}"${open ? ', mạng mở không mật khẩu' : `, bảo mật ${sec}`}.`);
    if (open) facts.push('Trên Wi-Fi mở, bất kỳ ai cùng mạng đều có thể theo dõi lưu lượng, và mạng có thể do kẻ gian phát giả.');
    steps.push(`Chỉ kết nối nếu "${ssid}" đúng là Wi-Fi do chủ địa điểm cung cấp (hỏi nhân viên).`);
    steps.push('Không đăng nhập ngân hàng / ví điện tử khi đang dùng Wi-Fi công cộng; chuyển sang dữ liệu di động.');
    return { scenario: 'Tình huống: mã QR kết nối Wi-Fi', facts, steps };
  }

  if (low.startsWith('tel:')) {
    const num = payload.slice(4).trim();
    facts.push(`Số sẽ được gọi: ${num}.`);
    if (/^\+?\d{3,5}$/.test(num.replace(/[\s.-]/g, ''))) facts.push(`${num} là đầu số ngắn, có thể là đầu số dịch vụ tính cước cao.`);
    steps.push(`Tra số ${num} trên website chính thức của tổ chức trước khi gọi; tổng đài thật không hỏi mật khẩu hay OTP.`);
    return { scenario: 'Tình huống: mã QR gọi điện', facts, steps };
  }

  if (low.startsWith('smsto:') || low.startsWith('sms:')) {
    const body = payload.replace(/^smsto:|^sms:/i, '');
    const [num, ...rest] = body.split(/[:?]/);
    const text = safeDecode(rest.join(':').replace(/^body=/i, ''));
    facts.push(`Gửi tới số ${num}${text ? `, nội dung soạn sẵn: "${text}"` : ''}.`);
    if (/^\d{3,5}$/.test(num)) facts.push(`${num} là đầu số ngắn: tin nhắn tới đầu số này có thể bị trừ tiền hoặc đăng ký dịch vụ.`);
    if (/(otp|mk|mat ?khau|pass)/i.test(text)) facts.push('Nội dung tin nhắn liên quan tới mật khẩu / OTP, đây là dấu hiệu lừa chiếm tài khoản.');
    steps.push(`Đọc kỹ nội dung "${text || '(trống)'}" trước khi bấm gửi; không gửi nếu không hiểu tin nhắn dùng để làm gì.`);
    return { scenario: 'Tình huống: mã QR gửi tin nhắn', facts, steps };
  }

  if (low.startsWith('mailto:')) {
    const addr = payload.slice(7).split('?')[0];
    facts.push(`Email sẽ gửi tới: ${addr}.`);
    steps.push(`Kiểm tra ${addr} có đúng là địa chỉ chính thức không; không đính kèm giấy tờ tùy thân.`);
    return { scenario: 'Tình huống: mã QR gửi email', facts, steps };
  }

  if (payload) {
    if (/\b\d{9,19}\b/.test(payload) && /(chuyen|ck|stk|tai khoan|chuyển|tài khoản)/i.test(payload)) {
      facts.push('Văn bản chứa số tài khoản kèm lời nhắn chuyển tiền nhưng không phải mã VietQR chuẩn, nên không có cấu trúc để kiểm tra.');
      steps.push('Không chuyển tiền theo văn bản tự do; yêu cầu người nhận gửi mã VietQR tạo từ ứng dụng ngân hàng.');
    }
  }
  return { scenario: null, facts, steps };
}

/**
 * Main entry. Returns null for provisional/pending results (evidence not complete yet).
 */
export function buildContextNarrative(result) {
  if (!result || result.is_provisional) return null;
  const type = String(result.payload_type || '').toLowerCase();
  const scheme = String(result.url_analysis?.scheme || '').toLowerCase();
  const isNonWebAppUri = /^(wifi|tel|sms|smsto|mailto|mecard|begin:vcard|geo):?/i.test(String(result.payload || '').trim());
  let out;
  if (type === 'vietqr') out = vietqrNarrative(result);
  else if (isNonWebAppUri) out = otherNarrative(result);
  else if ((type === 'url' || type === 'uri') && result.url_analysis && (scheme === 'http' || scheme === 'https' || scheme)) out = urlNarrative(result);
  else out = otherNarrative(result);
  return {
    scenario: out.scenario || null,
    facts: uniq(out.facts).slice(0, 8),
    steps: uniq(out.steps).slice(0, 5),
  };
}
