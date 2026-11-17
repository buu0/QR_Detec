/**
 * iocDetails — plain-language description of a Local IOC match, taken from backend provenance.
 * Display only: it never changes the verdict.
 */

const SOURCE_INFO = {
  'phishing.database': 'Danh sách tên miền lừa đảo đang hoạt động do cộng đồng bảo mật duy trì (mã nguồn mở).',
  'urlhaus (abuse.ch)': 'Cơ sở dữ liệu liên kết phát tán mã độc của tổ chức abuse.ch (Thụy Sĩ).',
  cert_polska: 'Danh sách cảnh báo tên miền lừa đảo của CERT Polska (NASK, Ba Lan).',
  chongluadao_vn: 'Dữ liệu cảnh báo lừa đảo của cộng đồng Chống Lừa Đảo / NCSC Việt Nam.',
  'local ioc': 'Danh sách chỉ báo lừa đảo cục bộ của hệ thống.',
};

const TYPE_LABEL = {
  phishing_domain: 'Tên miền lừa đảo (phishing)',
  phishing_url: 'Liên kết lừa đảo (phishing)',
  malware_url: 'Liên kết phát tán mã độc',
  abused_legitimate_service: 'Dịch vụ hợp pháp bị lợi dụng để lừa đảo',
};

const VERDICT_LABEL = {
  known_malicious: 'Đã bị ghi nhận là độc hại',
  suspicious: 'Bị ghi nhận là nghi vấn',
};

function dateVi(iso) {
  if (!iso) return null;
  const m = String(iso).match(/^(\d{4})-(\d{2})-(\d{2})/);
  return m ? `${m[3]}/${m[2]}/${m[1]}` : null;
}

function matchWhere(ti, host, embeddedHost) {
  const d = String(ti?.details || '');
  if (ti?.scope === 'ioc_embedded') return `Địa chỉ chuyển tiếp ẩn trong liên kết${embeddedHost ? ` (${embeddedHost})` : ''}`;
  if (/^Exact URL/i.test(d)) return 'Trùng khớp chính xác toàn bộ địa chỉ liên kết';
  if (/^Parent domain/i.test(d)) return `Tên miền gốc của "${host}"`;
  if (/^Domain/i.test(d)) return `Tên miền "${host}"`;
  return host ? `Địa chỉ "${host}"` : 'Địa chỉ trong mã QR';
}

/**
 * Returns null unless the backend reported a Local IOC match.
 * { where, freshness, checkedAt, distinctSources, records: [{ source, about, type, verdict, firstSeen, lastSeen, expires, confidence, stale }] }
 */
export function formatIocDetails(urlAnalysis) {
  const ti = urlAnalysis?.threat_intel;
  if (!ti || String(ti.local_ti_status || '').toUpperCase() !== 'MATCH') return null;
  let embeddedHost = '';
  const first = Array.isArray(urlAnalysis?.embedded_urls) ? urlAnalysis.embedded_urls[0] : null;
  if (first) {
    try {
      embeddedHost = new URL(first).hostname;
    } catch {
      embeddedHost = '';
    }
  }
  const prov = Array.isArray(ti.provenance) && ti.provenance.length > 0
    ? ti.provenance
    : (ti.sources || []).map((s) => ({ source: s }));
  const records = prov.map((p) => {
    const key = String(p.source || 'Local IOC').trim().toLowerCase();
    return {
      source: p.source || 'Local IOC',
      about: SOURCE_INFO[key] || null,
      type: TYPE_LABEL[p.indicator_type] || (p.indicator_type ? String(p.indicator_type) : null),
      verdict: VERDICT_LABEL[p.verdict] || null,
      firstSeen: dateVi(p.first_seen),
      lastSeen: dateVi(p.last_seen),
      expires: dateVi(p.expires_at),
      confidence: typeof p.confidence === 'number' && Number.isFinite(p.confidence) ? `${Math.round(p.confidence * 100)}%` : null,
      stale: !!p.stale,
    };
  });
  return {
    where: matchWhere(ti, urlAnalysis?.host || '', embeddedHost),
    freshness: ti.freshness === 'stale'
      ? 'Dữ liệu cũ (quá 90 ngày chưa được ghi nhận lại)'
      : ti.freshness === 'fresh' ? 'Còn hiệu lực (được ghi nhận trong 90 ngày gần đây)' : null,
    checkedAt: dateVi(ti.last_checked),
    distinctSources: ti.distinct_sources || records.length,
    records,
  };
}
