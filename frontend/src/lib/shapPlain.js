/**
 * shapPlain — turns TreeSHAP contributions into everyday Vietnamese for non-technical users.
 *
 * Every sentence describes what the AI saw in THIS link (with real values such as the TLD or the
 * number of hyphens) and whether it made the AI more or less suspicious. No log-odds, no feature
 * names, no "base value". The exact numbers stay available in the technical drawer.
 */

const n = (v) => (typeof v === 'number' && Number.isFinite(v) ? Math.round(v) : null);

function keywordSentence(kind) {
  return {
    risk: (v) => `Liên kết có ${n(v) > 1 ? `${n(v)} từ` : 'từ'} ${kind}, kiểu chữ hay gặp ở trang lừa đảo.`,
    benign: () => `Liên kết không có từ ${kind}.`,
  };
}

const UNICODE_TRICK = {
  risk: () => 'Tên miền dùng chữ cái của bảng chữ khác (ví dụ chữ Nga) trông giống hệt chữ thường để giả mạo.',
  benign: () => 'Tên miền chỉ dùng chữ cái thông thường, không có chữ lạ giả mạo.',
};
const ENCODED = {
  risk: () => 'Một phần liên kết bị mã hóa thành ký hiệu (%xx) khiến người đọc khó nhận ra nội dung.',
  benign: () => 'Liên kết không bị mã hóa thành ký hiệu khó đọc.',
};
const PARAMS = {
  risk: () => 'Liên kết kèm nhiều tham số (dấu =, ?, &), thường dùng để mang theo mã theo dõi hoặc địa chỉ chuyển tiếp.',
  benign: () => 'Liên kết không kèm nhiều tham số phía sau.',
};
const RANDOM = {
  risk: () => 'Liên kết có chuỗi ký tự lộn xộn, trông như được tạo ngẫu nhiên.',
  benign: () => 'Chữ trong liên kết đọc được, không lộn xộn như chuỗi ngẫu nhiên.',
};
const WORDS = {
  risk: () => 'Các từ trong liên kết có độ dài bất thường so với trang web bình thường.',
  benign: () => 'Các từ trong liên kết có độ dài tự nhiên.',
};
const BRAND_MENTION = {
  risk: () => 'Liên kết có nhắc tên một ngân hàng hoặc thương hiệu quen thuộc.',
  benign: () => 'Tên thương hiệu nằm đúng chỗ của tên miền chính.',
};

const RULES = {
  is_suspicious_tld: {
    risk: (v, c) => `Tên miền dùng đuôi "${c.tld}", loại đuôi hay gặp ở các trang lừa đảo.`,
    benign: (v, c) => `Đuôi tên miền "${c.tld}" ít khi bị dùng cho trang lừa đảo.`,
  },
  tld_len: {
    risk: (v, c) => `Đuôi tên miền "${c.tld}" không thuộc nhóm phổ biến.`,
    benign: (v, c) => `Đuôi tên miền "${c.tld}" thuộc nhóm phổ biến.`,
  },
  hostname_len: {
    risk: (v) => `Tên miền khá dài (${n(v)} ký tự); trang giả hay ghép nhiều chữ quen thuộc vào tên miền.`,
    benign: (v) => `Tên miền ngắn gọn (${n(v)} ký tự).`,
  },
  url_len: {
    risk: (v) => `Cả liên kết dài bất thường (${n(v)} ký tự).`,
    benign: () => 'Liên kết có độ dài bình thường.',
  },
  path_len: {
    risk: () => 'Phần phía sau tên miền dài, có thể dùng để giấu thông tin.',
    benign: () => 'Phần phía sau tên miền ngắn gọn.',
  },
  query_len: {
    risk: () => 'Phần tham số phía sau dấu "?" dài bất thường.',
    benign: () => 'Phần tham số phía sau không dài bất thường.',
  },
  fragment_len: {
    risk: () => 'Liên kết có đoạn đuôi sau dấu "#" dài bất thường.',
    benign: () => 'Liên kết không có đoạn đuôi "#" bất thường.',
  },
  n_hyphens_host: {
    risk: (v) => `Tên miền ghép chữ bằng ${n(v)} dấu gạch ngang (kiểu "nganhang-xacthuc"), cách đặt tên hay gặp ở trang giả.`,
    benign: () => 'Tên miền không ghép chữ bằng dấu gạch ngang.',
  },
  n_hyphens_url: {
    risk: (v) => `Liên kết có ${n(v)} dấu gạch ngang nối các từ.`,
    benign: () => 'Liên kết ít dấu gạch ngang.',
  },
  n_digits_host: {
    risk: (v) => `Tên miền chứa ${n(v)} chữ số xen giữa chữ cái.`,
    benign: () => 'Tên miền không chứa chữ số lạ.',
  },
  ratio_digits_url: {
    risk: () => 'Liên kết có nhiều chữ số hơn bình thường.',
    benign: () => 'Liên kết không có nhiều chữ số.',
  },
  ratio_letters_url: {
    risk: () => 'Tỉ lệ chữ cái trong liên kết bất thường.',
    benign: () => 'Liên kết chủ yếu là chữ cái đọc được.',
  },
  ratio_special_url: {
    risk: () => 'Liên kết có nhiều ký hiệu đặc biệt.',
    benign: () => 'Liên kết ít ký hiệu đặc biệt.',
  },
  n_subdomains: {
    risk: (v) => `Tên miền xếp chồng ${n(v)} tầng phụ phía trước, có thể để che tên miền thật.`,
    benign: () => 'Tên miền không có tầng phụ xếp chồng phía trước.',
  },
  path_depth: {
    risk: (v) => `Liên kết đi sâu ${n(v)} tầng thư mục.`,
    benign: () => 'Liên kết chỉ có ít tầng thư mục.',
  },
  n_slashes_url: {
    risk: (v) => `Liên kết có nhiều dấu "/" (${n(v)} dấu), cấu trúc phức tạp hơn bình thường.`,
    benign: () => 'Liên kết có cấu trúc thư mục đơn giản.',
  },
  port_val: {
    risk: () => 'Liên kết chỉ định một cổng mạng lạ.',
    benign: () => 'Liên kết không dùng cổng mạng lạ.',
  },
  n_dots_url: {
    risk: () => 'Liên kết có nhiều dấu chấm, kiểu xếp chồng nhiều tên miền.',
    benign: () => 'Liên kết ít dấu chấm.',
  },
  n_dots_host: {
    risk: () => 'Tên miền có nhiều dấu chấm, cấu trúc phức tạp.',
    benign: () => 'Tên miền có cấu trúc đơn giản.',
  },
  n_underscores_url: {
    risk: () => 'Liên kết dùng nhiều dấu gạch dưới "_".',
    benign: () => 'Liên kết không dùng nhiều dấu gạch dưới.',
  },
  n_question_url: PARAMS,
  n_equal_url: PARAMS,
  n_ampersand_url: PARAMS,
  n_percent_url: ENCODED,
  n_pct_encoded: ENCODED,
  decode_depth: ENCODED,
  has_escape_seq: ENCODED,
  has_html_entities: ENCODED,
  n_at_url: {
    risk: () => 'Liên kết có ký tự "@": phần đứng trước "@" chỉ để đánh lừa người đọc.',
    benign: () => 'Liên kết không có ký tự "@" đánh lừa.',
  },
  has_userinfo: {
    risk: () => 'Liên kết có ký tự "@": phần đứng trước "@" chỉ để đánh lừa người đọc.',
    benign: () => 'Liên kết không có ký tự "@" đánh lừa.',
  },
  entropy_url: RANDOM,
  entropy_host: {
    risk: () => 'Tên miền có chuỗi ký tự lộn xộn, trông như được tạo ngẫu nhiên.',
    benign: () => 'Tên miền đọc được, không lộn xộn.',
  },
  entropy_path: RANDOM,
  has_ip_host: {
    risk: (v, c) => `Liên kết dùng địa chỉ IP${c.host ? ` (${c.host})` : ''} thay vì tên miền, nên không biết ai sở hữu trang.`,
    benign: () => 'Liên kết dùng tên miền, không dùng địa chỉ IP trần.',
  },
  scheme_is_https: {
    risk: () => 'Liên kết không dùng kết nối mã hóa HTTPS.',
    benign: () => 'Liên kết dùng kết nối mã hóa HTTPS (lưu ý: trang lừa đảo cũng có thể có HTTPS).',
  },
  scheme_is_http: {
    risk: () => 'Liên kết dùng http:// không mã hóa.',
    benign: () => 'Liên kết không dùng http:// không mã hóa.',
  },
  scheme_is_other: {
    risk: () => 'Liên kết dùng kiểu mở lạ, không phải trang web thông thường.',
    benign: () => 'Liên kết mở trang web theo cách thông thường.',
  },
  scheme_missing: {
    risk: () => 'Liên kết thiếu phần mở đầu "http://" hoặc "https://".',
    benign: () => 'Liên kết có phần mở đầu đầy đủ.',
  },
  has_data_uri: {
    risk: () => 'Liên kết chứa dữ liệu nhúng có thể chạy mã.',
    benign: () => 'Liên kết không chứa dữ liệu nhúng.',
  },
  has_javascript_pseudo: {
    risk: () => 'Liên kết chứa lệnh chạy mã "javascript:".',
    benign: () => 'Liên kết không chứa lệnh chạy mã.',
  },
  has_executable_extension: {
    risk: () => 'Liên kết trỏ tới tệp cài đặt (.apk, .exe…), có thể là phần mềm độc hại.',
    benign: () => 'Liên kết không tải tệp cài đặt về máy.',
  },
  has_archive_extension: {
    risk: () => 'Liên kết trỏ tới tệp nén (.zip, .rar…).',
    benign: () => 'Liên kết không tải tệp nén.',
  },
  has_redirect_parameter: {
    risk: (v, c) => `Liên kết có tham số chuyển tiếp${c.embeddedHost ? ` sang "${c.embeddedHost}"` : ' sang trang khác'}.`,
    benign: () => 'Liên kết không chuyển tiếp sang trang khác.',
  },
  brand_token_in_hostname: BRAND_MENTION,
  brand_token_in_registered_domain: BRAND_MENTION,
  brand_token_in_subdomain: {
    risk: () => 'Tên thương hiệu nằm ở phần đầu tên miền, còn tên miền thật lại là một trang khác.',
    benign: () => 'Không có tên thương hiệu bị đặt ở phần đầu tên miền.',
  },
  brand_token_in_path: {
    risk: () => 'Tên thương hiệu xuất hiện ở phần đường dẫn, không phải ở tên miền.',
    benign: () => 'Không có tên thương hiệu chèn vào đường dẫn.',
  },
  brand_token_in_query: {
    risk: () => 'Tên thương hiệu xuất hiện trong phần tham số của liên kết.',
    benign: () => 'Không có tên thương hiệu chèn vào phần tham số.',
  },
  brand_official_domain_match: {
    risk: () => 'Liên kết không thuộc tên miền chính thức của thương hiệu được nhắc tới.',
    benign: (v, c) => `Đây đúng là tên miền chính thức của thương hiệu${c.host ? ` (${c.host})` : ''}.`,
  },
  brand_official_domain_mismatch: {
    risk: () => 'Liên kết mượn tên một thương hiệu nhưng không phải tên miền chính thức của thương hiệu đó.',
    benign: () => 'Không thấy dấu hiệu mượn tên thương hiệu.',
  },
  brand_lookalike_distance: {
    risk: () => 'Tên miền được viết gần giống tên một thương hiệu (thêm, bớt hoặc đổi vài chữ).',
    benign: () => 'Tên miền không phải bản nhái chữ của thương hiệu nào.',
  },
  brand_homoglyph_similarity: UNICODE_TRICK,
  brand_plus_security_keyword: {
    risk: () => 'Tên thương hiệu đi kèm các từ như "xác thực", "bảo mật".',
    benign: () => 'Không ghép tên thương hiệu với từ "xác thực", "bảo mật".',
  },
  brand_plus_payment_keyword: {
    risk: () => 'Tên thương hiệu đi kèm các từ như "thanh toán", "hoàn tiền".',
    benign: () => 'Không ghép tên thương hiệu với từ "thanh toán".',
  },
  phishing_keyword_count: keywordSentence('dụ dỗ như "đăng nhập", "xác minh", "cập nhật"'),
  credential_keyword_count: keywordSentence('đòi thông tin đăng nhập'),
  payment_keyword_count: keywordSentence('về thanh toán, chuyển tiền'),
  account_security_keyword_count: keywordSentence('cảnh báo tài khoản như "bị khóa", "bảo mật"'),
  vietnamese_keyword_count: keywordSentence('tiếng Việt nhạy cảm'),
  vietnamese_bank_keyword_count: keywordSentence('nhắc tới ngân hàng Việt Nam'),
  vietnamese_otp_keyword_count: keywordSentence('về mã OTP, mã xác thực'),
  vietnamese_public_service_keyword_count: keywordSentence('mạo danh cơ quan nhà nước, dịch vụ công'),
  hostname_has_non_ascii: UNICODE_TRICK,
  hostname_is_punycode: UNICODE_TRICK,
  hostname_mixed_script: UNICODE_TRICK,
  hostname_confusable_count: UNICODE_TRICK,
  hostname_confusable_brand_match: {
    risk: () => 'Tên miền dùng chữ cái giả (trông giống hệt) để nhái tên một thương hiệu.',
    benign: () => 'Tên miền không dùng chữ cái giả để nhái thương hiệu.',
  },
  hostname_unicode_script_count: UNICODE_TRICK,
  hostname_ascii_normalization_changed: UNICODE_TRICK,
  tld_in_path: {
    risk: () => 'Có đuôi tên miền giả (như ".com", ".vn") chèn vào giữa liên kết để đánh lừa.',
    benign: () => 'Không có đuôi tên miền giả chèn vào giữa liên kết.',
  },
  tld_in_subdomain: {
    risk: () => 'Có đuôi tên miền giả (như ".com", ".vn") đặt ở phần đầu tên miền để đánh lừa.',
    benign: () => 'Không có đuôi tên miền giả ở phần đầu tên miền.',
  },
  abnormal_subdomain: {
    risk: () => 'Phần đầu tên miền có dạng lạ (như "www1", "ww2").',
    benign: () => 'Phần đầu tên miền có dạng bình thường.',
  },
  shortening_service: {
    risk: () => 'Đây là liên kết rút gọn, che mất trang đích thật.',
    benign: () => 'Đây không phải liên kết rút gọn.',
  },
  nb_www: {
    risk: () => 'Chữ "www" xuất hiện ở vị trí bất thường.',
    benign: () => 'Không có chữ "www" đặt sai chỗ.',
  },
  nb_com: {
    risk: () => 'Chuỗi ".com" xuất hiện ở phần sau tên miền để đánh lừa.',
    benign: () => 'Không có chuỗi ".com" chèn vào phần sau tên miền.',
  },
  nb_dslash: {
    risk: () => 'Liên kết có thêm "//" ở giữa, dấu hiệu đang chứa một liên kết khác bên trong.',
    benign: () => 'Liên kết không chứa liên kết khác bên trong.',
  },
  char_repeat: {
    risk: () => 'Có chữ cái lặp lại liên tiếp bất thường (như "aaaa").',
    benign: () => 'Không có chữ cái lặp lại bất thường.',
  },
  shortest_word_host: WORDS,
  avg_word_host: WORDS,
  longest_word_path: WORDS,
  avg_word_path: WORDS,
};

/** Plain strength wording from |TreeSHAP| (log-odds); `level` drives the 3-step visual meter. */
export function shapStrength(shapValue) {
  const a = Math.abs(Number(shapValue) || 0);
  if (a >= 1.0) return { level: 3, text: 'Ảnh hưởng nhiều' };
  if (a >= 0.35) return { level: 2, text: 'Ảnh hưởng vừa' };
  return { level: 1, text: 'Ảnh hưởng ít' };
}

/** Context taken from the URL analysis (host, TLD, embedded redirect). */
export function shapContext(urlAnalysis) {
  const host = String(urlAnalysis?.host || '').toLowerCase();
  const tldLabel = host.includes('.') ? host.split('.').pop() : '';
  let embeddedHost = '';
  const first = Array.isArray(urlAnalysis?.embedded_urls) ? urlAnalysis.embedded_urls[0] : null;
  if (first) {
    try {
      embeddedHost = new URL(first).hostname;
    } catch {
      embeddedHost = '';
    }
  }
  return { host, tld: tldLabel ? `.${tldLabel}` : 'lạ', embeddedHost };
}

// 0/1 flags: the sentence must describe the FACT (present / absent), whatever the SHAP sign.
const BINARY = new Set([
  'is_suspicious_tld', 'has_ip_host', 'has_userinfo', 'scheme_is_https', 'scheme_is_http', 'scheme_is_other',
  'scheme_missing', 'has_escape_seq', 'has_html_entities', 'has_data_uri', 'has_javascript_pseudo',
  'has_executable_extension', 'has_archive_extension', 'has_redirect_parameter', 'brand_token_in_hostname',
  'brand_token_in_registered_domain', 'brand_token_in_subdomain', 'brand_token_in_path', 'brand_token_in_query',
  'brand_official_domain_match', 'brand_official_domain_mismatch', 'brand_plus_security_keyword',
  'brand_plus_payment_keyword', 'hostname_has_non_ascii', 'hostname_is_punycode', 'hostname_mixed_script',
  'hostname_confusable_brand_match', 'hostname_ascii_normalization_changed', 'tld_in_path', 'tld_in_subdomain',
  'abnormal_subdomain', 'shortening_service', 'n_at_url',
]);
// Flags whose "present" state is the reassuring one.
const PRESENT_IS_BENIGN = new Set(['scheme_is_https', 'brand_official_domain_match']);
// Counts where 0 means "absent" (use the reassuring sentence even if SHAP is positive).
const ZERO_MEANS_ABSENT = /(_count|^n_|^nb_|decode_depth|char_repeat|path_depth)/;

/** One everyday sentence for a SHAP contribution. */
export function plainShapSentence(item, ctx = {}) {
  return plainShapItem(item, ctx).text;
}

/**
 * Sentence + whether the described fact agrees with the SHAP direction.
 * (A 0/1 flag can have a sign the plain fact cannot explain; such rows stay in the technical table.)
 */
export function plainShapItem(item, ctx = {}) {
  const feature = item?.feature;
  const direction = item?.direction || ((item?.shapValue ?? item?.shap_value ?? 0) >= 0 ? 'risk' : 'benign');
  const rule = RULES[feature];
  const value = item?.value;
  const wantRisk = direction === 'risk';
  if (rule) {
    if (BINARY.has(feature) && (value === 0 || value === 1)) {
      const present = value === 1;
      const factRisk = PRESENT_IS_BENIGN.has(feature) ? !present : present;
      return { text: (factRisk ? rule.risk : rule.benign)(value, ctx), consistent: factRisk === wantRisk };
    }
    if (feature === 'hostname_unicode_script_count' && typeof value === 'number' && value <= 1) {
      return { text: rule.benign(value, ctx), consistent: !wantRisk };
    }
    if (ZERO_MEANS_ABSENT.test(feature || '') && value === 0) {
      return { text: rule.benign(value, ctx), consistent: !wantRisk };
    }
    if (rule[direction]) return { text: rule[direction](value, ctx), consistent: true };
  }
  const label = String(item?.label || 'Một đặc điểm của liên kết');
  return { text: wantRisk ? `${label} khiến AI nghi ngờ hơn.` : `${label} khiến AI bớt nghi ngờ.`, consistent: true };
}
