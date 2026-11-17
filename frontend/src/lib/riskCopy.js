/**
 * User-facing copy for scan results.
 *
 * The backend is the single source of truth for risk: every QR result carries `risk_level`
 * (danger | warning | no_known_risk | unverifiable | info | pending) and `alert_code`.
 * This module ONLY maps those values to plain-language Vietnamese text. It never derives,
 * upgrades or downgrades a risk level on its own.
 *
 * Wording rules: never say "an toàn" as a verdict, never claim full certainty, never claim bank verification.
 */

export const RISK_LEVELS = ['danger', 'warning', 'no_known_risk', 'unverifiable', 'info', 'pending'];

/** Severity order used only for sorting / summarising (most severe first). */
export const RISK_ORDER = { danger: 0, warning: 1, unverifiable: 2, pending: 3, no_known_risk: 4, info: 5 };

const BASE = {
  danger: {
    tone: 'danger',
    label: 'Nguy hiểm',
    title: 'Nguy hiểm — không mở mã QR này',
    description: 'Chúng tôi phát hiện dấu hiệu cho thấy liên kết có thể được dùng để lừa đảo hoặc gây hại.',
    action: 'Không mở liên kết, không nhập mật khẩu và không chuyển tiền. Hãy liên hệ người gửi qua kênh đáng tin cậy.',
  },
  warning: {
    tone: 'warning',
    label: 'Đáng ngờ',
    title: 'Mã QR này có dấu hiệu đáng ngờ',
    description: 'Có một số điểm bất thường. Chúng tôi chưa thể xác định chắc chắn đây có phải lừa đảo hay không.',
    action: 'Khoan mở liên kết hoặc chuyển tiền. Hãy kiểm tra lại nguồn gửi.',
  },
  no_known_risk: {
    tone: 'ok',
    label: 'Chưa thấy dấu hiệu nguy hiểm',
    title: 'Chưa phát hiện dấu hiệu nguy hiểm đã biết',
    description: 'Các bước kiểm tra đã thực hiện chưa tìm thấy cảnh báo rõ ràng. Điều này không có nghĩa mã QR an toàn tuyệt đối.',
    action: 'Chỉ tiếp tục khi bạn tin tưởng người gửi. Không cung cấp mật khẩu hoặc mã OTP.',
  },
  unverifiable: {
    tone: 'unknown',
    label: 'Chưa kiểm tra đầy đủ',
    title: 'Chưa thể kiểm tra đầy đủ mã QR',
    description: 'Ảnh bị mờ, mã QR không hợp lệ hoặc một phần hệ thống kiểm tra chưa phản hồi.',
    action: 'Thử chụp lại ảnh rõ hơn. Nếu vẫn không kiểm tra được, đừng vội mở liên kết hoặc chuyển tiền.',
  },
  info: {
    tone: 'info',
    label: 'Thông tin',
    title: 'Mã QR chứa văn bản',
    description: 'Mã QR này không phải liên kết web hay mã chuyển tiền.',
    action: 'Không làm theo yêu cầu chuyển tiền hoặc cung cấp mật khẩu nếu văn bản yêu cầu.',
  },
  pending: {
    tone: 'pending',
    label: 'Đang kiểm tra',
    title: 'Đang kiểm tra mã QR...',
    description: 'Chúng tôi đang xem mã QR dẫn đến đâu và có dấu hiệu đáng ngờ hay không.',
    action: 'Bạn không cần thao tác thêm. Đừng mở liên kết hoặc chuyển tiền trong lúc chờ.',
  },
};

export const KID_TIP =
  'Nếu còn băn khoăn hoặc chưa rõ nguồn gốc, bạn hãy tạm dừng lại và hỏi người có kinh nghiệm hoặc liên hệ trực tiếp người gửi để xác thực.';
export const BANK_REMINDER =
  'Trước khi chuyển tiền, hãy kiểm tra tên và số tài khoản người nhận trong ứng dụng ngân hàng và đối chiếu với thông tin đáng tin cậy.';
export const VIETQR_MATCH_CAVEAT = 'Điều này chưa xác nhận tài khoản thuộc đúng người bạn muốn chuyển tiền.';

function normalizeLevel(level) {
  return RISK_LEVELS.includes(level) ? level : 'unverifiable';
}

/** Find a VietQR comparison row (account / bank / name / amount) */
function check(result, field) {
  return (result?.match_result?.checks || []).find((c) => c.field === field) || null;
}

/** Plain-language mismatch sentences built from backend comparison rows (no inference). */
export function vietqrMismatchLines(result) {
  const lines = [];
  const acc = check(result, 'account');
  if (acc && acc.status === 'mismatch' && acc.context_value && acc.qr_value) {
    lines.push(`Ảnh ghi số tài khoản ${acc.context_value} nhưng mã QR chứa số tài khoản ${acc.qr_value}.`);
  }
  if (acc && acc.status === 'conflict' && acc.context_value && acc.qr_value) {
    lines.push(`Ảnh ghi nhiều số tài khoản khác nhau (có cả ${acc.context_value}); mã QR chuyển tới ${acc.qr_value}.`);
  }
  const bank = check(result, 'bank');
  if (bank && bank.status === 'mismatch' && bank.context_value && bank.qr_value) {
    lines.push(`Ảnh ghi ngân hàng ${bank.context_value} nhưng mã QR chuyển tới ${bank.qr_value}.`);
  }
  const name = check(result, 'name');
  if (name && name.status === 'mismatch' && name.context_value && name.qr_value) {
    lines.push(`Ảnh ghi tên ${name.context_value} nhưng mã QR mang tên ${name.qr_value}.`);
  }
  const amount = check(result, 'amount');
  if (amount && amount.status === 'mismatch' && amount.qr_value) {
    lines.push(amount.context_value
      ? `Ảnh ghi số tiền ${amount.context_value} nhưng mã QR đặt sẵn ${amount.qr_value}.`
      : `Số tiền trong mã QR (${amount.qr_value}) không có trên ảnh.`);
  }
  const desc = check(result, 'description');
  if (desc && desc.status === 'mismatch') {
    lines.push('Nội dung chuyển khoản ghi một số tiền khác với số tiền thật trong mã QR.');
  }
  return lines;
}

/**
 * Collect all uppercase reason codes from top-level and URL analysis results.
 */
function collectReasonCodes(result) {
  const raw = [...(result?.reason_codes || []), ...(result?.url_analysis?.reason_codes || [])];
  return new Set(raw.map((c) => String(c || '').toUpperCase()).filter(Boolean));
}

/**
 * Context-specific warning badges for AlertBanner (`actionBadgesForResult`).
 * Adapts to payload_type (`vietqr` vs `url`/`uri` vs `other`), alert_code, and reason_codes.
 */
export function actionBadgesForResult(result) {
  const level = normalizeLevel(
    result?.is_provisional && result?.risk_level !== 'danger' && result?.risk_level !== 'warning'
      ? 'pending'
      : result?.risk_level,
  );
  const type = (result?.payload_type || '').toLowerCase();
  const code = String(result?.alert_code || '').toUpperCase();
  const reasons = collectReasonCodes(result);

  if (level === 'pending') {
    return [{ type: 'pending', text: type === 'vietqr' ? 'Đang đối chiếu ngữ cảnh thanh toán' : 'Đang phân tích bảo mật' }];
  }

  if (type === 'vietqr') {
    if (code === 'CRITICAL_MISMATCH') {
      return [
        { type: 'dont', text: 'Mâu thuẫn thông tin nhận tiền' },
        { type: 'dont', text: 'Tuyệt đối không chuyển khoản' },
        { type: 'check', text: 'Nghi vấn dán đè / tráo mã QR' },
      ];
    }
    if (code === 'PARTIAL_MATCH') {
      return [
        { type: 'pause', text: 'Thông tin chuyển tiền lệch một phần' },
        { type: 'check', text: 'Tạm dừng & đối chiếu từng số TK, số tiền' },
      ];
    }
    if (code === 'CONTEXT_CONSISTENT') {
      return [
        { type: 'ok', text: 'Khớp chữ in trên ảnh' },
        { type: 'caution', text: 'CRC hợp lệ ≠ Chủ tài khoản thật' },
        { type: 'check', text: 'Kiểm tra tên người nhận trên app ngân hàng' },
      ];
    }
    if (code === 'INSUFFICIENT_CONTEXT') {
      return [
        { type: 'action', text: 'Thiếu chữ in đối chiếu trên ảnh' },
        { type: 'pause', text: 'Tự kiểm tra kỹ tên & STK trên app ngân hàng' },
      ];
    }
    if (code === 'INVALID_PAYLOAD') {
      return [
        { type: 'dont', text: 'Lỗi cấu trúc EMVCo / CRC-16' },
        { type: 'dont', text: 'Không dùng mã này để chuyển tiền' },
      ];
    }
  }

  if (code === 'UNSUPPORTED_URI') {
    return [
      { type: 'info', text: 'Lệnh mở cuộc gọi / tin nhắn / email' },
      { type: 'check', text: 'Kiểm tra kỹ số điện thoại & nội dung trước khi gửi' },
    ];
  }

  if (type === 'url' || type === 'uri') {
    if (level === 'danger') {
      if (reasons.has('TI_KNOWN_MALICIOUS') || reasons.has('TI_EMBEDDED_URL_MATCH')) {
        return [
          { type: 'dont', text: 'Khớp danh sách chỉ báo độc hại (Local IOC)' },
          { type: 'dont', text: 'Tuyệt đối không mở liên kết' },
          { type: 'dont', text: 'Không nhập mật khẩu / OTP / tải tệp' },
        ];
      }
      if (reasons.has('DANGEROUS_SCHEME')) {
        return [
          { type: 'dont', text: 'Giao thức thực thi mã nguy hiểm' },
          { type: 'dont', text: 'Không mở hoặc dán vào trình duyệt' },
        ];
      }
      return [
        { type: 'dont', text: 'Liên kết có nguy cơ độc hại cao' },
        { type: 'dont', text: 'Không mở liên kết' },
        { type: 'dont', text: 'Không cung cấp mật khẩu / mã OTP' },
      ];
    }

    if (level === 'warning') {
      if (reasons.has('IDN_BRAND_HOMOGRAPH') || reasons.has('PUNYCODE_DOMAIN')) {
        return [
          { type: 'dont', text: 'Giả mạo tên miền bằng ký tự đồng hình (IDN)' },
          { type: 'pause', text: 'Không mở liên kết từ mã QR' },
          { type: 'check', text: 'Tự gõ tên miền chính chủ trên trình duyệt' },
        ];
      }
      if (reasons.has('BRAND_LOOKALIKE_DOMAIN') || reasons.has('BRAND_IN_SUBDOMAIN') || reasons.has('EMBEDDED_BRAND_LOOKALIKE')) {
        return [
          { type: 'dont', text: 'Nghi vấn giả mạo thương hiệu / ngân hàng' },
          { type: 'dont', text: 'Không nhập mật khẩu / số thẻ / mã OTP' },
          { type: 'check', text: 'Chỉ dùng ứng dụng hoặc trang chính thức' },
        ];
      }
      if (reasons.has('DANGEROUS_SCHEME')) {
        return [
          { type: 'dont', text: 'Giao thức thực thi mã nguy hiểm' },
          { type: 'dont', text: 'Không mở hoặc dán vào trình duyệt' },
        ];
      }
      if (reasons.has('OBFUSCATED_HOST') || reasons.has('IP_LITERAL_HOST') || reasons.has('PRIVATE_OR_LOCAL_HOST') || reasons.has('URL_USERINFO_PRESENT') || reasons.has('USERINFO_PRESENT')) {
        return [
          { type: 'pause', text: 'Địa chỉ máy chủ bị làm rối / dùng IP trực tiếp' },
          { type: 'dont', text: 'Khoan truy cập liên kết' },
          { type: 'check', text: 'Kiểm tra lại nguồn đặt mã QR' },
        ];
      }
      if (reasons.has('URL_SHORTENER') || reasons.has('EMBEDDED_REDIRECT_URL')) {
        return [
          { type: 'pause', text: 'Liên kết rút gọn / chuyển hướng ẩn đích đến' },
          { type: 'check', text: 'Kiểm tra kỹ tên miền cuối cùng sau khi mở' },
        ];
      }
      return [
        { type: 'pause', text: 'Liên kết có dấu hiệu cấu trúc bất thường' },
        { type: 'check', text: 'Kiểm tra kỹ tên miền & nguồn gửi trước khi mở' },
      ];
    }

    if (level === 'no_known_risk') {
      if (result?.url_analysis?.model?.ml_prediction === 1) {
        return [
          { type: 'ok', text: 'Chưa khớp danh sách đen / luật chặn' },
          { type: 'caution', text: 'Cảm biến AI ghi nhận cấu trúc đáng lưu ý' },
          { type: 'check', text: 'Kiểm tra kỹ tên miền, không nhập OTP' },
        ];
      }
      return [
        { type: 'ok', text: 'Chưa có cảnh báo đã biết' },
        { type: 'caution', text: 'Không đồng nghĩa an toàn tuyệt đối' },
        { type: 'check', text: 'Kiểm tra đúng tên miền trên trình duyệt' },
      ];
    }
  }

  if (level === 'danger') {
    return [
      { type: 'dont', text: 'Nguy cơ độc hại cao' },
      { type: 'dont', text: 'Không mở liên kết' },
      { type: 'dont', text: 'Không cung cấp OTP / Mật khẩu' },
    ];
  }
  if (level === 'warning') {
    return [
      { type: 'pause', text: 'Dấu hiệu đáng ngờ' },
      { type: 'check', text: 'Cần xác minh nguồn gửi' },
    ];
  }
  if (level === 'no_known_risk') {
    return [
      { type: 'ok', text: 'Chưa có cảnh báo đã biết' },
      { type: 'caution', text: 'Kiểm tra kỹ trước khi truy cập' },
    ];
  }
  if (level === 'unverifiable') {
    return [
      { type: 'action', text: 'Cần ảnh rõ nét hơn' },
      { type: 'pause', text: 'Tạm hoãn thao tác' },
    ];
  }
  return [{ type: 'info', text: 'Dữ liệu văn bản' }];
}

/**
 * Copy for a single QR result. Returns { level, tone, label, title, description, action, extra[], steps[] }.
 * `extra` holds additional plain sentences (e.g. VietQR caveats) shown right under the description.
 * `steps` holds concrete, context-specific user action steps.
 */
export function copyForResult(result) {
  const level = normalizeLevel(result?.is_provisional && result?.risk_level !== 'danger' && result?.risk_level !== 'warning'
    ? 'pending'
    : result?.risk_level);
  const base = { level, ...BASE[level], extra: [], steps: [] };
  const type = (result?.payload_type || '').toLowerCase();
  const code = result?.alert_code;
  const reasons = collectReasonCodes(result);

  if (type === 'vietqr' && !result?.is_provisional) {
    if (code === 'CRITICAL_MISMATCH') {
      const lines = vietqrMismatchLines(result);
      return {
        ...base,
        title: 'Cảnh báo: Thông tin nhận tiền không khớp.',
        description: lines[0] || 'Thông tin in trên ảnh khác với thông tin người nhận trong mã QR.',
        extra: lines.slice(1),
        action: 'Không chuyển tiền. Hãy xác nhận lại trực tiếp với người nhận.',
        steps: [
          'Dừng ngay giao dịch trên ứng dụng ngân hàng, tuyệt đối không bấm chuyển tiền.',
          'Kiểm tra xem mã QR trên biển hiệu hoặc hóa đơn có dấu hiệu bị dán đè hay chỉnh sửa không.',
          'Hỏi trực tiếp người bán hoặc người nhận qua số điện thoại tin cậy để đối chiếu lại số tài khoản.',
        ],
      };
    }
    if (code === 'PARTIAL_MATCH') {
      const lines = vietqrMismatchLines(result);
      return {
        ...base,
        title: 'Thông tin chuyển tiền có điểm chưa khớp',
        description: lines[0] || 'Một phần thông tin trên ảnh không trùng hoặc chỉ gần giống với mã QR.',
        extra: lines.slice(1),
        action: 'Khoan chuyển tiền. So từng chữ số và tên người nhận trong ứng dụng ngân hàng trước khi xác nhận.',
        steps: [
          'Tạm dừng ở màn hình kiểm tra thông tin chuyển khoản trên ứng dụng ngân hàng.',
          'Đối chiếu từng chữ số tài khoản, tên người thụ hưởng và tổng số tiền cần thanh toán với hóa đơn gốc.',
          'Chỉ chuyển khoản khi người nhận trực tiếp khẳng định thông tin là chính xác.',
        ],
      };
    }
    if (code === 'CONTEXT_CONSISTENT') {
      return {
        ...base,
        title: 'Thông tin trong mã QR trùng với chữ đọc được trên ảnh.',
        description: VIETQR_MATCH_CAVEAT,
        action: 'Chỉ chuyển tiền khi bạn chắc chắn về người nhận.',
        steps: [
          'Kiểm tra tên chủ tài khoản tự động hiển thị trên ứng dụng ngân hàng xem có đúng với người hoặc cửa hàng bạn muốn trả tiền hay không.',
          'Lưu ý: Kẻ gian có thể in giả toàn bộ tờ biển hiệu (cả chữ in lẫn mã QR đều mang tài khoản kẻ gian), nên việc trùng chữ trên ảnh không thay thế bước kiểm tra tên người nhận.',
        ],
      };
    }
    if (code === 'INSUFFICIENT_CONTEXT') {
      return {
        ...base,
        title: 'Chưa đủ thông tin để so sánh.',
        description: 'Trên ảnh không có đủ chữ (số tài khoản, tên người nhận) để đối chiếu với mã QR. Chúng tôi không thể kết luận thông tin là đúng.',
        action: 'Chụp rộng hơn để thấy cả phần chữ in cạnh mã QR, hoặc tự kiểm tra người nhận trong ứng dụng ngân hàng.',
        steps: [
          'Chụp lại ảnh góc rộng hơn sao cho thấy rõ cả mã QR lẫn dòng chữ in số tài khoản và tên chủ tài khoản xung quanh.',
          'Nếu mã QR đứng độc lập không có chữ đi kèm, hãy hỏi trực tiếp người nhận tên chủ tài khoản trước khi chuyển tiền.',
        ],
      };
    }
    if (code === 'INVALID_PAYLOAD') {
      return {
        ...base,
        title: 'Mã QR chuyển tiền bị lỗi hoặc không đúng chuẩn',
        description: 'Dữ liệu trong mã QR không đầy đủ hoặc đã bị thay đổi.',
        action: 'Không dùng mã này để chuyển tiền. Hãy xin người nhận mã QR mới.',
        steps: [
          'Không sử dụng mã QR này để giao dịch vì cấu trúc dữ liệu EMVCo hoặc mã kiểm tra CRC-16 không hợp lệ.',
          'Đề nghị người nhận cung cấp lại mã QR thanh toán mới từ ứng dụng ngân hàng chính thức.',
        ],
      };
    }
  }

  // Wi-Fi / SMS / other app schemes: the image was read fine; the scheme simply is not a web link.
  if (type === 'uri' && !result?.is_provisional && reasons.has('UNSUPPORTED_URI_SCHEME')) {
    const p = String(result?.payload || '').trim().toLowerCase();
    const kind = p.startsWith('wifi:') ? 'kết nối Wi-Fi'
      : (p.startsWith('smsto:') || p.startsWith('sms:')) ? 'soạn sẵn tin nhắn'
        : p.startsWith('tel:') ? 'gọi điện'
          : (p.startsWith('mecard:') || p.startsWith('begin:vcard')) ? 'lưu danh bạ'
            : 'mở một ứng dụng trên điện thoại';
    return {
      ...base,
      title: `Mã QR dùng để ${kind}`,
      description: 'Đây không phải liên kết trang web nên hệ thống không chấm được mức rủi ro cho mã này.',
      action: 'Đọc kỹ nội dung mã bên dưới trước khi làm theo.',
    };
  }

  if (type === 'vietqr' && result?.is_provisional) {
    return { ...base, title: 'Đã đọc được mã QR chuyển tiền', description: 'Đang so sánh thông tin chuyển tiền với chữ trên ảnh...' };
  }

  if (code === 'UNSUPPORTED_URI') {
    return {
      ...base,
      title: 'Mã QR mở cuộc gọi, tin nhắn hoặc email',
      description: 'Mã này không mở trang web mà yêu cầu điện thoại gọi, nhắn tin hoặc gửi email.',
      action: 'Kiểm tra kỹ số điện thoại hoặc địa chỉ trước khi gọi hay gửi tin.',
      steps: [
        'Xem kỹ số điện thoại hoặc địa chỉ email đích cùng nội dung tin nhắn được điền sẵn.',
        'Tuyệt đối không gửi đi các tin nhắn chứa mã OTP, mật khẩu hoặc cú pháp chuyển hướng cuộc gọi lạ.',
      ],
    };
  }

  if ((type === 'url' || type === 'uri') && !result?.is_provisional) {
    if (level === 'danger') {
      if (reasons.has('TI_KNOWN_MALICIOUS') || reasons.has('TI_EMBEDDED_URL_MATCH')) {
        return {
          ...base,
          description: 'Địa chỉ liên kết trong mã QR trùng khớp với cơ sở dữ liệu chỉ báo lừa đảo hoặc phát tán mã độc đã biết (Local IOC).',
          action: 'Tuyệt đối không mở liên kết, không đăng nhập tài khoản, không cung cấp mã OTP và không tải tệp tin về máy.',
          steps: [
            'Không mở liên kết này trên trình duyệt và không sao chép địa chỉ để truy cập.',
            'Tuyệt đối không nhập tên đăng nhập, mật khẩu, thông tin thẻ hay mã OTP và không cài đặt tệp (.apk, .exe).',
            'Nếu mã QR được dán tại điểm công cộng hoặc gửi qua tin nhắn, hãy cảnh báo cho người xung quanh hoặc quản trị viên.',
          ],
        };
      }
      return {
        ...base,
        action: 'Tuyệt đối không mở liên kết, không nhập mật khẩu hay mã OTP. Hãy liên hệ người gửi qua kênh đáng tin cậy.',
        steps: [
          'Không mở liên kết hoặc thực thi nội dung mã QR này trên trình duyệt.',
          'Không cung cấp thông tin cá nhân, mật khẩu hoặc mã OTP.',
        ],
      };
    }

    if (level === 'warning') {
      if (reasons.has('IDN_BRAND_HOMOGRAPH') || reasons.has('PUNYCODE_DOMAIN')) {
        return {
          ...base,
          description: 'Tên miền trong mã QR sử dụng ký tự đồng hình quốc tế hóa (Punycode xn--) trông giống hệt chữ cái thông thường nhằm giả dạng thương hiệu thật.',
          action: 'Không mở liên kết từ mã QR này. Hãy tự gõ địa chỉ trang web chính chủ hoặc mở ứng dụng chính thức.',
          steps: [
            'Không truy cập liên kết từ mã QR vì tên miền dùng chữ cái hệ khác (ví dụ chữ Kirin) để đánh lừa mắt nhìn.',
            'Kiểm tra mục "Mã QR dẫn tới trang web" bên dưới: tên miền thật sau giải mã bắt đầu bằng "xn--", không phải trang chính chủ.',
            'Nếu cần giao dịch, hãy mở trực tiếp ứng dụng chính thức trên điện thoại hoặc tự gõ tên miền chính thức vào trình duyệt.',
          ],
        };
      }
      if (reasons.has('BRAND_LOOKALIKE_DOMAIN') || reasons.has('BRAND_IN_SUBDOMAIN') || reasons.has('EMBEDDED_BRAND_LOOKALIKE')) {
        return {
          ...base,
          description: 'Liên kết mượn tên ngân hàng hoặc thương hiệu quen thuộc nhưng nằm trên một tên miền khác, không phải trang chính thức.',
          action: 'Không mở liên kết và tuyệt đối không nhập mật khẩu, số thẻ hay mã OTP. Hãy kiểm tra trên ứng dụng chính thức.',
          steps: [
            'Không đăng nhập tài khoản ngân hàng, ví điện tử hay cổng dịch vụ công qua liên kết này.',
            'Tuyệt đối không nhập mật khẩu, số căn cước, thông tin thẻ tín dụng hoặc mã OTP.',
            'Mở trực tiếp ứng dụng chính thức của ngân hàng/tổ chức hoặc gọi tổng đài chính thức để kiểm tra thông báo.',
          ],
        };
      }
      if (reasons.has('DANGEROUS_SCHEME')) {
        return {
          ...base,
          description: 'Liên kết sử dụng giao thức thực thi kịch bản trực tiếp (như javascript: hoặc data:) thay vì trang web thông thường.',
          action: 'Tuyệt đối không mở hoặc sao chép liên kết này vào thanh địa chỉ trình duyệt.',
          steps: [
            'Không mở và không dán chuỗi nội dung này lên trình duyệt web.',
            'Bỏ qua mã QR này để tránh nguy cơ thực thi mã độc trên trình duyệt.',
          ],
        };
      }
      if (reasons.has('OBFUSCATED_HOST') || reasons.has('IP_LITERAL_HOST') || reasons.has('PRIVATE_OR_LOCAL_HOST') || reasons.has('URL_USERINFO_PRESENT') || reasons.has('USERINFO_PRESENT')) {
        return {
          ...base,
          description: 'Liên kết dùng địa chỉ IP trực tiếp, mạng nội bộ hoặc ký tự @ để che giấu máy chủ đích thực sự.',
          action: 'Không truy cập liên kết này. Hãy kiểm tra lại nguồn phát hành mã QR.',
          steps: [
            'Không mở các liên kết dùng dãy số IP trực tiếp hoặc cấu trúc che giấu tên miền.',
            'Liên hệ trực tiếp với đơn vị phát hành mã QR nếu bạn cần xác nhận đường dẫn hợp lệ.',
          ],
        };
      }
      if (reasons.has('URL_SHORTENER') || reasons.has('EMBEDDED_REDIRECT_URL')) {
        return {
          ...base,
          description: 'Liên kết đã bị rút gọn hoặc lồng tham số chuyển hướng, khiến bạn không biết trước trang đích thực sự sẽ mở ra.',
          action: 'Khoan mở liên kết nếu chưa rõ nguồn gửi. Kiểm tra kỹ tên miền cuối cùng trên trình duyệt trước khi thao tác.',
          steps: [
            'Chỉ mở liên kết nếu bạn biết rõ và tin tưởng người tạo mã QR.',
            'Sau khi trang web tải xong, hãy nhìn kỹ tên miền trên thanh địa chỉ trình duyệt xem có đúng trang chính thức hay không.',
            'Không nhập mật khẩu hay mã OTP nếu bị chuyển hướng sang tên miền lạ.',
          ],
        };
      }
      return {
        ...base,
        action: 'Khoan mở liên kết. Hãy kiểm tra kỹ tên miền đích và nguồn gửi trước khi thao tác.',
        steps: [
          'Xem kỹ địa chỉ đầy đủ của liên kết và các dấu hiệu cảnh báo ở phần bằng chứng bên dưới.',
          'Không nhập mật khẩu, mã OTP hoặc tải tệp nếu chưa rõ nguồn gửi.',
        ],
      };
    }

    if (level === 'no_known_risk') {
      return {
        ...base,
        action: 'Chỉ tiếp tục khi bạn tin tưởng người gửi. Không cung cấp mật khẩu hoặc mã OTP.',
        steps: [
          'Chỉ mở liên kết khi bạn biết rõ nguồn gốc của mã QR.',
          'Khi trình duyệt mở trang, hãy kiểm tra lại tên miền trên thanh địa chỉ để đảm bảo không bị chuyển hướng sang trang lạ.',
          'Không nhập mật khẩu hoặc mã OTP nếu bạn không chủ động thực hiện đăng nhập trên trang chính chủ.',
        ],
      };
    }
  }

  if (result?.is_provisional && (level === 'danger' || level === 'warning')) {
    return { ...base, extra: ['Đây là cảnh báo ban đầu. Chúng tôi đang kiểm tra thêm.'] };
  }
  return base;
}

/** Short plain explanation for backend reason codes (shown under "Vì sao có cảnh báo này?"). */
const REASON_TEXT = {
  TI_KNOWN_MALICIOUS: 'Địa chỉ này đã bị các nguồn bảo mật ghi nhận là lừa đảo hoặc độc hại.',
  TI_SUSPICIOUS: 'Một số nguồn bảo mật đã cảnh báo địa chỉ này.',
  DANGEROUS_SCHEME: 'Liên kết dùng kiểu mở nguy hiểm có thể chạy mã trên máy.',
  URL_USERINFO_PRESENT: 'Liên kết được viết để giả dạng một trang web khác.',
  BRAND_IN_SUBDOMAIN: 'Liên kết mượn tên thương hiệu nhưng không thuộc trang chính thức.',
  BRAND_LOOKALIKE_DOMAIN: 'Tên miền có chứa tên ngân hàng/thương hiệu nhưng không phải trang chính thức — kiểu giả mạo rất hay gặp.',
  URL_SHORTENER: 'Liên kết đã bị rút gọn nên không thấy được trang đích thật.',
  SHARED_HOSTING_PLATFORM: 'Trang nằm trên dịch vụ cho phép ai cũng tạo trang, nên tên miền quen thuộc không bảo đảm nội dung.',
  PRIVATE_OR_LOCAL_HOST: 'Liên kết trỏ vào mạng nội bộ, điều bất thường với mã QR công khai.',
  URL_XGB_HIGH_SCORE: 'Liên kết có nhiều đặc điểm giống các trang lừa đảo đã biết.',
  URL_XGB_MEDIUM_SCORE: 'Liên kết có một vài đặc điểm giống các trang lừa đảo.',
  URL_HIGH_RULE_SCORE: 'Liên kết có cấu trúc bất thường (ví dụ rút gọn, tên miền lạ, ký tự đánh lừa).',
  URL_SYNTAX_INVALID: 'Liên kết bị lỗi, không đọc được đúng cách.',
  EVALUATION_INCONCLUSIVE: 'Một bước kiểm tra chưa có kết quả nên chưa thể kết luận.',
  TI_IOC_STALE: 'Địa chỉ này từng bị ghi nhận lừa đảo trước đây (dữ liệu cũ, chưa được xác nhận lại).',
  TI_EMBEDDED_URL_MATCH: 'Liên kết sẽ chuyển tiếp tới một địa chỉ đã bị ghi nhận lừa đảo.',
  OBFUSCATED_HOST: 'Địa chỉ trang web bị viết theo cách che giấu để khó nhận ra.',
  IDN_BRAND_HOMOGRAPH: 'Tên miền dùng chữ cái trông giống tên ngân hàng/thương hiệu nhưng thực ra là trang khác.',
  EMBEDDED_BRAND_LOOKALIKE: 'Liên kết chuyển tiếp tới trang mang tên ngân hàng/thương hiệu nhưng không phải trang chính thức.',
  EMBEDDED_REDIRECT_URL: 'Liên kết có chứa một địa chỉ khác bên trong và có thể chuyển bạn sang trang đó.',
  NO_ANOMALIES_DETECTED: 'Các bước kiểm tra đã chạy chưa thấy điểm bất thường.',
  OCR_UNAVAILABLE: 'Chưa đọc được chữ trên ảnh nên chưa thể so sánh thông tin.',
  OCR_ERROR: 'Đọc chữ trên ảnh bị lỗi nên chưa thể so sánh thông tin.',
  PDF_HIDDEN_TEXT: 'PDF có chữ bị ẩn (không nhìn thấy được); phần chữ ẩn đã bị bỏ qua khi so sánh.',
  CRITICAL_MISMATCH: 'Thông tin người nhận trong mã QR khác với chữ in trên ảnh.',
  PARTIAL_MATCH: 'Một phần thông tin người nhận không khớp hoặc chỉ gần giống.',
  CONTEXT_CONSISTENT: 'Số tài khoản trong mã QR trùng với số in trên ảnh.',
  INSUFFICIENT_CONTEXT: 'Trên ảnh không có đủ chữ để so sánh.',
  INVALID_PAYLOAD: 'Dữ liệu mã QR chuyển tiền không đúng chuẩn hoặc đã bị sửa đổi.',
  UNSUPPORTED_URI_SCHEME: 'Liên kết dùng giao thức đặc biệt nên hệ thống không tự kiểm tra trang đích.',
  UNSUPPORTED_URI: 'Mã QR mở một ứng dụng trên điện thoại (gọi, nhắn tin, email).',
  TI_NOT_CONSULTED: 'Chưa đối chiếu được với danh sách địa chỉ lừa đảo đã biết.',
  TI_INTEGRITY_FAILED: 'Danh sách địa chỉ lừa đảo có sẵn không qua được bước kiểm tra tính nguyên vẹn.',
  TI_LOAD_ERROR: 'Không đọc được danh sách địa chỉ lừa đảo có sẵn.',
  TI_NOT_CONFIGURED: 'Chưa cài đặt danh sách địa chỉ lừa đảo có sẵn.',
  LOCAL_IOC_NO_MATCH: 'Địa chỉ này chưa có trong danh sách lừa đảo đã biết.',
  QR_ANALYSIS_ERROR: 'Gặp lỗi khi phân tích mã QR này.',
};

export function reasonTexts(codes = []) {
  const seen = new Set();
  const out = [];
  for (const code of codes) {
    const key = String(code || '').toUpperCase();
    const text = REASON_TEXT[key] || (key.startsWith('URI_SCHEME_') ? 'Mã QR mở một ứng dụng trên điện thoại (gọi, nhắn tin, email).' : null);
    if (text && !seen.has(text)) {
      seen.add(text);
      out.push(text);
    }
  }
  return out;
}

/** Local IOC list state -> [state, optional plain text]. */
const LOCAL_IOC_STATE = {
  match: ['done', 'có trong danh sách'],
  stale: ['done', 'từng có trong danh sách (dữ liệu cũ)'],
  no_match: ['done', 'không có trong danh sách'],
  not_configured: ['skipped', 'chưa có danh sách'],
  not_applicable: ['skipped', null],
  integrity_failed: ['failed', 'danh sách không hợp lệ'],
  load_error: ['failed', 'danh sách bị lỗi'],
  error: ['failed', 'danh sách bị lỗi'],
  unknown: ['failed', null],
};

/**
 * Which checks actually ran, in plain words (never claims a check that did not run).
 * Exposes the 2 active layers: Local IOC and XGBoost AI Model.
 */
export function checksSummary(checks = {}) {
  const items = [];
  if (checks.local_ioc) {
    const [state, text] = LOCAL_IOC_STATE[checks.local_ioc] || ['failed', null];
    items.push({ label: 'Danh sách địa chỉ lừa đảo đã biết', state, ...(text ? { text } : {}) });
  }
  if (checks.ml_sensor) {
    const label = 'Mô hình AI nhận diện liên kết lừa đảo';
    if (checks.ml_sensor === 'done') {
      items.push({ label, state: 'done' });
    } else if (checks.ml_sensor === 'not_configured') {
      items.push({ label, state: 'skipped', text: 'chưa được nạp' });
    } else {
      items.push({ label, state: 'skipped', text: 'không sử dụng được' });
    }
  }
  return items;
}


/** Messages for job-level error codes (API + worker). */
const ERROR_COPY = {
  FILE_TOO_LARGE: ['Tệp quá lớn.', 'Hãy chọn ảnh hoặc PDF nhỏ hơn 50 MB, hoặc chụp riêng mã QR.'],
  UNSUPPORTED_FILE_TYPE: ['Định dạng tệp không được hỗ trợ.', 'Hãy chọn ảnh JPG, PNG, WEBP hoặc tệp PDF.'],
  EMPTY_FILE: ['Tệp rỗng hoặc bị hỏng.', 'Hãy chụp lại hoặc chọn tệp khác.'],
  INVALID_FILE: ['Không đọc được tệp này. Tệp có thể bị hỏng.', 'Hãy chụp lại ảnh rõ hơn hoặc chọn tệp khác.'],
  FILE_RESOURCE_LIMIT: ['Ảnh hoặc PDF quá lớn nên hệ thống từ chối xử lý.', 'Hãy dùng ảnh nhỏ hơn (dưới 36 megapixel) hoặc PDF ít trang hơn.'],
  PDF_ENCRYPTED: ['PDF đang đặt mật khẩu nên không thể kiểm tra.', 'Hãy dùng bản PDF không đặt mật khẩu hoặc chụp ảnh mã QR.'],
  NO_QR_FOUND: ['Không tìm thấy mã QR trong ảnh.', 'Hãy chụp gần hơn, đủ sáng và giữ mã QR nằm trọn trong khung.'],
  CSRF_REJECTED: ['Yêu cầu không hợp lệ.', 'Hãy tải lại trang rồi thử lại.'],
  JOB_NOT_FOUND: ['Phiên kiểm tra đã hết hạn hoặc không tồn tại.', 'Hãy kiểm tra lại mã QR từ đầu.'],
  HTTPS_REQUIRED: ['Cần mở trang bằng HTTPS để kiểm tra.', 'Hãy dùng địa chỉ bắt đầu bằng https:// (camera cũng cần HTTPS). Khi thử trong mạng nội bộ, dùng cấu hình docker-compose.dev.yml.'],
  TOO_MANY_ACTIVE_JOBS: ['Bạn đang kiểm tra quá nhiều mã cùng lúc.', 'Hãy đợi lượt hiện tại xong rồi thử lại.'],
  TOO_MANY_STREAMS: ['Có quá nhiều cửa sổ đang kiểm tra.', 'Hãy đóng bớt các tab rồi thử lại.'],
  RATE_LIMITED: ['Bạn thao tác quá nhanh.', 'Hãy đợi vài giây rồi thử lại.'],
  SERVICE_UNAVAILABLE: ['Hệ thống đang bận hoặc tạm gián đoạn.', 'Hãy thử lại sau ít phút.'],
  PROCESSING_ERROR: ['Đã xảy ra lỗi khi kiểm tra tệp.', 'Hãy thử lại. Nếu vẫn lỗi, đừng vội mở liên kết hoặc chuyển tiền.'],
  ANALYSIS_FAILED: ['Không thể hoàn tất phân tích mã QR.', 'Hãy thử kiểm tra lại. Trong khi chưa có kết quả, không mở liên kết hoặc chuyển tiền.'],
  QR_ANALYSIS_ERROR: ['Gặp lỗi khi phân tích nội dung mã QR.', 'Hãy thử lại với ảnh chụp rõ hơn hoặc kiểm tra lại nguồn gửi.'],
  MODEL_UNAVAILABLE: ['Cảm biến máy học tạm thời không khả dụng.', 'Hệ thống vẫn đánh giá bằng luật tĩnh và Local IOC, nhưng hãy thận trọng trước khi thao tác.'],
  LOCAL_IOC_UNAVAILABLE: ['Không thể truy cập cơ sở dữ liệu Local IOC cục bộ.', 'Chưa đối chiếu được danh sách chỉ báo đã biết; hãy thận trọng với liên kết này.'],
  OCR_INSUFFICIENT: ['Chưa đọc đủ chữ trên ảnh để đối chiếu ngữ cảnh.', 'Hãy chụp rộng hơn để thấy rõ thông tin người nhận in cạnh mã QR.'],
  INVALID_VIETQR: ['Cấu trúc mã QR thanh toán VietQR không hợp lệ.', 'Không sử dụng mã này để chuyển tiền; hãy yêu cầu người nhận cung cấp mã mới.'],
  INVALID_PAYLOAD: ['Dữ liệu trong mã QR không đúng chuẩn hoặc bị hỏng.', 'Không sử dụng mã QR này.'],
  JOB_TIMEOUT: ['Việc kiểm tra mất quá nhiều thời gian và đã dừng.', 'Hãy thử lại với ảnh nhỏ hơn hoặc chụp riêng mã QR.'],
  CHECK_TOO_LONG: ['Chưa nhận được kết quả sau thời gian dài.', 'Hãy kiểm tra kết nối mạng rồi thử lại. Đừng vội mở liên kết hoặc chuyển tiền.'],
  OFFLINE: ['Bạn đang ngoại tuyến.', 'Cần có kết nối mạng để kiểm tra mã QR. Hãy bật Wi-Fi hoặc dữ liệu di động.'],
  NETWORK_ERROR: ['Không kết nối được máy chủ.', 'Hãy kiểm tra mạng rồi thử lại.'],
  CANCELLED: ['Bạn đã hủy lượt kiểm tra.', 'Bạn có thể kiểm tra lại bất cứ lúc nào.'],
  INTERNAL_ERROR: ['Đã xảy ra lỗi không mong muốn.', 'Hãy thử lại sau.'],
};

export function copyForError(code, fallbackMessage) {
  const [message, action] = ERROR_COPY[code] || ERROR_COPY.INTERNAL_ERROR;
  return { code: ERROR_COPY[code] ? code : 'INTERNAL_ERROR', message: ERROR_COPY[code] ? message : (fallbackMessage || message), action };
}

/** Job-level warnings (codes from backend `warnings`) → plain text. */
export function warningTexts(warnings = []) {
  const out = [];
  for (const w of warnings) {
    const s = String(w);
    if (s === 'PARTIAL_ANALYSIS') out.push('Một phần tệp chưa được kiểm tra, nên kết quả chưa đầy đủ.');
    else if (s.startsWith('PDF_PAGE_LIMIT:')) {
      const [done, total] = s.split(':')[1].split('/');
      out.push(`PDF có ${total} trang, chúng tôi mới kiểm tra ${done} trang đầu. Mã QR ở các trang sau chưa được kiểm tra.`);
    } else if (s.startsWith('PDF_PAGES_SKIPPED:')) out.push(`Không đọc được trang ${s.split(':')[1]} của PDF.`);
    else if (s.startsWith('PDF_HIDDEN_TEXT:')) out.push(`Trang ${s.split(':')[1]} của PDF có chữ bị ẩn. Chúng tôi chỉ so sánh phần chữ nhìn thấy được.`);
    else if (s.startsWith('QR_LIMIT:')) {
      const [done, total] = s.split(':')[1].split('/');
      out.push(`Tệp có ${total} mã QR, chúng tôi mới kiểm tra ${done} mã đầu. Các mã còn lại chưa được kiểm tra.`);
    }
  }
  return out;
}

/** Mask an account number: keep last 4 digits. */
export function maskAccount(value) {
  const s = String(value || '');
  if (s.length <= 4) return s;
  return `${'•'.repeat(Math.min(6, s.length - 4))} ${s.slice(-4)}`;
}

/** Format a VietQR amount string as VND. */
export function formatAmount(value) {
  const n = Number.parseInt(String(value || '').replace(/[^\d]/g, ''), 10);
  if (!Number.isFinite(n)) return null;
  return `${n.toLocaleString('vi-VN')} đ`;
}

/** Most severe level among results (for the summary line). */
export function worstLevel(results = []) {
  let worst = null;
  for (const r of results) {
    const lvl = normalizeLevel(r?.risk_level);
    if (worst === null || RISK_ORDER[lvl] < RISK_ORDER[worst]) worst = lvl;
  }
  return worst;
}

/** Mandatory VietQR structural caveat: valid CRC never proves recipient identity. */
export const VIETQR_CRC_CAVEAT = 'CRC hợp lệ ≠ xác thực người nhận. Mã kiểm tra CRC chỉ xác nhận dữ liệu mã QR đúng chuẩn kỹ thuật, không xác nhận chủ tài khoản.';

const RULE_TITLES = {
  DANGEROUS_SCHEME: 'Giao thức thực thi nguy hiểm',
  UNSUPPORTED_SCHEME: 'Giao thức URI ngoài HTTP/HTTPS',
  USERINFO_PRESENT: 'Thành phần định danh @ gây nhầm lẫn',
  URL_USERINFO_PRESENT: 'Thành phần định danh @ gây nhầm lẫn',
  PRIVATE_OR_LOCAL_HOST: 'Địa chỉ mạng nội bộ / cục bộ',
  IP_LITERAL_HOST: 'Sử dụng địa chỉ IP trực tiếp',
  OBFUSCATED_HOST: 'Che giấu định dạng địa chỉ máy chủ',
  PUNYCODE_DOMAIN: 'Tên miền quốc tế hóa Punycode (xn--)',
  URL_SHORTENER: 'Dịch vụ rút gọn che khuất đích đến',
  EMBEDDED_REDIRECT_URL: 'Tham số chuyển hướng URL lồng bên trong',
  EXCESSIVE_SUBDOMAINS: 'Cấu trúc nhiều tầng tên miền phụ',
  SHARED_HOSTING_PLATFORM: 'Nền tảng lưu trữ chia sẻ công cộng',
  BRAND_IN_SUBDOMAIN: 'Mượn tên thương hiệu ở tên miền phụ',
  BRAND_LOOKALIKE_DOMAIN: 'Tên miền giả mạo thương hiệu',
  IDN_BRAND_HOMOGRAPH: 'Ký tự đồng hình (IDN Homograph) giả mạo',
  EMBEDDED_BRAND_LOOKALIKE: 'Chuyển hướng tới tên miền giả mạo thương hiệu',
  HIGH_HOST_ENTROPY: 'Chuỗi tên miền có độ ngẫu nhiên cao',
  HIGH_DIGIT_RATIO: 'Tỷ lệ chữ số cao bất thường trong tên miền',
  EXCESSIVE_URL_LENGTH: 'Độ dài liên kết vượt ngưỡng thông thường',
  EXCESSIVE_QUERY_LENGTH: 'Chuỗi truy vấn (query) dài bất thường',
  HIGH_SPECIAL_CHAR_RATIO: 'Mật độ ký tự đặc biệt cao trong liên kết',
  NON_STANDARD_PORT: 'Cổng dịch vụ mạng (port) phi tiêu chuẩn',
  SUSPICIOUS_KEYWORD: 'Từ khóa nhạy cảm thường gặp khi giả mạo',
  URL_SYNTAX_INVALID: 'Cú pháp liên kết không hợp lệ',
};

const RULE_SEVERITY_MAP = {
  critical: { label: 'Nghiêm trọng', tone: 'danger' },
  high: { label: 'Cao', tone: 'danger' },
  medium: { label: 'Trung bình', tone: 'warning' },
  low: { label: 'Thấp', tone: 'info' },
  info: { label: 'Thông tin', tone: 'info' },
};

/**
 * Formats a single triggered static rule finding for the Static Rules summary card.
 * Keeps the internal rule code while surfacing severity + title + short explanation.
 */
export function formatRuleFinding(finding) {
  if (!finding) return null;
  const code = String(finding.code || '').toUpperCase();
  const sevKey = String(finding.severity || 'low').toLowerCase();
  const sev = RULE_SEVERITY_MAP[sevKey] || { label: finding.severity || 'Ghi nhận', tone: 'neutral' };
  const title = RULE_TITLES[code] || 'Dấu hiệu bất thường theo luật tĩnh';
  const explanation = REASON_TEXT[code] || finding.description || 'Phát hiện đặc trưng cấu trúc cần lưu ý.';
  return {
    code,
    severity: sevKey,
    severityLabel: sev.label,
    tone: sev.tone,
    title,
    explanation,
  };
}

function fmtPercentValue(val, digits = 1) {
  if (typeof val === 'number' && Number.isFinite(val)) {
    const pct = (val * 100).toFixed(digits);
    return `${pct}%`;
  }
  return null;
}

/**
 * Pure formatter for XGBoost ML Sensor data.
 * Strictly uses backend `ml_prediction` without client-side threshold comparison
 * and never converts a null/missing `model_score` into zero percent.
 */
const SCALE_PCT = 10 * 10;

function formatHumanFeatureValue(feature, value, valueLabel) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return `Giá trị: ${valueLabel}`;
  }
  const f = String(feature || '').toLowerCase();
  if (f === 'scheme_is_https') {
    return value === 1 ? 'Đang dùng kết nối HTTPS' : 'Không dùng kết nối HTTPS';
  }
  if (f === 'scheme_is_http') {
    return value === 1 ? 'Đang dùng HTTP không mã hóa' : 'Không dùng HTTP thường';
  }
  if (f === 'brand_official_domain_match') {
    return value === 1 ? 'Trùng khớp tên miền chính chủ' : 'Không trùng tên miền chính chủ';
  }
  if (f === 'brand_official_domain_mismatch') {
    return value === 1 ? 'Có tên thương hiệu nhưng khác miền chính chủ' : 'Không mâu thuẫn tên miền thương hiệu';
  }
  const isBinaryFlag = (
    f.startsWith('is_')
    || f.startsWith('has_')
    || f.endsWith('_match')
    || f.endsWith('_mismatch')
    || f.endsWith('_present')
    || f.endsWith('_in_subdomain')
    || f.endsWith('_in_domain')
    || f.endsWith('_in_path')
    || f.endsWith('_is_punycode')
    || f.endsWith('_is_ip')
  );
  if (isBinaryFlag && (value === 0 || value === 1)) {
    return value === 1 ? 'Có phát hiện trong liên kết' : 'Không xuất hiện trong liên kết';
  }
  if (f.endsWith('_length') || f.endsWith('_len')) {
    return `Độ dài: ${Math.round(value)} ký tự`;
  }
  if (f.endsWith('_count') || f.startsWith('n_')) {
    return value === 0 ? 'Số lượng: 0 (không có)' : `Số lượng: ${Math.round(value)}`;
  }
  if (f.endsWith('_ratio')) {
    return `Tỷ lệ: ${(value * SCALE_PCT).toFixed(0)}%`;
  }
  if (f.endsWith('_entropy')) {
    return `Độ ngẫu nhiên: ${value.toFixed(2)} bit/ký tự`;
  }
  return `Giá trị đo được: ${valueLabel}`;
}

function formatShapItems(items, maxAbsAcrossCard = 1) {
  if (!Array.isArray(items)) return [];
  const valid = items.filter(
    (it) => it && typeof it.feature === 'string' && typeof it.shap_value === 'number' && Number.isFinite(it.shap_value),
  );
  if (valid.length === 0) return [];

  const groupTotalAbs = valid.reduce((acc, it) => acc + Math.abs(it.shap_value), 0) || 1;
  const normMax = Math.max(maxAbsAcrossCard, 0.01);

  return valid.map((it) => {
    const sVal = it.shap_value;
    const absVal = Math.abs(sVal);
    const shapLabel = sVal >= 0 ? `+${sVal.toFixed(2)}` : sVal.toFixed(2);
    const fVal = typeof it.value === 'number' && Number.isFinite(it.value)
      ? (Number.isInteger(it.value) ? String(it.value) : it.value.toFixed(2))
      : '—';
    const direction = it.direction || (sVal >= 0 ? 'risk' : 'benign');
    const humanValueLabel = formatHumanFeatureValue(it.feature, it.value, fVal);

    let impactLabel;
    let plainExplanation;
    if (direction === 'risk') {
      if (absVal >= 1.0) impactLabel = 'Tăng mạnh rủi ro';
      else if (absVal >= 0.35) impactLabel = 'Tăng rủi ro';
      else impactLabel = 'Tăng nhẹ rủi ro';
      plainExplanation = `Cộng thêm ${shapLabel} điểm nghi vấn do: ${humanValueLabel}.`;
    } else {
      if (absVal >= 1.0) impactLabel = 'Giảm mạnh nghi vấn';
      else if (absVal >= 0.35) impactLabel = 'Giảm nghi vấn';
      else impactLabel = 'Giảm nhẹ nghi vấn';
      plainExplanation = `Trừ bớt ${shapLabel} điểm nghi vấn nhờ: ${humanValueLabel}.`;
    }

    const sharePct = Math.max(1, Math.min(SCALE_PCT, Math.round((absVal / groupTotalAbs) * SCALE_PCT)));
    const barWidthPct = Math.max(14, Math.min(SCALE_PCT, Math.round((absVal / normMax) * SCALE_PCT)));

    return {
      feature: it.feature,
      label: it.label || it.feature,
      value: it.value,
      valueLabel: fVal,
      humanValueLabel,
      shapValue: sVal,
      shapLabel,
      direction,
      impactLabel,
      plainExplanation,
      sharePct,
      barWidthPct,
    };
  });
}

export function formatMlSensorSummary(model, warnings = []) {
  if (!model) return null;
  const status = String(model.model_status || 'NOT_CONFIGURED').toUpperCase();
  const isCached = Array.isArray(warnings) && warnings.includes('CACHED_RESULT');
  const modelId = model.model_id || 'qrdetec-url-xgb';
  const nFeatures = model.n_features ?? 81;

  const hasScore = typeof model.model_score === 'number' && Number.isFinite(model.model_score);
  const scorePct = hasScore ? (model.model_score >= 0.9995 ? 'trên 99.9%' : fmtPercentValue(model.model_score, 1)) : null;
  const scoreLabel = scorePct != null ? scorePct : 'Không đo lường';
  const rawScorePct = fmtPercentValue(model.raw_score, 1);
  const thresholdPct = fmtPercentValue(model.ml_threshold, 1);

  let predictionLabel = 'Chưa xác định';
  let predictionState = 'unknown';
  if (model.ml_prediction === 1) {
    predictionLabel = 'Vượt ngưỡng';
    predictionState = 'exceeded';
  } else if (model.ml_prediction === 0) {
    predictionLabel = 'Không vượt ngưỡng';
    predictionState = 'below';
  }

  const allShapVals = [
    ...(Array.isArray(model.shap_top_risk) ? model.shap_top_risk : []),
    ...(Array.isArray(model.shap_top_benign) ? model.shap_top_benign : []),
  ]
    .map((it) => (it && typeof it.shap_value === 'number' && Number.isFinite(it.shap_value) ? Math.abs(it.shap_value) : 0));
  const maxShapAbs = Math.max(0.01, ...allShapVals);

  return {
    status,
    modelId,
    nFeatures,
    rawScore: model.raw_score ?? null,
    rawScoreLabel: rawScorePct || '—',
    modelScore: hasScore ? model.model_score : null,
    scorePct,
    scoreLabel,
    threshold: model.ml_threshold ?? null,
    thresholdLabel: thresholdPct || '—',
    prediction: model.ml_prediction ?? null,
    predictionLabel,
    predictionState,
    isCached,
    shapBaseValue: typeof model.shap_base_value === 'number' && Number.isFinite(model.shap_base_value) ? model.shap_base_value : null,
    shapBaseProbLabel: typeof model.shap_base_value === 'number' && Number.isFinite(model.shap_base_value)
      ? `${((1 / (1 + Math.exp(-model.shap_base_value))) * SCALE_PCT).toFixed(1)}%`
      : null,
    shapGuideText: 'Cách đọc dễ hiểu: AI bắt đầu từ Điểm xuất phát trung bình (Base). Dấu (+) màu cam là dấu hiệu đáng ngờ làm cộng thêm điểm rủi ro; dấu (-) màu xanh là đặc điểm bình thường giúp trừ bớt điểm rủi ro trước khi quy đổi ra tỷ lệ % cuối cùng.',
    shapTopRisk: formatShapItems(model.shap_top_risk, maxShapAbs),
    shapTopBenign: formatShapItems(model.shap_top_benign, maxShapAbs),
    disclaimer: `Mô hình AI XGBoost (${nFeatures} đặc trưng) kết hợp hiệu chuẩn Isotonic và giải thích cục bộ TreeSHAP trực tiếp đánh giá cấu trúc liên kết.`,
  };
}

const LOCAL_IOC_SUMMARY_MAP = {
  MATCH: {
    status: 'MATCH',
    label: 'Có IOC khớp',
    tone: 'danger',
    description: 'Địa chỉ hoặc tên miền trùng khớp chỉ báo độc hại đã biết trong cơ sở dữ liệu Local IOC.',
  },
  STALE: {
    status: 'MATCH',
    label: 'Có IOC khớp',
    tone: 'warning',
    description: 'Địa chỉ trùng khớp chỉ báo trong cơ sở dữ liệu Local IOC (bản ghi đã quá hạn khuyến nghị cập nhật).',
  },
  NO_MATCH: {
    status: 'NO_MATCH',
    label: 'Đã tra cứu — không khớp IOC đã biết',
    tone: 'neutral',
    description: 'Đã đối chiếu cơ sở dữ liệu Local IOC cục bộ; chưa ghi nhận chỉ báo trùng khớp. Không đồng nghĩa địa chỉ không có rủi ro.',
  },
  NOT_CONFIGURED: {
    status: 'NOT_CONFIGURED',
    label: 'Chưa cấu hình',
    tone: 'neutral',
    description: 'Nguồn dữ liệu Local IOC cục bộ chưa được cấu hình trên hệ thống.',
  },
  INTEGRITY_FAILED: {
    status: 'INTEGRITY_FAILED',
    label: 'Không thể xác minh toàn vẹn nguồn IOC',
    tone: 'warning',
    description: 'Tệp nguồn Local IOC không vượt qua bước kiểm tra mã băm toàn vẹn.',
  },
  LOAD_ERROR: {
    status: 'LOAD_ERROR',
    label: 'Không thể tải Local IOC',
    tone: 'warning',
    description: 'Không thể nạp cơ sở dữ liệu Local IOC cục bộ trong lượt kiểm tra này.',
  },
  NOT_APPLICABLE: {
    status: 'NOT_APPLICABLE',
    label: 'Không áp dụng',
    tone: 'neutral',
    description: 'Tra cứu Local IOC chỉ áp dụng cho liên kết web HTTP/HTTPS.',
  },
};

/**
 * Pure formatter for the Local IOC evidence card.
 * Never labels NO_MATCH as safe and never exposes full hashes in summary view.
 */
export function formatLocalIocSummary(ti, checkStatus) {
  const rawKey = String(ti?.local_ti_status || checkStatus || 'NOT_CONFIGURED').toUpperCase();
  if (rawKey === 'MATCH' && String(ti?.freshness || '').toLowerCase() === 'stale') {
    return LOCAL_IOC_SUMMARY_MAP.STALE;
  }
  if (LOCAL_IOC_SUMMARY_MAP[rawKey]) {
    return LOCAL_IOC_SUMMARY_MAP[rawKey];
  }
  if (rawKey === 'ERROR' || rawKey === 'UNKNOWN') {
    return LOCAL_IOC_SUMMARY_MAP.LOAD_ERROR;
  }
  return {
    status: rawKey,
    label: 'Chưa xác định trạng thái Local IOC',
    tone: 'neutral',
    description: 'Chưa ghi nhận kết quả đối chiếu từ cơ sở dữ liệu Local IOC.',
  };
}

const VIETQR_CONCLUSION_MAP = {
  CONTEXT_CONSISTENT: {
    status: 'CONTEXT_CONSISTENT',
    label: 'Nhất quán ngữ cảnh',
    tone: 'ok',
    summary: 'Thông tin trong mã QR khớp với văn bản hiển thị trên ảnh. Lưu ý: CRC hợp lệ ≠ xác thực người nhận.',
  },
  CRITICAL_MISMATCH: {
    status: 'CRITICAL_MISMATCH',
    label: 'Mâu thuẫn ngữ cảnh nghiêm trọng',
    tone: 'danger',
    summary: 'Thông tin người nhận hoặc số tài khoản trong mã QR mâu thuẫn với văn bản in trên ảnh.',
  },
  PARTIAL_MATCH: {
    status: 'PARTIAL_MATCH',
    label: 'Khớp một phần — cần đối chiếu thủ công',
    tone: 'warning',
    summary: 'Một số trường trên ảnh không trùng hoàn toàn hoặc thiếu thông tin đối chiếu với mã QR.',
  },
  INSUFFICIENT_CONTEXT: {
    status: 'INSUFFICIENT_CONTEXT',
    label: 'Chưa đủ ngữ cảnh trên ảnh',
    tone: 'unknown',
    summary: 'Ảnh không có đủ chữ in xung quanh mã QR để đối chiếu tự động.',
  },
  INVALID_PAYLOAD: {
    status: 'INVALID_PAYLOAD',
    label: 'Cấu trúc mã QR không hợp lệ',
    tone: 'danger',
    summary: 'Cấu trúc TLV hoặc mã kiểm tra CRC của mã VietQR bị lỗi hoặc đã bị sửa đổi.',
  },
};

/**
 * Pure formatter for the 3-step VietQR verification flow (Structural -> Context -> Conclusion).
 * Supports real progressive state when structural decoding finishes before OCR context comparison.
 */
export function formatVietQrFlow(result) {
  const isProvisional = Boolean(result?.is_provisional);
  const code = String(result?.alert_code || '').toUpperCase();
  const isInvalid = code === 'INVALID_PAYLOAD' || result?.vietqr_data?.crc_valid === false;

  const structuralStep = isInvalid
    ? { state: 'error', label: 'Kiểm tra cấu trúc', detail: 'Cấu trúc TLV / CRC không hợp lệ' }
    : { state: 'done', label: 'Kiểm tra cấu trúc', detail: 'Đã hoàn tất kiểm tra cấu trúc' };

  const contextStep = isInvalid
    ? { state: 'skipped', label: 'Kiểm tra ngữ cảnh', detail: 'Bỏ qua do cấu trúc mã QR lỗi' }
    : isProvisional
      ? { state: 'current', label: 'Kiểm tra ngữ cảnh', detail: 'Đang kiểm tra ngữ cảnh hiển thị' }
      : { state: 'done', label: 'Kiểm tra ngữ cảnh', detail: 'Đã hoàn tất đối chiếu ngữ cảnh hiển thị' };

  const conclusion = isProvisional
    ? {
      status: 'PENDING',
      label: 'Đang chờ kết luận ngữ cảnh',
      tone: 'pending',
      summary: 'Đã hoàn tất kiểm tra cấu trúc. Đang kiểm tra ngữ cảnh hiển thị bằng OCR...',
    }
    : (VIETQR_CONCLUSION_MAP[code] || {
      status: code || 'UNVERIFIABLE',
      label: 'Chưa đủ dữ liệu kết luận ngữ cảnh',
      tone: 'unknown',
      summary: 'Chưa đủ dữ liệu đối chiếu tự động; vui lòng kiểm tra trực tiếp trên ứng dụng ngân hàng.',
    });

  return {
    isProvisional,
    structuralStep,
    contextStep,
    conclusionStep: {
      ...conclusion,
      state: isProvisional ? 'todo' : 'done',
      label: 'Kết luận ngữ cảnh',
      detail: conclusion.label,
    },
  };
}

const VIETQR_FIELD_LABELS = {
  account: 'Số tài khoản / Số thẻ',
  bank: 'Ngân hàng thụ hưởng',
  name: 'Tên người nhận',
  recipient: 'Tên người nhận',
  amount: 'Số tiền chuyển khoản',
  description: 'Nội dung chuyển khoản',
};

const VIETQR_CHECK_STATUS = {
  match: { code: 'MATCH', label: 'Khớp ngữ cảnh', tone: 'ok' },
  partial: { code: 'PARTIAL', label: 'Khớp một phần', tone: 'warning' },
  mismatch: { code: 'MISMATCH', label: 'Không khớp', tone: 'danger' },
  conflict: { code: 'CONFLICT', label: 'Mâu thuẫn', tone: 'danger' },
  unknown: { code: 'UNKNOWN', label: 'Chưa xác định', tone: 'unknown' },
  missing: { code: 'UNKNOWN', label: 'Chưa có trên ảnh', tone: 'unknown' },
};

/**
 * Formats field-by-field VietQR vs OCR context comparison rows.
 * Always includes explicit status code + Vietnamese text (never color/icon alone).
 */
export function formatVietQrComparisonRows(matchResult) {
  const checks = matchResult?.checks;
  if (!Array.isArray(checks) || checks.length === 0) return [];
  return checks.map((c, idx) => {
    const fieldKey = String(c.field || '').toLowerCase();
    const statusKey = String(c.status || 'unknown').toLowerCase();
    const st = VIETQR_CHECK_STATUS[statusKey] || {
      code: String(c.status || 'UNKNOWN').toUpperCase(),
      label: 'Chưa xác định',
      tone: 'unknown',
    };
    return {
      key: `${fieldKey || 'field'}-${idx}`,
      field: fieldKey,
      fieldLabel: VIETQR_FIELD_LABELS[fieldKey] || c.field || 'Trường thông tin',
      qrValue: c.qr_value || '—',
      contextValue: c.context_value || 'Không tìm thấy trên ảnh',
      statusCode: st.code,
      statusLabel: st.label,
      tone: st.tone,
    };
  });
}

