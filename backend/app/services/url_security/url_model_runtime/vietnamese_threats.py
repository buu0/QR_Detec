"""
Vietnamese Brand & Threat Intelligence
======================================
Module chuyen sau ve nhan dien URL thuong hieu Viet Nam (Zalo, MoMo, ZaloPay,
Vietcombank, Techcombank, Shopee, Tiki, Viettel, VNPT, FPT, v.v.).

Nguyen tac:
1. Phan biet ro rang 5 nhom:
   - OFFICIAL_DOMAIN: Domain chinh thuc va subdomain hop le cua thuong hieu.
   - BRAND_SPOOF_SUBDOMAIN: Brand nam o subdomain cua domain la (momo.vn.attacker.com).
   - TYPOSQUAT_OR_FAKE: Domain mao danh, typosquat, ghep keyword (-xacthuc, -login, .tk, .xyz).
   - PUNYCODE_SPOOF: Tan cong homograph bang Punycode (xn--).
   - BRAND_IN_PATH_UNTRUSTED: Host IP hoac host la chua brand trong path/query de lua dao.
   - LEGITIMATE_MENTION: Trang bao chi / tin tuc / portal uy tin nhac den brand.
2. KHONG coi moi URL co ten brand la doc hai.
3. Hoan toan OFFLINE / STATIC, deterministic, khong DNS, khong HTTP request.
"""

import re
import idna
from urllib.parse import urlsplit
from typing import Any, Optional


# ---------------------------------------------------------------------------
# 1. Official Brands & Domains Registry
# ---------------------------------------------------------------------------

OFFICIAL_VN_BRANDS: dict[str, dict[str, Any]] = {
    "zalo": {
        "display_name": "Zalo",
        "official_apex_domains": {
            "zalo.me", "zaloapp.com", "zaloweb.me", "zadn.vn", "vng.com.vn"
        },
        "keywords": ["zalo", "zalo-chat", "zalome"],
    },
    "momo": {
        "display_name": "MoMo E-Wallet",
        "official_apex_domains": {
            "momo.vn", "mservice.com.vn", "mservice.io"
        },
        "keywords": ["momo", "vi-momo", "vimomo"],
    },
    "zalopay": {
        "display_name": "ZaloPay",
        "official_apex_domains": {
            "zalopay.vn", "zalopay.com.vn"
        },
        "keywords": ["zalopay", "zalo-pay", "vi-zalopay"],
    },
    "vietcombank": {
        "display_name": "Vietcombank",
        "official_apex_domains": {
            "vietcombank.com.vn"
        },
        "keywords": ["vietcombank", "vcb", "vcbdigibank"],
    },
    "techcombank": {
        "display_name": "Techcombank",
        "official_apex_domains": {
            "techcombank.com.vn", "techcombank.com"
        },
        "keywords": ["techcombank", "tcb"],
    },
    "mbbank": {
        "display_name": "MBBank",
        "official_apex_domains": {
            "mbbank.com.vn", "mbbank.com"
        },
        "keywords": ["mbbank", "mb-bank"],
    },
    "bidv": {
        "display_name": "BIDV",
        "official_apex_domains": {
            "bidv.com.vn"
        },
        "keywords": ["bidv", "bidv-smartbanking"],
    },
    "agribank": {
        "display_name": "Agribank",
        "official_apex_domains": {
            "agribank.com.vn"
        },
        "keywords": ["agribank"],
    },
    "vpbank": {
        "display_name": "VPBank",
        "official_apex_domains": {
            "vpbank.com.vn"
        },
        "keywords": ["vpbank", "vp-bank", "vpbankneo"],
    },
    "acb": {
        "display_name": "ACB",
        "official_apex_domains": {
            "acb.com.vn"
        },
        "keywords": ["acb", "acb-bank"],
    },
    "tpbank": {
        "display_name": "TPBank",
        "official_apex_domains": {
            "tpbank.com.vn", "tpb.vn"
        },
        "keywords": ["tpbank", "tp-bank"],
    },
    "sacombank": {
        "display_name": "Sacombank",
        "official_apex_domains": {
            "sacombank.com.vn", "sacombank.com"
        },
        "keywords": ["sacombank", "sacom-bank"],
    },
    "vietinbank": {
        "display_name": "VietinBank",
        "official_apex_domains": {
            "vietinbank.vn", "vietinbank.com.vn"
        },
        "keywords": ["vietinbank", "vietin-bank"],
    },
    "viettel": {
        "display_name": "Viettel",
        "official_apex_domains": {
            "viettel.vn", "viettel.com.vn", "vietteltelecom.vn", "viettelmoney.vn",
            "viettelpost.vn", "viettelpay.vn"
        },
        "keywords": ["viettel", "viettelpay", "viettelmoney"],
    },
    "vnpt": {
        "display_name": "VNPT",
        "official_apex_domains": {
            "vnpt.com.vn", "vinaphone.com.vn"
        },
        "keywords": ["vnpt", "vinaphone"],
    },
    "fpt": {
        "display_name": "FPT",
        "official_apex_domains": {
            "fpt.vn", "fpt.com.vn", "fpt.com", "fptshop.com.vn", "fptplay.vn", "fpt.edu.vn"
        },
        "keywords": ["fpt", "fptshop", "fptplay"],
    },
    "shopee": {
        "display_name": "Shopee",
        "official_apex_domains": {
            "shopee.vn", "shopeepay.vn"
        },
        "keywords": ["shopee", "shopeepay"],
    },
    "tiki": {
        "display_name": "Tiki",
        "official_apex_domains": {
            "tiki.vn"
        },
        "keywords": ["tiki", "tikivn"],
    },
    "lazada": {
        "display_name": "Lazada",
        "official_apex_domains": {
            "lazada.vn"
        },
        "keywords": ["lazada"],
    },
    "hdbank": {
        "display_name": "HDBank",
        "official_apex_domains": {"hdbank.com.vn"},
        "keywords": ["hdbank", "hd-bank"],
    },
    "ocb": {
        "display_name": "OCB",
        "official_apex_domains": {"ocb.com.vn"},
        "keywords": ["ocb", "ocb-bank"],
    },
    "shb": {
        "display_name": "SHB",
        "official_apex_domains": {"shb.com.vn"},
        "keywords": ["shb", "shb-bank"],
    },
    "seabank": {
        "display_name": "SeABank",
        "official_apex_domains": {"seabank.com.vn"},
        "keywords": ["seabank", "sea-bank"],
    },
    "vib": {
        "display_name": "VIB",
        "official_apex_domains": {"vib.com.vn"},
        "keywords": ["vib", "vib-bank"],
    },
    "scb": {
        "display_name": "SCB",
        "official_apex_domains": {"scb.com.vn"},
        "keywords": ["scb", "scb-bank"],
    },
    "lpbank": {
        "display_name": "LPBank",
        "official_apex_domains": {"lpbank.com.vn", "lienvietpostbank.com.vn"},
        "keywords": ["lpbank", "lienvietpostbank"],
    },
    "baoviet": {
        "display_name": "BaoViet Bank",
        "official_apex_domains": {"baovietbank.com.vn", "baoviet.com.vn"},
        "keywords": ["baoviet", "baovietbank"],
    },
    "namabank": {
        "display_name": "Nam A Bank",
        "official_apex_domains": {"namabank.com.vn"},
        "keywords": ["namabank", "nam-a-bank"],
    },
    "vnpay": {
        "display_name": "VNPAY",
        "official_apex_domains": {"vnpay.vn", "vnpayqr.vn"},
        "keywords": ["vnpay", "vnpay-qr"],
    },
    "thegioididong": {
        "display_name": "TheGioiDiDong",
        "official_apex_domains": {"thegioididong.com", "dienmayxanh.com", "bachhoaxanh.com"},
        "keywords": ["thegioididong", "dienmayxanh"],
    },
    "vietnamairlines": {
        "display_name": "Vietnam Airlines",
        "official_apex_domains": {"vietnamairlines.com"},
        "keywords": ["vietnamairlines"],
    },
    "vinfast": {
        "display_name": "VinFast",
        "official_apex_domains": {"vinfastauto.com", "vingroup.net"},
        "keywords": ["vinfast", "vingroup"],
    },
    "topcv": {
        "display_name": "TopCV",
        "official_apex_domains": {"topcv.vn", "vietnamworks.com"},
        "keywords": ["topcv", "vietnamworks"],
    },
    "google": {
        "display_name": "Google",
        "official_apex_domains": {"google.com", "google.com.vn"},
        "keywords": ["google", "google-search"],
    },
    "paypal": {
        "display_name": "PayPal",
        "official_apex_domains": {"paypal.com"},
        "keywords": ["paypal", "paypal-secure"],
    },
    "roblox": {
        "display_name": "Roblox",
        "official_apex_domains": {"roblox.com"},
        "keywords": ["roblox", "robiox"],
    },
}

# Tap domain toan cau uy tin (Tranco Top 100 globally recognized apex domains)
TRUSTED_GLOBAL_DOMAINS = {
    "google.com", "google.com.vn", "microsoft.com", "microsoftonline.com",
    "apple.com", "amazon.com", "wikipedia.org", "github.com", "paypal.com",
    "ebay.com", "cloudflare.com", "facebook.com", "youtube.com", "twitter.com",
    "x.com", "linkedin.com", "zoom.us", "netflix.com", "instagram.com",
    "reddit.com", "bing.com", "live.com", "office.com", "dropbox.com", "adobe.com"
}

# Tap domain tin tuc, bao chi uy tin Viet Nam thuong trich dan ten brand
TRUSTED_MEDIA_DOMAINS = {
    "vnexpress.net", "dantri.com.vn", "tuoitre.vn", "thanhnien.vn",
    "vietnamnet.vn", "vtv.vn", "baomoi.com", "cafef.vn", "cafebiz.vn",
    "genk.vn", "ictnews.vietnamnet.vn", "laodong.vn", "plo.vn", "zingnews.vn",
    "znews.vn", "kenh14.vn", "chongluadao.vn", "tinnhiemmang.vn",
    "ais.gov.vn", "mic.gov.vn", "ncsc.gov.vn", "khonggianmang.vn"
}

# Multi-part public suffixes pho bien tai Viet Nam va quoc te
MULTI_PART_TLDS = {
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "int.vn",
    "ac.vn", "biz.vn", "info.vn", "health.vn", "name.vn", "pro.vn",
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
}

# Cac tu khoa thuong gap trong lua dao thuong hieu Viet Nam
SPOOF_ACTION_KEYWORDS = {
    "login", "dang-nhap", "dangnhap", "signin", "sign-in",
    "otp", "xac-thuc", "xacthuc", "verify", "verification",
    "nhan-qua", "nhanqua", "nhan-tien", "nhantien", "chuyen-tien", "chuyentien",
    "khuyen-mai", "khuyenmai", "voucher", "nhan-thuong", "nhanthuong",
    "khoa-tai-khoan", "khoataikhoan", "kich-hoat", "kichhoat", "cap-nhat", "capnhat",
    "secure", "bao-mat", "baomat", "ebank", "ibanking"
}

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


# ---------------------------------------------------------------------------
# 2. Public Suffix & Registered Domain Helper
# ---------------------------------------------------------------------------

def extract_registered_domain(hostname: str) -> tuple[str, str]:
    """
    Tach hostname thanh (subdomain, registered_domain).
    Co tinh den cac ccTLD 2 phan nhu .com.vn, .edu.vn, .co.uk.
    
    Vi du:
      'banking.vietcombank.com.vn' -> ('banking', 'vietcombank.com.vn')
      'momo.vn'                    -> ('', 'momo.vn')
      'sub.momo.vn.attacker.com'   -> ('sub.momo.vn', 'attacker.com')
    """
    if not hostname:
        return "", ""

    h = hostname.lower().strip().rstrip(".")
    if _IP_RE.match(h):
        return "", h

    parts = h.split(".")
    if len(parts) <= 1:
        return "", h

    # Kiem tra ccTLD 2 phan (vi du: com.vn)
    if len(parts) >= 3:
        two_part_tld = f"{parts[-2]}.{parts[-1]}"
        if two_part_tld in MULTI_PART_TLDS:
            reg_domain = f"{parts[-3]}.{two_part_tld}"
            subdomain = ".".join(parts[:-3])
            return subdomain, reg_domain

    # Mac dinh TLD 1 phan (vi du: .vn, .com, .me)
    reg_domain = f"{parts[-2]}.{parts[-1]}"
    subdomain = ".".join(parts[:-2])
    return subdomain, reg_domain


# ---------------------------------------------------------------------------
# 3. Comprehensive Vietnamese Brand Threat Analyzer
# ---------------------------------------------------------------------------

def analyze_vietnamese_url(url: str) -> dict[str, Any]:
    """
    Phan tich toan dien URL duoi lang kinh an toan thuong hieu Viet Nam.
    
    Returns:
        dict voi cac truong:
        - brand_detected: ten brand phat hien hoac None
        - is_official_asset: True neu thuoc domain chinh thuc cua brand
        - is_brand_impersonation: True neu co hanh vi gia mao / spoofing brand
        - impersonation_type: loai tan cong (subdomain, typosquat, punycode, ip, etc.)
        - threat_severity: 'SAFE' | 'BENIGN_MEDIA' | 'SUSPICIOUS' | 'CRITICAL'
        - punycode_detected: True neu host dung xn--
        - decoded_host: hostname sau khi giai ma IDN / punycode
        - registered_domain: registered domain da chuan hoa
        - subdomain: subdomain da chuan hoa
        - evidence: danh sach bang chung chi tiet
    """
    result: dict[str, Any] = {
        "brand_detected": None,
        "is_official_asset": False,
        "is_brand_impersonation": False,
        "impersonation_type": None,
        "threat_severity": "SAFE",
        "punycode_detected": False,
        "decoded_host": "",
        "registered_domain": "",
        "subdomain": "",
        "evidence": [],
    }

    if not isinstance(url, str) or not url.strip():
        return result

    raw_url = url.strip()
    try:
        parsed = urlsplit(raw_url if "://" in raw_url else f"http://{raw_url}")
        host = (parsed.hostname or "").lower().strip()
        path = parsed.path or ""
        query = parsed.query or ""
    except Exception:
        return result

    if not host:
        return result

    # 1. Kiem tra Punycode
    punycode_found = "xn--" in host
    result["punycode_detected"] = punycode_found
    decoded_host = host
    if punycode_found:
        try:
            decoded_host = idna.decode(host)
            result["evidence"].append(f"Punycode host decoded: {host} -> {decoded_host}")
        except Exception:
            decoded_host = host
    result["decoded_host"] = decoded_host

    subdomain, reg_domain = extract_registered_domain(host)
    result["registered_domain"] = reg_domain
    result["subdomain"] = subdomain

    is_ip = bool(_IP_RE.match(host))

    # 2. Xac dinh Brand lien quan
    detected_brand_key = None
    target_brand_info = None

    # Thu tim theo registered domain chinh thuc truoc
    for b_key, b_info in OFFICIAL_VN_BRANDS.items():
        if reg_domain in b_info["official_apex_domains"]:
            detected_brand_key = b_key
            target_brand_info = b_info
            result["brand_detected"] = b_key
            result["is_official_asset"] = True
            result["threat_severity"] = "SAFE"
            result["evidence"].append(
                f"Verified official domain of {b_info['display_name']} ({reg_domain})"
            )
            return result

    # Kiem tra cac domain chinh phu (.gov.vn), giao duc (.edu.vn) va domain toan cau uy tin
    if reg_domain.endswith(".gov.vn") or reg_domain in {"chinhphu.vn", "dichvucong.gov.vn"}:
        result["is_official_asset"] = True
        result["threat_severity"] = "SAFE"
        result["evidence"].append(f"Verified Vietnamese government portal ({reg_domain})")
        return result

    if reg_domain.endswith(".edu.vn"):
        result["is_official_asset"] = True
        result["threat_severity"] = "SAFE"
        result["evidence"].append(f"Verified Vietnamese educational institution ({reg_domain})")
        return result

    if reg_domain in TRUSTED_GLOBAL_DOMAINS:
        result["is_official_asset"] = True
        result["threat_severity"] = "SAFE"
        result["evidence"].append(f"Verified trusted global platform domain ({reg_domain})")
        return result

    if reg_domain in TRUSTED_MEDIA_DOMAINS:
        result["is_official_asset"] = True
        result["threat_severity"] = "SAFE"
        result["evidence"].append(f"Verified trusted Vietnamese media/journalism portal ({reg_domain})")
        return result

    # Neu khong phai official domain, tim xem URL co de cap brand khong
    # Xet ca URL goc va unaccented / homoglyph-normalized decoded host neu co punycode
    import unicodedata
    CYRILLIC_CONFUSABLES = str.maketrans({
        '\u0430': 'a', '\u043e': 'o', '\u0435': 'e', '\u0440': 'p', '\u0441': 'c',
        '\u0456': 'i', '\u0443': 'y', '\u0445': 'x', '\u04bb': 'h', '\u0455': 's',
    })
    unaccented_host = "".join(
        c for c in unicodedata.normalize("NFD", decoded_host)
        if unicodedata.category(c) != "Mn"
    ).lower().translate(CYRILLIC_CONFUSABLES)

    url_lower = raw_url.lower()
    search_space = f"{url_lower} {unaccented_host}" if punycode_found else url_lower

    for b_key, b_info in OFFICIAL_VN_BRANDS.items():
        for kw in b_info["keywords"]:
            if len(kw) <= 3:
                # Tu ngan (vcb, tcb, mb, acb): bat buoc tach token ro rang
                tokens = set(re.split(r"[^a-zA-Z0-9]+", search_space))
                if kw in tokens:
                    detected_brand_key = b_key
                    target_brand_info = b_info
                    break
            else:
                if kw in search_space:
                    detected_brand_key = b_key
                    target_brand_info = b_info
                    break
        if detected_brand_key:
            break

    if not detected_brand_key:
        # Khong lien quan den brand Viet Nam duoc theo doi
        return result

    result["brand_detected"] = detected_brand_key
    b_name = target_brand_info["display_name"]

    # 3. Kiem tra cac trang tin tuc / bao chi uy tin
    if reg_domain in TRUSTED_MEDIA_DOMAINS:
        result["threat_severity"] = "BENIGN_MEDIA"
        result["evidence"].append(
            f"Brand '{b_name}' referenced in trusted media portal ({reg_domain})"
        )
        return result

    # 4. Phat hien cac kieu gia mao (Impersonation Patterns)

    # 4a. Brand nam trong SUBDOMAIN cua host khac (vi du: momo.vn.attacker.com)
    if subdomain and any(kw in subdomain for kw in target_brand_info["keywords"]):
        result["is_brand_impersonation"] = True
        result["impersonation_type"] = "BRAND_SPOOF_IN_SUBDOMAIN"
        result["threat_severity"] = "CRITICAL"
        result["evidence"].append(
            f"Brand spoof in subdomain: '{subdomain}' on external host '{reg_domain}'"
        )
        return result

    # 4b. Punycode homograph tan cong brand
    if punycode_found and any(kw in unaccented_host for kw in target_brand_info["keywords"]):
        result["is_brand_impersonation"] = True
        result["impersonation_type"] = "PUNYCODE_HOMOGRAPH_SPOOF"
        result["threat_severity"] = "CRITICAL"
        result["evidence"].append(
            f"Punycode homograph attack on brand: '{decoded_host}' (simulates '{unaccented_host}')"
        )
        return result

    # 4c. Host la IP address chua brand trong path hoac query
    if is_ip:
        result["is_brand_impersonation"] = True
        result["impersonation_type"] = "IP_HOST_BRAND_HARVESTER"
        result["threat_severity"] = "CRITICAL"
        result["evidence"].append(
            f"IP address host '{host}' pretending to serve brand {b_name}"
        )
        return result

    # 4d. Registered domain typosquatting / gia mao brand
    # Vi du: momo-xacthuc.tk, zalo-nhanqua.com, vietcombank-ebank.xyz
    reg_lower = reg_domain.lower()
    for kw in target_brand_info["keywords"]:
        if kw in reg_lower:
            # Phat hien keyword lua dao hoac TLD dang ngo
            has_action_kw = any(act in url_lower for act in SPOOF_ACTION_KEYWORDS)
            tld = reg_domain.split(".")[-1]
            is_suspicious_tld = tld in {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw", "cc", "club", "site", "online"}

            if has_action_kw or is_suspicious_tld or "-" in reg_lower:
                result["is_brand_impersonation"] = True
                result["impersonation_type"] = "TYPOSQUAT_OR_FAKE_DOMAIN"
                result["threat_severity"] = "CRITICAL"
                result["evidence"].append(
                    f"Fake/Typosquat domain targeting {b_name}: '{reg_domain}' (action_kw={has_action_kw}, tld={tld})"
                )
                return result

    # 4e. Brand xuat hien trong path/query cua untrusted host kem tu khoa lua dao
    path_query = f"{path}?{query}".lower()
    has_action_in_path = any(act in path_query for act in SPOOF_ACTION_KEYWORDS)
    if any(kw in path_query for kw in target_brand_info["keywords"]) and has_action_in_path:
        result["is_brand_impersonation"] = True
        result["impersonation_type"] = "CREDENTIAL_HARVESTER_ON_UNTRUSTED_HOST"
        result["threat_severity"] = "SUSPICIOUS"
        result["evidence"].append(
            f"Untrusted host '{host}' with brand action path: {path_query[:60]}"
        )
        return result

    return result


def is_verified_official_vn_url(url: str) -> bool:
    """Kiem tra nhanh mot URL co phai la URL chinh thuc cua dich vu Viet Nam."""
    res = analyze_vietnamese_url(url)
    return res["is_official_asset"]
