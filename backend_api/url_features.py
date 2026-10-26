import re
import socket
from urllib.parse import urlparse
from datetime import datetime

import tldextract
import whois

FEATURE_COLUMNS = [
    'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens',
    'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
    'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma',
    'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com',
    'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url',
    'ratio_digits_host', 'punycode', 'port', 'tld_in_path',
    'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains',
    'prefix_suffix', 'random_domain', 'shortening_service',
    'path_extension', 'nb_redirection', 'nb_external_redirection',
    'length_words_raw', 'char_repeat', 'shortest_words_raw',
    'shortest_word_host', 'shortest_word_path', 'longest_words_raw',
    'longest_word_host', 'longest_word_path', 'avg_words_raw',
    'avg_word_host', 'avg_word_path', 'phish_hints', 'domain_in_brand',
    'brand_in_subdomain', 'brand_in_path', 'suspecious_tld',
    'statistical_report', 'nb_hyperlinks', 'ratio_intHyperlinks',
    'ratio_extHyperlinks', 'ratio_nullHyperlinks', 'nb_extCSS',
    'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors',
    'ratio_extErrors', 'login_form', 'external_favicon', 'links_in_tags',
    'submit_email', 'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe',
    'popup_window', 'safe_anchor', 'onmouseover', 'right_clic',
    'empty_title', 'domain_in_title', 'domain_with_copyright',
    'whois_registered_domain', 'domain_registration_length', 'domain_age',
    'web_traffic', 'dns_record', 'google_index', 'page_rank'
]

SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "tiny.cc", "cutt.ly", "rebrand.ly", "soo.gd"
}

SUSPICIOUS_WORDS = {
    "login", "secure", "bank", "verify", "update",
    "confirm", "signin", "password", "account", "wallet",
    "payment", "invoice", "reset", "recover", "unlock"
}

SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science",
    "work", "party", "gq", "link", "click", "top"
}

HIGH_TRUST_DOMAINS = {
    "google.com", "instagram.com", "facebook.com", "fb.com", "microsoft.com",
    "apple.com", "amazon.com", "github.com", "linkedin.com", "paypal.com",
    "openai.com", "x.com", "twitter.com", "dropbox.com", "adobe.com",
    "notion.so", "notion.site", "icloud.com", "whatsapp.com", "telegram.org"
}


def get_root_domain(hostname: str) -> str:
    if not hostname:
        return ""
    try:
        extracted = tldextract.extract(hostname)
        return ".".join(part for part in [extracted.domain, extracted.suffix] if part).lower()
    except Exception:
        return ""


def apply_live_reputation_hints(features: dict, hostname: str) -> dict:
    """Fill a few missing live-mode trust signals for exact high-trust domains."""
    root_domain = get_root_domain(hostname)
    if root_domain in HIGH_TRUST_DOMAINS:
        features["web_traffic"] = max(features.get("web_traffic", 0), 1)
        features["google_index"] = max(features.get("google_index", 0), 1)
        features["page_rank"] = max(features.get("page_rank", 0), 6)
    return features


def normalize_url(url: str) -> str:
    if not isinstance(url, str):
        return ""
    url = url.strip()
    if not url:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    return url


def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        if is_ip_address(hostname):
            return True
        if "." not in hostname:
            return False
        return True
    except Exception:
        return False


def is_ip_address(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        socket.inet_aton(hostname)
        return True
    except OSError:
        return False


def get_dns_record(hostname: str) -> int:
    if not hostname:
        return 0
    try:
        socket.gethostbyname(hostname)
        return 1
    except OSError:
        return 0


def get_whois_info(hostname: str):
    """
    Return (whois_registered_domain, domain_age_days, registration_length_days).

    FIX APPLIED: When WHOIS lookup fails (network timeout, rate limit, etc.)
    we now return (1, 0, 0) instead of (0, 0, 0).

    Why this matters:
      - Old behaviour: failure → whois_registered_domain = 0
        The model treats 0 as "unregistered/suspicious" → false high scores
        for real domains like google.com when WHOIS times out.
      - New behaviour: failure → whois_registered_domain = 1
        We assume "probably registered" — only domain_age stays at 0,
        which has a much smaller effect on the score.

    We also try both root_domain AND www.root_domain so that
    "google.com" gets the same lookup success as "www.google.com".
    """
    if not hostname:
        return 1, 0, 0   # unknown = assume registered

    try:
        extracted = tldextract.extract(hostname)
        root_domain = ".".join(
            part for part in [extracted.domain, extracted.suffix] if part
        )

        if not root_domain:
            return 1, 0, 0

        # ── Try root domain first, then www. prefix as fallback ──
        w = None
        for attempt in [root_domain, "www." + root_domain]:
            try:
                result = whois.whois(attempt)
                # Only accept the result if it actually has a domain name
                if result and result.domain_name:
                    w = result
                    break
            except Exception:
                continue   # try next attempt

        # ── If all WHOIS attempts failed, assume registered ──
        # We don't penalise domains just because our lookup timed out.
        if w is None:
            return 1, 0, 0

        registered = 1 if w.domain_name else 0

        creation_date   = w.creation_date
        expiration_date = w.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        now = datetime.utcnow()
        domain_age_days          = 0
        registration_length_days = 0

        if isinstance(creation_date, datetime):
            domain_age_days = max((now - creation_date).days, 0)

        if isinstance(creation_date, datetime) and isinstance(expiration_date, datetime):
            registration_length_days = max((expiration_date - creation_date).days, 0)

        return registered, domain_age_days, registration_length_days

    except Exception:
        return 1, 0, 0   # any unexpected error → assume registered


def safe_port(parsed) -> int:
    try:
        return parsed.port
    except ValueError:
        return None


def split_words(text: str):
    if not text:
        return []
    parts = re.split(r"[\/\.\-\_\=\?\&\%\#\:]+", text)
    return [p for p in parts if p]


def compute_word_stats(words):
    if not words:
        return 0, 0, 0, 0
    lengths = [len(w) for w in words]
    return len(words), min(lengths), max(lengths), sum(lengths) / len(lengths)


def has_repeated_chars(text: str, repeat_len: int = 3) -> int:
    if not text:
        return 0
    pattern = rf"(.)\1{{{repeat_len - 1},}}"
    return 1 if re.search(pattern, text) else 0


def extract_url_features(url):
    features = {col: 0 for col in FEATURE_COLUMNS}

    url = normalize_url(url)
    if not is_valid_url(url):
        return features

    parsed   = urlparse(url)
    extracted = tldextract.extract(url)

    hostname   = parsed.hostname or ""
    path       = parsed.path or ""
    port_value = safe_port(parsed)

    features["length_url"]      = len(url)
    features["length_hostname"] = len(hostname)
    features["ip"]              = 1 if is_ip_address(hostname) else 0

    features["nb_dots"]       = url.count(".")
    features["nb_hyphens"]    = url.count("-")
    features["nb_at"]         = url.count("@")
    features["nb_qm"]         = url.count("?")
    features["nb_and"]        = url.count("&")
    features["nb_or"]         = url.count("|")
    features["nb_eq"]         = url.count("=")
    features["nb_underscore"] = url.count("_")
    features["nb_tilde"]      = url.count("~")
    features["nb_percent"]    = url.count("%")
    features["nb_slash"]      = url.count("/")
    features["nb_star"]       = url.count("*")
    features["nb_colon"]      = url.count(":")
    features["nb_comma"]      = url.count(",")
    features["nb_semicolumn"] = url.count(";")
    features["nb_dollar"]     = url.count("$")
    features["nb_space"]      = url.count(" ")
    features["nb_www"]        = url.lower().count("www")
    features["nb_com"]        = url.lower().count(".com")
    features["nb_dslash"]     = url.count("//")

    features["http_in_path"]  = 1 if "http" in path.lower() else 0
    features["https_token"]   = 1 if parsed.scheme.lower() == "https" else 0

    nb_digits_url  = sum(c.isdigit() for c in url)
    nb_digits_host = sum(c.isdigit() for c in hostname)
    features["ratio_digits_url"]  = nb_digits_url  / len(url)      if url      else 0
    features["ratio_digits_host"] = nb_digits_host / len(hostname) if hostname else 0

    features["punycode"] = 1 if "xn--" in hostname.lower() else 0
    features["port"]     = 1 if port_value not in (80, 443, None) else 0

    features["tld_in_path"]      = 1 if extracted.suffix and extracted.suffix.lower() in path.lower()              else 0
    features["tld_in_subdomain"] = 1 if extracted.suffix and extracted.suffix.lower() in extracted.subdomain.lower() else 0

    if extracted.subdomain:
        features["nb_subdomains"] = extracted.subdomain.count(".") + 1
    else:
        features["nb_subdomains"] = 0

    features["abnormal_subdomain"] = 1 if features["nb_subdomains"] > 2 else 0
    features["prefix_suffix"]      = 1 if "-" in extracted.domain else 0
    features["random_domain"]      = 1 if re.fullmatch(r"[a-z0-9]{12,}", extracted.domain.lower() or "") else 0
    features["shortening_service"] = 1 if hostname.lower() in SHORTENING_SERVICES else 0
    features["suspecious_tld"]     = 1 if extracted.suffix.lower() in SUSPICIOUS_TLDS else 0

    features["path_extension"]          = 1 if re.search(r"\.[a-zA-Z0-9]{1,5}$", path) else 0
    features["nb_redirection"]          = max(url.lower().count("//") - 1, 0)
    features["nb_external_redirection"] = 0

    raw_words  = split_words(url)
    host_words = split_words(hostname)
    path_words = split_words(path)

    raw_count,  raw_shortest,  raw_longest,  raw_avg  = compute_word_stats(raw_words)
    host_count, host_shortest, host_longest, host_avg = compute_word_stats(host_words)
    path_count, path_shortest, path_longest, path_avg = compute_word_stats(path_words)

    features["length_words_raw"]   = raw_count
    features["char_repeat"]        = has_repeated_chars(url)
    features["shortest_words_raw"] = raw_shortest
    features["shortest_word_host"] = host_shortest
    features["shortest_word_path"] = path_shortest
    features["longest_words_raw"]  = raw_longest
    features["longest_word_host"]  = host_longest
    features["longest_word_path"]  = path_longest
    features["avg_words_raw"]      = raw_avg
    features["avg_word_host"]      = host_avg
    features["avg_word_path"]      = path_avg

    lower_url = url.lower()
    features["phish_hints"] = sum(1 for word in SUSPICIOUS_WORDS if word in lower_url)

    features["dns_record"] = get_dns_record(hostname)

    whois_registered, domain_age_days, registration_length_days = get_whois_info(hostname)
    features["whois_registered_domain"]   = whois_registered
    features["domain_age"]                = domain_age_days
    features["domain_registration_length"] = registration_length_days

    # Remaining features still set to 0 (require page fetch — done separately)
    zero_features = [
        "domain_in_brand", "brand_in_subdomain", "brand_in_path",
        "statistical_report", "nb_hyperlinks",
        "ratio_intHyperlinks", "ratio_extHyperlinks", "ratio_nullHyperlinks",
        "nb_extCSS", "ratio_intRedirection", "ratio_extRedirection",
        "ratio_intErrors", "ratio_extErrors", "login_form",
        "external_favicon", "links_in_tags", "submit_email",
        "ratio_intMedia", "ratio_extMedia", "sfh", "iframe",
        "popup_window", "safe_anchor", "onmouseover", "right_clic",
        "empty_title", "domain_in_title", "domain_with_copyright",
        "web_traffic", "google_index", "page_rank"
    ]
    for zf in zero_features:
        features[zf] = 0

    features = apply_live_reputation_hints(features, hostname)
    return features


def extract_url_features_ordered(url):
    """Returns features as a list in the exact order expected by the trained model."""
    feats = extract_url_features(url)
    return [feats[col] for col in FEATURE_COLUMNS]


# ─────────────────────────────────────────────────────────────────
# STEP 3 — PAGE CONTENT SCANNER (Login Form Detection)
# ─────────────────────────────────────────────────────────────────
# This function is called SEPARATELY from extract_url_features.
# It fetches the actual webpage HTML and scans it for signs of
# credential harvesting (fake login forms).
#
# WHY SEPARATE?
#   Feature extraction is fast (just string operations).
#   Page fetching is slow (network request, 2-5 seconds).
#   Keeping them separate means the ML prediction still runs
#   instantly — the page scan result is added on top.

import urllib.request
import urllib.error
from html.parser import HTMLParser

# Selenium fallback for JavaScript-heavy pages
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


# Words commonly found in phishing page bodies
PAGE_PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "update your information",
    "suspended", "unusual activity", "security alert", "verify now",
    "click here to verify", "your account will be", "limited access",
    "validate your", "authenticate", "re-enter your", "billing information"
]

# Suspicious form action keywords — form posts to these paths are suspicious
SUSPICIOUS_FORM_ACTIONS = [
    "steal", "harvest", "collect", "grab", "phish", "capture", "log",
    ".php", "submit.php", "login.php", "signin.php", "verify.php"
]


class _LoginFormParser(HTMLParser):
    """
    Simple HTML parser that scans a page for login form indicators.
    Works for both raw fetched HTML and Selenium-rendered HTML.
    """

    def __init__(self, page_hostname: str):
        super().__init__()
        self.page_hostname = page_hostname.lower()
        self.has_password_field = False
        self.has_email_field = False
        self.has_submit_button = False
        self.has_iframe = False
        self.form_actions = []
        self.page_title = ""
        self._in_title = False
        self._title_done = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = {k.lower(): (v or "").lower() for k, v in attrs}

        if tag == "input":
            input_type = attrs_dict.get("type", "text")
            if input_type == "password":
                self.has_password_field = True
            elif input_type in ("email", "text"):
                self.has_email_field = True
            elif input_type in ("submit", "button", "image"):
                self.has_submit_button = True

        elif tag == "button":
            self.has_submit_button = True

        elif tag == "form":
            action = attrs_dict.get("action", "")
            if action:
                self.form_actions.append(action)

        elif tag == "iframe":
            self.has_iframe = True

        elif tag == "title" and not self._title_done:
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
            self._title_done = True

    def handle_data(self, data):
        if self._in_title:
            self.page_title += data.strip()

    def is_sfh_suspicious(self) -> bool:
        for action in self.form_actions:
            if not action or action.startswith("#") or action.startswith("javascript"):
                continue

            if action.startswith("http"):
                try:
                    action_host = urlparse(action).hostname or ""
                    if action_host and self.page_hostname not in action_host:
                        return True
                except Exception:
                    continue

            for keyword in SUSPICIOUS_FORM_ACTIONS:
                if keyword in action:
                    return True

        return False


def _empty_page_scan_result() -> dict:
    return {
        "login_form": 0,
        "sfh": 0,
        "submit_email": 0,
        "iframe": 0,
        "empty_title": 0,
        "domain_in_title": 0,
        "has_login_form": False,
        "page_title": "",
        "keyword_hits": [],
        "sfh_suspicious": False,
        "page_fetched": False,
        "page_fetched_method": None,
        "rendered_analysis_used": False,
        "error": None,
    }


def _finalize_page_scan(html_text: str, hostname: str, method: str) -> dict:
    result = _empty_page_scan_result()
    result["page_fetched"] = True
    result["page_fetched_method"] = method
    result["rendered_analysis_used"] = method == "selenium"

    parser = _LoginFormParser(hostname)
    try:
        parser.feed(html_text)
    except Exception:
        pass

    has_login = parser.has_password_field and parser.has_submit_button
    result["has_login_form"] = has_login
    result["login_form"] = 1 if has_login else 0

    sfh_bad = parser.is_sfh_suspicious()
    result["sfh_suspicious"] = sfh_bad
    result["sfh"] = 1 if sfh_bad else 0

    result["submit_email"] = 1 if (parser.has_email_field and parser.has_submit_button) else 0
    result["iframe"] = 1 if parser.has_iframe else 0

    title = parser.page_title.strip()
    result["page_title"] = title
    result["empty_title"] = 1 if not title else 0

    if title and hostname:
        domain_parts = hostname.replace("www.", "").split(".")
        domain_name = domain_parts[0] if domain_parts else ""
        result["domain_in_title"] = 1 if (domain_name and domain_name in title.lower()) else 0

    html_lower = html_text.lower()
    result["keyword_hits"] = [kw for kw in PAGE_PHISHING_KEYWORDS if kw in html_lower]
    return result


def _fetch_page_features_requests(url: str) -> dict:
    result = _empty_page_scan_result()
    try:
        import requests as req_lib

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
        }

        response = req_lib.get(
            url,
            headers=headers,
            timeout=8,
            allow_redirects=True,
            verify=False,
            stream=True,
        )

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            result["error"] = f"Not an HTML page ({content_type})"
            return result

        raw_bytes = b""
        for chunk in response.iter_content(chunk_size=8192):
            raw_bytes += chunk
            if len(raw_bytes) >= 200_000:
                break

        try:
            html_text = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            html_text = raw_bytes.decode("latin-1", errors="replace")

        return _finalize_page_scan(html_text, hostname, method="requests")

    except Exception as e:
        result["error"] = f"Page scan failed: {str(e)[:80]}"
        return result


def _should_try_rendered_fallback(url: str, result: dict) -> bool:
    if not result.get("page_fetched"):
        return True
    if result.get("login_form"):
        return False

    lowered = url.lower()
    login_like = any(token in lowered for token in ["login", "signin", "sign-in", "auth", "account", "password", "verify"])

    return any([
        result.get("empty_title") == 1,
        result.get("page_title", "").strip() == "",
        login_like,
    ])


def _fetch_page_features_selenium(url: str) -> dict:
    result = _empty_page_scan_result()
    driver = None
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--window-size=1400,1000")
        options.add_argument(
            "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        )

        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.set_page_load_timeout(15)
        driver.get(url)
        driver.implicitly_wait(3)
        html_text = driver.page_source or ""

        finalized = _finalize_page_scan(html_text, hostname, method="selenium")

        if not finalized.get("page_title"):
            try:
                browser_title = (driver.title or "").strip()
                if browser_title:
                    finalized["page_title"] = browser_title
                    finalized["empty_title"] = 0
                    domain_parts = hostname.replace("www.", "").split(".")
                    domain_name = domain_parts[0] if domain_parts else ""
                    finalized["domain_in_title"] = 1 if (domain_name and domain_name in browser_title.lower()) else 0
            except Exception:
                pass

        return finalized

    except Exception as e:
        result["error"] = f"Rendered page scan failed: {str(e)[:120]}"
        return result
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass


def fetch_page_features(url: str, use_rendered_fallback: bool = False) -> dict:
    """
    Fast requests-based page scan first.
    Optional Selenium fallback for JavaScript-heavy pages.
    """
    result = _fetch_page_features_requests(url)

    if not use_rendered_fallback:
        return result

    if not _should_try_rendered_fallback(url, result):
        return result

    rendered = _fetch_page_features_selenium(url)
    if rendered.get("page_fetched"):
        return rendered

    # Keep original fast result, but preserve Selenium error for debugging.
    result["rendered_analysis_used"] = False
    if rendered.get("error") and not result.get("error"):
        result["error"] = rendered["error"]
    return result
