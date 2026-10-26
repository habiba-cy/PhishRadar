"""
Phishing Detection System — Backend API
========================================
Step 1: XSS prevention, URL sanitization, in-memory cache
Step 2: Real external API integration — VirusTotal + Google Safe Browsing
"""

from flask import Flask, request, render_template, jsonify
import joblib
import numpy as np
import re
import html
import hashlib
import time
import os
import requests as http_requests
from urllib.parse import urlparse
import ssl
import socket
from datetime import datetime
from dotenv import load_dotenv
import tldextract

from url_features import (extract_url_features_ordered, normalize_url, is_valid_url, fetch_page_features, FEATURE_COLUMNS)

app = Flask(__name__)
load_dotenv()

HIGH_TRUST_DOMAINS = {
    "google.com", "instagram.com", "facebook.com", "fb.com", "microsoft.com",
    "apple.com", "amazon.com", "github.com", "linkedin.com", "paypal.com",
    "openai.com", "x.com", "twitter.com", "dropbox.com", "adobe.com",
    "notion.so", "notion.site", "icloud.com", "whatsapp.com", "telegram.org"
}


def root_domain_from_url(url: str) -> str:
    try:
        extracted = tldextract.extract(url)
        return ".".join(part for part in [extracted.domain, extracted.suffix] if part).lower()
    except Exception:
        return ""


def is_high_trust_domain(url: str) -> bool:
    return root_domain_from_url(url) in HIGH_TRUST_DOMAINS


def adjust_score_with_trust_signals(raw_ml_score, url, external, page_scan=None):
    ps = page_scan or {}
    vt = external.get("virustotal") or {}
    gsb = external.get("google_safe_browsing") or {}

    adjusted = float(raw_ml_score)
    vt_mal = int(vt.get("malicious", 0) or 0)
    vt_har = int(vt.get("harmless", 0) or 0)
    gsb_clean = not gsb.get("threat")
    login_form = bool(ps.get("login_form"))
    safe_form_handler = not bool(ps.get("sfh"))
    suspicious_keywords = len(ps.get("keyword_hits") or [])
    trusted_domain = is_high_trust_domain(url)

    if vt_mal >= 2 or not gsb_clean or (login_form and not safe_form_handler) or suspicious_keywords:
        return adjusted

    if trusted_domain and login_form and safe_form_handler and vt_mal == 0 and vt_har >= 20 and gsb_clean:
        return min(adjusted, 0.18)

    if vt_mal == 0 and vt_har >= 40 and gsb_clean:
        if login_form and safe_form_handler:
            return min(adjusted, 0.22)
        return min(adjusted, 0.24)

    if vt_mal == 0 and vt_har >= 15 and gsb_clean and login_form and safe_form_handler:
        return min(adjusted, 0.26)

    if trusted_domain and vt_mal == 1 and vt_har >= 20 and gsb_clean and login_form and safe_form_handler:
        return min(adjusted, 0.28)

    return adjusted

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "")
    if origin.startswith("chrome-extension://") or "127.0.0.1" in origin or "localhost" in origin:
        response.headers["Access-Control-Allow-Origin"]  = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response

@app.route("/predict", methods=["OPTIONS"])
def predict_preflight():
    return "", 204

# ─────────────────────────────────────────
# MODEL
# ─────────────────────────────────────────
model = joblib.load("phishing_model.pkl")

# ─────────────────────────────────────────
# API KEYS
# ─────────────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")

if not VIRUSTOTAL_API_KEY:
    raise ValueError("Missing VIRUSTOTAL_API_KEY in .env file")

if not GOOGLE_SAFE_BROWSING_KEY:
    raise ValueError("Missing GOOGLE_SAFE_BROWSING_KEY in .env file")

# ─────────────────────────────────────────
# CACHE
# ─────────────────────────────────────────
CACHE_TTL     = 600
API_CACHE_TTL = 3600

_cache     = {}
_api_cache = {}

def _key(url):
    return hashlib.md5(url.encode()).hexdigest()

def cache_get(url):
    k = _key(url); e = _cache.get(k)
    if e and time.time() < e["expires_at"]: return e["result"]
    _cache.pop(k, None); return None

def cache_set(url, result):
    _cache[_key(url)] = {"result": result, "expires_at": time.time() + CACHE_TTL}

def api_cache_get(url):
    k = _key(url); e = _api_cache.get(k)
    if e and time.time() < e["expires_at"]: return e["result"]
    _api_cache.pop(k, None); return None

def api_cache_set(url, result):
    _api_cache[_key(url)] = {"result": result, "expires_at": time.time() + API_CACHE_TTL}

def map_feature_values(features):
    return dict(zip(FEATURE_COLUMNS, features))


def get_ssl_certificate_info(url: str):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname or parsed.scheme != "https":
            return {
                "available": False,
                "status": "none",
                "issuer": None,
                "expires_at": None,
                "days_left": None,
            }

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        issuer_name = "Unknown issuer"
        for item in cert.get("issuer", []):
            for key, value in item:
                if key == "organizationName":
                    issuer_name = value
                    break

        not_after = cert.get("notAfter")
        expires_at = None
        days_left = None

        if not_after:
            expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expires_at = expiry_dt.strftime("%d %b %Y")
            days_left = (expiry_dt - datetime.utcnow()).days

        return {
            "available": True,
            "status": "valid",
            "issuer": issuer_name,
            "expires_at": expires_at,
            "days_left": days_left,
        }

    except Exception:
        return {
            "available": False,
            "status": "error",
            "issuer": None,
            "expires_at": None,
            "days_left": None,
        }

# ─────────────────────────────────────────
# SANITIZATION
# ─────────────────────────────────────────
def sanitize_url_input(raw):
    if not isinstance(raw, str): return ""
    cleaned = raw.strip()
    cleaned = re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', cleaned)
    cleaned = re.sub(r'<[^>]*>', '', cleaned)
    cleaned = re.sub(r' {2,}', ' ', cleaned)
    return cleaned[:2048]

def escape_for_display(text):
    return html.escape(str(text), quote=True)

# ─────────────────────────────────────────
# EXTERNAL APIs
# ─────────────────────────────────────────

def check_virustotal(url):
    """
    Calls the VirusTotal API v3.
    Submits the URL and returns how many vendors flagged it.
    The API key is at the top of this file: VIRUSTOTAL_API_KEY
    """
    try:
        import base64
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url_id  = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        # Try to get existing report first
        resp = http_requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=10
        )

        if resp.status_code == 404:
            # Not scanned before — submit it
            scan = http_requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers, data={"url": url}, timeout=10
            )
            if scan.status_code != 200:
                return None
            time.sleep(2)
            resp = http_requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers, timeout=10
            )

        if resp.status_code != 200:
            return None

        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless",   0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        if malicious >= 3:
            verdict = "malicious"
        elif malicious >= 1 or suspicious >= 3:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "malicious": malicious, "suspicious": suspicious,
            "harmless": harmless, "undetected": undetected,
            "total": total, "verdict": verdict
        }
    except Exception:
        return None


def check_google_safe_browsing(url):
    """
    Calls the Google Safe Browsing API v4.
    Checks if the URL is in Google's threat database.
    The API key is at the top of this file: GOOGLE_SAFE_BROWSING_KEY
    """
    try:
        payload = {
            "client": {"clientId": "phishradar-fyp", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}]
            }
        }
        resp = http_requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}",
            json=payload, timeout=10
        )
        if resp.status_code != 200:
            return None

        matches = resp.json().get("matches", [])
        if matches:
            return {
                "threat":  matches[0].get("threatType",   "UNKNOWN"),
                "platform": matches[0].get("platformType", "ANY"),
                "verdict": "dangerous"
            }
        return {"threat": None, "platform": None, "verdict": "clean"}
    except Exception:
        return None


def run_external_checks(url):
    cached = api_cache_get(url)
    if cached:
        cached["from_api_cache"] = True
        return cached

    vt  = check_virustotal(url)
    gsb = check_google_safe_browsing(url)

    any_flagged = any([
        vt  and vt.get("malicious",  0) >= 1,
        vt  and vt.get("suspicious", 0) >= 3,
        gsb and gsb.get("threat") is not None,
    ])

    result = {
        "virustotal": vt, "google_safe_browsing": gsb,
        "any_flagged": any_flagged, "from_api_cache": False
    }
    api_cache_set(url, result)
    return result


# ─────────────────────────────────────────
# FINAL VERDICT — ML + External + Page scan
# ─────────────────────────────────────────

def compute_final_verdict(ml_score, external, page_scan=None):
    vt  = external.get("virustotal")
    gsb = external.get("google_safe_browsing")
    ps  = page_scan or {}

    vt_mal = vt.get("malicious", 0) if vt else 0
    vt_har = vt.get("harmless", 0) if vt else 0

    if gsb and gsb.get("threat"):
        return "High risk of phishing", "high", 0.95

    if vt_mal >= 3:
        return "High risk of phishing", "high", max(ml_score, 0.90)

    if ps.get("login_form") and ps.get("sfh"):
        return "High risk of phishing", "high", max(ml_score, 0.90)

    if vt_har >= 20 and vt_mal == 0 and (not gsb or gsb.get("verdict") == "clean"):
        if ps.get("login_form") and not ps.get("sfh"):
            return "Likely safe", "safe", min(ml_score, 0.22)
        return "Likely safe", "safe", min(ml_score, 0.24)

    if vt_mal == 1 and vt_har >= 20 and (not gsb or gsb.get("verdict") == "clean"):
        if ps.get("login_form") and not ps.get("sfh"):
            return "Likely safe", "safe", min(ml_score, 0.28)
        return "Potentially suspicious", "medium", max(ml_score, 0.55)

    if vt_mal == 2:
        return "Potentially suspicious", "medium", max(ml_score, 0.65)

    if ps.get("login_form") and ml_score >= 0.80:
        return "Potentially suspicious", "medium", max(ml_score, 0.65)

    if ml_score >= 0.80:
        return "High risk of phishing", "high", ml_score
    if ml_score >= 0.50:
        return "Potentially suspicious", "medium", ml_score
    return "Likely safe", "safe", ml_score


# ─────────────────────────────────────────
# EXPLANATIONS (XAI)
# ─────────────────────────────────────────

def build_explanations(features, ml_score, external, page_scan=None):
    explanations = []
    vt  = external.get("virustotal")
    gsb = external.get("google_safe_browsing")
    ps  = page_scan or {}

    # 1. Google Safe Browsing
    if gsb and gsb.get("threat"):
        labels = {
            "SOCIAL_ENGINEERING": "Google Safe Browsing has flagged this as a phishing/social engineering site.",
            "MALWARE":            "Google Safe Browsing has flagged this URL as distributing malware.",
            "UNWANTED_SOFTWARE":  "Google Safe Browsing flagged this for distributing unwanted software.",
        }
        explanations.append(labels.get(gsb["threat"], f"Google Safe Browsing flagged this URL ({gsb['threat']})."))

    # 2. VirusTotal
    if vt:
        mal = vt.get("malicious", 0)
        har = vt.get("harmless",  0)
        tot = vt.get("total",     0)
        if mal >= 3:
            explanations.append(f"VirusTotal: {mal} of {tot} security vendors flagged this as malicious.")
        elif mal == 2:
            explanations.append(f"VirusTotal: {mal} vendor(s) flagged this URL — treat with caution.")
        elif mal == 1:
            if gsb and gsb.get("verdict") == "clean":
                explanations.append(f"VirusTotal: 1 vendor flagged this URL (Google Safe Browsing found no threat — this may be a false positive, but exercise caution).")
            else:
                explanations.append(f"VirusTotal: 1 vendor flagged this URL — treat with caution.")
        elif har > 10 and ml_score >= 0.50:
            if ps.get("sfh") or ps.get("keyword_hits") or features[2] == 1:
                explanations.append(
                    f"Although VirusTotal shows {har} vendors marking this URL as safe, stronger phishing indicators were detected on the page, so the final verdict remains high risk."
                    )
            else:
                explanations.append(
                    f"VirusTotal: {har} vendors confirmed this URL as safe, so the live reputation layer lowered the risk despite the raw ML model being conservative on login pages."
                )
                
    # 3. Page scan — login form detection
    if ps.get("page_fetched"):
        if ps.get("login_form") and ps.get("sfh"):
            explanations.append("A login form was detected on this page, and the form submits credentials to a different domain — a strong indicator of credential harvesting.")
        elif ps.get("login_form"):
            explanations.append("A login form with a password field was detected. This is normal for sign-in pages, and it is treated as high risk only when combined with suspicious external evidence or an unsafe form handler.")
        if ps.get("keyword_hits"):
            hits = ps["keyword_hits"][:2]
            explanations.append(f"The page content contains suspicious phrases: \"{hits[0]}\"{(' and \"' + hits[1] + '\"') if len(hits) > 1 else ''}.")

    # 4. ML features
    if ml_score >= 0.50:
        if features[0] > 75:
            explanations.append("The URL is unusually long, which is common in phishing attempts.")
        if features[3] > 3:
            explanations.append("The URL contains many dots, which can be used to confuse users.")
        if features[25] > 0.6:
            explanations.append("The URL contains an unusually high proportion of digits.")
        if features[80] == 0:
            explanations.append("WHOIS data is missing — the domain may be newly registered.")
        if features[2] == 1:
            explanations.append("The URL uses a raw IP address instead of a domain name.")

    if not explanations:
        explanations.append("No strong phishing indicators were found in this URL." if ml_score < 0.50 else "The model detected patterns commonly associated with phishing.")
    return explanations




def get_recommended_actions(risk_level, page_scan=None):
    ps = page_scan or {}

    if risk_level == "high":
        actions = [
            "Do not enter passwords, banking details, or personal information on this page.",
            "Close the website immediately and avoid clicking any links or buttons.",
            "Open the official website manually in a new tab instead of using this link.",
            "Report the suspicious page to your browser or security team if applicable."
        ]
        if ps.get("login_form") and ps.get("sfh"):
            actions.insert(1, "This page may be harvesting credentials, so do not submit the login form.")
        return actions

    if risk_level == "medium":
        actions = [
            "Double-check the domain name carefully before interacting with the page.",
            "Avoid entering sensitive information until the site is verified as legitimate.",
            "Try reaching the service through its official homepage instead of this URL.",
            "Use extra caution if the link came from email, SMS, or social media."
        ]
        return actions

    return [
        "Verify the URL carefully before signing in, especially on login pages.",
        "Use strong, unique passwords for important accounts.",
        "Enable two-factor authentication (2FA) where possible.",
        "Stay cautious with links received through emails, messages, or pop-ups."
    ]


# ─────────────────────────────────────────
# CORE ANALYSIS
# ─────────────────────────────────────────

def analyse_url(url):
    cached = cache_get(url)
    if cached:
        cached["from_cache"] = True
        return cached

    features       = extract_url_features_ordered(url)
    feature_map    = map_feature_values(features)
    features_array = np.array(features, dtype=float).flatten()
    prediction     = int(model.predict([features_array])[0])
    probability    = model.predict_proba([features_array])[0]
    raw_ml_score   = float(probability[1])

    external  = run_external_checks(url)
    page_scan = fetch_page_features(url, use_rendered_fallback=True)
    ml_score  = adjust_score_with_trust_signals(raw_ml_score, url, external, page_scan)

    parsed_url = urlparse(url)
    ssl_info = get_ssl_certificate_info(url)

    technical_checks = {
        "hostname": parsed_url.hostname or "",
        "dns_record": bool(feature_map.get("dns_record", 0)),
        "whois_registered": bool(feature_map.get("whois_registered_domain", 0)),
        "domain_age_days": int(feature_map.get("domain_age", 0) or 0),
        "registration_length_days": int(feature_map.get("domain_registration_length", 0) or 0),
        "ssl": ssl_info,
    }

    risk_label, risk_level, final_score = compute_final_verdict(ml_score, external, page_scan)
    explanations = build_explanations(features, ml_score, external, page_scan)
    recommended_actions = get_recommended_actions(risk_level, page_scan)

    result = {
        "url": url,
        "prediction": prediction,
        "score": final_score,
        "ml_score": ml_score,
        "raw_ml_score": raw_ml_score,
        "probability": [float(probability[0]), float(probability[1])],
        "risk_label": risk_label,
        "risk_level": risk_level,
        "explanations": explanations,
        "recommended_actions": recommended_actions,
        "external": external,
        "page_scan": page_scan,
        "technical_checks": technical_checks,
        "from_cache": False,
    }
    cache_set(url, result)
    return result


# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "GET":
        return render_template("index.html", result=None)

    clean_input = sanitize_url_input(request.form.get("url", ""))
    if not clean_input:
        return render_template("index.html", result={"error": "Please enter a URL.", "url_display": ""})

    url = normalize_url(clean_input)
    if not is_valid_url(url):
        return render_template("index.html", result={
            "error": "That doesn't look like a valid URL. Try: https://example.com",
            "url_display": escape_for_display(clean_input)
        })

    try:
        result = analyse_url(url)
        result["url_display"] = escape_for_display(url)
        return render_template("index.html", result=result)
    except Exception as e:
        return render_template("index.html", result={
            "error": f"Analysis failed: {escape_for_display(str(e))}",
            "url_display": escape_for_display(url)
        })


@app.route("/predict", methods=["POST"])
def predict_api():
    try:
        data    = request.get_json(silent=True) or {}
        raw_url = str(data.get("url", "")).strip()
        if not raw_url:
            return jsonify({"error": "No URL provided."}), 400

        clean_input = sanitize_url_input(raw_url)
        url         = normalize_url(clean_input)
        if not is_valid_url(url):
            return jsonify({"error": "Invalid URL format."}), 400

        return jsonify(analyse_url(url))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/cache/clear", methods=["GET", "POST"])
def clear_cache():
    count = len(_cache) + len(_api_cache)
    _cache.clear(); _api_cache.clear()
    return jsonify({"message": f"Cache cleared. {count} entries removed."})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "cache_entries": len(_cache),
        "api_cache_entries": len(_api_cache),
        "model_loaded": model is not None,
        "virustotal": "configured",
        "google_safe_browsing": "configured",
    })


if __name__ == "__main__":
    app.run(debug=True)
