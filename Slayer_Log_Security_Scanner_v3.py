#!/usr/bin/env python3
"""
Slayer Log Security Scanner — crafted by Slayer
Slayer Log Security Scanner v3.0
--------------------------------------
Captures logcat output for a given package PID (catches ALL process logs,
not just lines containing the package name), then scans for sensitive data
and produces a pretty HTML report + plain text report.

Philosophy: BROAD patterns — catch everything, false positives expected.
            Human review filters noise. Missing real findings is unacceptable.
"""

import subprocess, sys, os, re, threading, argparse, math, collections
from datetime import datetime
from pathlib import Path
import html as html_module

# ── ANSI colours ──────────────────────────────────────────────────────────────
USE_COLOR = sys.stdout.isatty() and os.name != "nt"
def c(t, code): return f"\033[{code}m{t}\033[0m" if USE_COLOR else t
RED     = lambda t: c(t, "91")
YELLOW  = lambda t: c(t, "93")
GREEN   = lambda t: c(t, "92")
CYAN    = lambda t: c(t, "96")
BOLD    = lambda t: c(t, "1")
DIM     = lambda t: c(t, "2")

# ── Shannon entropy ────────────────────────────────────────────────────────────
def shannon_entropy(s):
    if not s: return 0.0
    freq = collections.Counter(s)
    length = len(s)
    return -sum((f/length) * math.log2(f/length) for f in freq.values())

# ── Entropy-based secret scan ─────────────────────────────────────────────────
# Looks for high-entropy tokens that regex cannot catch
# Ignores known-safe patterns (hex addresses, timestamps, class names)
ENTROPY_THRESHOLD = 3
ENTROPY_MIN_LEN   = 20
ENTROPY_MAX_LEN   = 500

# Patterns that look high-entropy but are NOT secrets
ENTROPY_SAFE_RE = re.compile(
    r'(?:'
    r'0x[0-9a-fA-F]{6,}'               # hex memory addresses
    r'|[0-9a-fA-F]{8,}(?:#\d+)?'       # layer IDs / buffer IDs
    r'|\d{13,}'                          # long numbers (timestamps)
    r'|(?:[A-Za-z]+\.){3,}[A-Za-z]+'   # java class names
    r'|Rect\([0-9, \-]+\)'              # Rect(...)
    r'|Point\([0-9, \-]+\)'             # Point(...)
    r')'
)

def find_high_entropy_tokens(line):
    """Extract tokens from a line and return those with high entropy."""
    # Split on common delimiters, keeping tokens
    tokens = re.findall(r'[A-Za-z0-9+/=_\-\.]{' + str(ENTROPY_MIN_LEN) + r',' + str(ENTROPY_MAX_LEN) + r'}', line)
    hits = []
    for tok in tokens:
        if ENTROPY_SAFE_RE.fullmatch(tok):
            continue
        # Skip if it's all one character class (all digits, all hex, all alpha)
        if re.fullmatch(r'[0-9]+', tok): continue
        if re.fullmatch(r'[a-fA-F0-9]+', tok) and len(tok) <= 64: continue
        if re.fullmatch(r'[a-zA-Z]+', tok): continue
        ent = shannon_entropy(tok)
        if ent >= ENTROPY_THRESHOLD:
            hits.append((tok, round(ent, 2)))
    return hits

# ── Sensitive patterns ─────────────────────────────────────────────────────────
# (label, confidence, regex)
SENSITIVE_PATTERNS = [

    # ── Auth / Tokens ──────────────────────────────────────────────────────────
    ("JWT / Bearer token", "HIGH",
     re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')),

    ("Authorization header", "HIGH",
     re.compile(r'Authorization:\s*(?:Bearer|Basic|Token)\s+[A-Za-z0-9\-\._~\+\/]+=*', re.I)),

    ("Auth token (keyword=value)", "HIGH",
     re.compile(r'auth[_\-]?token[\s]*[=:>\'"\s]+[A-Za-z0-9+/=_\-]{20,}', re.I)),

    ("JSON token field", "HIGH",
     re.compile(r'"(?:token|accessToken|refreshToken|authToken|idToken|bearerToken)"'
                r'\s*:\s*"[^"]{10,}"', re.I)),

    ("Access / refresh token (keyword)", "HIGH",
     re.compile(r'(?:access[_\-]?token|refresh[_\-]?token|id[_\-]?token)'
                r'[\s]*[=:>\'"\s]+\S{15,}', re.I)),

    ("Bearer header", "HIGH",
     re.compile(r'[Bb]earer\s+[A-Za-z0-9+/=_\-\.]{20,}')),

    ("API key / secret", "HIGH",
     re.compile(r'(?:api[_\-]?key|api[_\-]?secret|client[_\-]?secret)'
                r'[\s]*[=:>\'"\s]+\S{10,}', re.I)),

    ("Password in log", "HIGH",
     re.compile(r'(?:password|passwd|pwd)[\s]*[=:>\'"\s]+\S{4,}', re.I)),

    ("Session cookie", "HIGH",
     re.compile(r'(?:cookie|set-cookie)[\s]*[:=][^\s\r\n]{10,}', re.I)),

    ("Firebase / FCM token", "HIGH",
     re.compile(r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{100,}')),

    # ── PII ────────────────────────────────────────────────────────────────────
    ("Mobile number (keyword)", "HIGH",
     re.compile(
         r'(?:mobile[_\-]?(?:number|num|no)?|phone[_\-]?(?:number|num|no)?'
         r'|msisdn|mobileNumber|phoneNumber|contactNo|ph[_\-]?no|mob)'
         r'[\s:=\'",]+(?:\+?91[\s\-]?)?[6-9]\d{9}',
         re.I
     )),

    ("Mobile number (+91 prefix)", "MEDIUM",
     re.compile(r'(?<!\d)\+?91[\s\-]?[6-9]\d{9}(?!\d)')),

    ("Mobile number (bare 10-digit)", "LOW",
     re.compile(r'(?<![.\d])[6-9]\d{9}(?!\d)')),

    ("Email address", "HIGH",
     re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')),

    ("Device ID (keyword)", "HIGH",
     re.compile(r'device[_\-]?id[\s]*[=:\'"\s]+[A-Za-z0-9]{8,}', re.I)),

    ("Customer / Merchant ID", "HIGH",
     re.compile(r'(?:merchant|customer)[_\-]?(?:custom|customer)?[_\-]?id'
                r'[\s]*[=:\'"\s]+[A-Za-z0-9]{4,}', re.I)),

    ("JSON PII fields", "HIGH",
     re.compile(r'"(?:mobileNumber|phoneNumber|emailId|email|fullName|firstName'
                r'|lastName|customerId|userId|accountNumber|dateOfBirth|dob)"'
                r'\s*:\s*"[^"]{2,}"', re.I)),

    ("Name field", "MEDIUM",
     re.compile(r'(?:full[_\-]?name|first[_\-]?name|last[_\-]?name|customer[_\-]?name)'
                r'[\s]*[=:\'"\s]+[A-Za-z ]{3,}', re.I)),

    ("Date of birth", "HIGH",
     re.compile(r'(?:dob|date[_\-]?of[_\-]?birth|birth[_\-]?date)'
                r'[\s]*[=:\'"\s]+[\d\-/]{6,}', re.I)),

    ("Aadhaar number", "HIGH",
     re.compile(r'(?:aadhaar|aadhar|uid)[\s]*[=:\'"\s]+\d{4}[\s\-]?\d{4}[\s\-]?\d{4}', re.I)),

    ("PAN card (keyword)", "HIGH",
     re.compile(r'(?:pan|pan[_\-]?(?:number|no|card))[\s]*[=:\'"\s]+[A-Z]{5}[0-9]{4}[A-Z]', re.I)),

    ("PAN card (bare pattern)", "MEDIUM",
     re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b')),

    ("UUID / GUID identifier", "MEDIUM",
     re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b', re.I)),

    # ── Payment / Banking ──────────────────────────────────────────────────────
    ("UPI URI", "HIGH",
     re.compile(r'upi://[^\s\'">{]+')),

    ("UPI VPA", "HIGH",
     re.compile(r'pa=[A-Za-z0-9.\-_@]+')),

    ("Transaction ID", "MEDIUM",
     re.compile(r'(?:txn[_\-]?id|transaction[_\-]?id|utr|rrn)[\s]*[=:\'"\s]+[A-Za-z0-9]{8,}', re.I)),

    ("Card number (keyword)", "HIGH",
     re.compile(r'(?:card[_\-]?(?:number|num|no)|pan\b|cc[_\-]?(?:number|num))'
                r'[\s]*[=:>\'"\s]+\d{13,19}', re.I)),

    ("Card number (grouped format)", "HIGH",
     re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))(?:[\s\-]\d{4}){3}\b')),

    ("16-digit number (possible card)", "LOW",
     re.compile(r'(?<!\d)\d{16}(?!\d)')),

    ("CVV", "HIGH",
     re.compile(r'\bcvv[\s]*[=:>\'"\s]+\d{3,4}\b', re.I)),

    ("Bank account number", "MEDIUM",
     re.compile(r'(?:account[_\-]?(?:number|num|no)|acc[_\-]?no)[\s]*[=:\'"\s]+\d{9,18}', re.I)),

    ("IFSC code", "HIGH",
     re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b')),

    ("IBAN number", "HIGH",
     re.compile(r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b')),

    # ── Crypto / Signatures / Keys ─────────────────────────────────────────────
    ("RSA / HMAC signature", "HIGH",
     re.compile(r'"?(?:signature|signaturePayload|signed[_\-]?token)"?'
                r'\s*[=:]\s*[\'"]?[A-Za-z0-9+/=_\-]{40,}', re.I)),

    ("AES key candidate", "MEDIUM",
     re.compile(r'(?:aes|secret|key|enckey|enc[_\-]?key)[\s:=]{1,5}[A-Za-z0-9+/]{24,}={0,2}', re.I)),

    ("Private key header", "HIGH",
     re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----')),

    ("AWS access key", "HIGH",
     re.compile(r'AKIA[0-9A-Z]{16}')),

    ("Large base64 blob", "LOW",
     re.compile(r'[A-Za-z0-9+/]{60,}={0,2}')),

    # ── Network / Infrastructure ───────────────────────────────────────────────
    ("Private IP address", "MEDIUM",
     re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                r'|192\.168\.\d{1,3}\.\d{1,3}'
                r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b')),

    ("Localhost / internal URL", "MEDIUM",
     re.compile(r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)[:/]', re.I)),

    ("Internal env URL", "MEDIUM",
     re.compile(r'https?://[a-z0-9\-\.]+\.(?:sit|uat|staging|dev|test|internal|local|corp)[:/]', re.I)),

    # ── OTP / PIN ──────────────────────────────────────────────────────────────
    ("OTP value", "HIGH",
     re.compile(r'\botp[\s]*[=:>\'"\s]+\d{4,8}\b', re.I)),

    ("PIN value", "HIGH",
     re.compile(r'\bpin[\s]*[=:>\'"\s]+\d{4,6}\b', re.I)),

    # ── Device ────────────────────────────────────────────────────────────────
    ("IMEI", "HIGH",
     re.compile(r'\bimei[\s]*[=:>\'"\s]+\d{15}\b', re.I)),

    ("SIM serial", "HIGH",
     re.compile(r'sim[_\-]?serial[\s]*[=:>\'"\s]+\S{5,}', re.I)),

    # ── Secret keywords ────────────────────────────────────────────────────────
    ("Secret / encryption key", "HIGH",
     re.compile(r'"?(?:secret|private[_\-]?key|encryption[_\-]?key|access[_\-]?key)"?'
                r'\s*[=:]\s*[\'"]?\S{8,}', re.I)),

    ("Hardcoded credential", "MEDIUM",
     re.compile(r'(?:^|\s)(?:username|login)[\s]*[=:][\s]*[\'"\s]*\S{4,}', re.I)),
]

CONF_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# ── Noise filters ──────────────────────────────────────────────────────────────
# Lines matching these are skipped for the associated pattern label
NOISE_FILTERS = [
    ("Hardcoded credential",
     re.compile(r'(?:GetCredential|ActivityRecord|GrantPermissions|WindowManager'
                r'|SurfaceFlinger|BufferQueue|InputDispatcher|Transition|Layer)'
                r'.*[Cc]redential', re.I)),
    ("Mobile number (bare 10-digit)",
     re.compile(r'(?:timestamp=\d{10,}|SyncId|focusRequests|windowName=|pid=\d)')),
    ("16-digit number (possible card)",
     re.compile(r'(?:timestamp=|graphicBufferId=|id:-1|mTimestamp=)')),
    ("Large base64 blob",
     re.compile(r'(?:SurfaceFlinger|BufferQueue|WindowManager|InsetsState'
                r'|cutoutSpec=|mDisplayShape|ViewRootImpl|SyncRtSurface)', re.I)),
    ("IBAN number",
     re.compile(r'(?:ActivityRecord|WindowManager|SurfaceFlinger|BufferQueue'
                r'|InsetsSource|Transition|RGBA)', re.I)),
    ("UUID / GUID identifier",
     re.compile(r'(?:requestId|traceId|spanId|correlationId)')),  # keep these, not noise
]

# ── ADB helpers ───────────────────────────────────────────────────────────────
def check_adb():
    try:
        r = subprocess.run(["adb", "version"], capture_output=True, text=True)
        if r.returncode != 0: raise FileNotFoundError
    except FileNotFoundError:
        print(RED("✗ 'adb' not found. Install Android Platform Tools and add to PATH."))
        sys.exit(1)

def check_device():
    r = subprocess.run(["adb", "devices"], capture_output=True, text=True)
    lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    devs  = [l for l in lines[1:] if "device" in l and "offline" not in l]
    if not devs:
        print(RED("✗ No device detected. Connect device and enable USB debugging."))
        sys.exit(1)
    print(GREEN(f"✓ Device connected: {devs[0].split()[0]}"))

def clear_logcat():
    subprocess.run(["adb", "logcat", "-c"], capture_output=True)
    print(GREEN("✓ Logcat buffer cleared."))

def get_pid(package):
    """Get PID for the running package. Returns None if not found."""
    try:
        r = subprocess.run(["adb", "shell", "pidof", package],
                           capture_output=True, text=True, timeout=5)
        pids = r.stdout.strip().split()
        if pids:
            print(GREEN(f"✓ Found PID {pids[0]} for {package}"))
            return pids[0]
    except Exception:
        pass
    # fallback: ps aux
    try:
        r = subprocess.run(["adb", "shell", "ps", "-A"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if package in line:
                parts = line.split()
                if len(parts) > 1:
                    print(GREEN(f"✓ Found PID {parts[1]} for {package} (via ps)"))
                    return parts[1]
    except Exception:
        pass
    print(YELLOW("⚠  Could not get PID — falling back to package-name line filter."))
    return None

# ── Capture ───────────────────────────────────────────────────────────────────
stop_flag = threading.Event()
log_lines = []

def capture_logcat(package, pid, log_file):
    """
    Capture strategy:
    - If PID known: use --pid flag (catches ALL logs from that process,
      including OkHttp, WebView, System.out, ActivityManager etc.)
    - Fallback: filter lines containing the package name
    """
    if pid:
        cmd = ["adb", "logcat", "--pid", pid]
        filter_fn = lambda line: True  # PID filter is done by adb
    else:
        cmd = ["adb", "logcat"]
        filter_fn = lambda line: package in line

    with open(log_file, "w", encoding="utf-8", errors="replace") as f:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                text=True, encoding="utf-8", errors="replace")
        while not stop_flag.is_set():
            line = proc.stdout.readline()
            if line == "" and proc.poll() is not None: break
            if line and filter_fn(line):
                f.write(line); f.flush()
                log_lines.append(line.rstrip())
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()

# ── Scan ──────────────────────────────────────────────────────────────────────
def scan_logs(lines, extra_patterns):
    all_p = list(SENSITIVE_PATTERNS)
    for pat in extra_patterns:
        all_p.append((f"Custom: '{pat.pattern}'", "HIGH", pat))

    findings = {}

    for i, line in enumerate(lines, 1):
        # ── Regex patterns ──
        for label, conf, pat in all_p:
            skip = any(
                noise_lbl in label and noise_pat.search(line)
                for noise_lbl, noise_pat in NOISE_FILTERS
            )
            if skip: continue
            m = pat.search(line)
            if m:
                findings.setdefault(("REGEX", conf, label), []).append(
                    (i, line, m.group(0), None))

        # ── Entropy detection ──
        entropy_hits = find_high_entropy_tokens(line)
        for tok, ent in entropy_hits:
            # Skip if already caught by a regex pattern
            already_caught = any(
                m_val == tok
                for hits in findings.values()
                for _, _, m_val, _ in hits
            )
            if not already_caught:
                findings.setdefault(
                    ("ENTROPY", "MEDIUM", f"High-entropy token (entropy={ent})"), []
                ).append((i, line, tok, ent))

    return findings

# ── HTML report ───────────────────────────────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Logcat Security Report — {package}</title>
<style>
  :root {{
    --bg:#0f1117;--surface:#1a1d27;--surface2:#22263a;--border:#2e3150;
    --text:#e2e8f0;--muted:#8892a4;
    --high:#ff4d6d;--high-bg:#2d0a14;--high-border:#7f1d2e;
    --med:#f59e0b;--med-bg:#1f1400;--med-border:#78350f;
    --low:#64748b;--low-bg:#131720;--low-border:#334155;
    --entropy:#a78bfa;--entropy-bg:#1a1040;--entropy-border:#5b21b6;
    --accent:#6366f1;--accent2:#818cf8;
    --match-bg:#2d1f00;--match-text:#fbbf24;
    --radius:10px;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6}}
  .header{{background:linear-gradient(135deg,#1e1b4b 0%,#312e81 50%,#1e1b4b 100%);
    border-bottom:1px solid var(--border);padding:28px 32px 24px}}
  .header h1{{font-size:22px;font-weight:700;color:#fff;letter-spacing:-.3px}}
  .header h1 span{{color:var(--accent2)}}
  .header .meta{{color:#a5b4fc;font-size:12px;margin-top:6px}}
  .summary{{display:flex;gap:14px;padding:20px 32px;flex-wrap:wrap}}
  .card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
    padding:16px 22px;min-width:130px;flex:1}}
  .card .num{{font-size:32px;font-weight:800;line-height:1}}
  .card .lbl{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-top:4px}}
  .card.total .num{{color:var(--accent2)}}
  .card.high  .num{{color:var(--high)}}
  .card.med   .num{{color:var(--med)}}
  .card.low   .num{{color:var(--low)}}
  .card.entropy .num{{color:var(--entropy)}}
  .toolbar{{display:flex;gap:10px;align-items:center;padding:0 32px 16px;flex-wrap:wrap}}
  .search-box{{flex:1;min-width:200px;background:var(--surface);border:1px solid var(--border);
    border-radius:8px;padding:8px 14px;color:var(--text);font-size:13px;outline:none}}
  .search-box:focus{{border-color:var(--accent)}}
  .search-box::placeholder{{color:var(--muted)}}
  .filter-btns{{display:flex;gap:6px;flex-wrap:wrap}}
  .fbtn{{padding:7px 14px;border-radius:20px;border:1px solid;font-size:12px;
    font-weight:600;cursor:pointer;transition:all .15s;background:transparent}}
  .fbtn.all{{border-color:var(--accent);color:var(--accent2)}}
  .fbtn.high{{border-color:var(--high-border);color:var(--high)}}
  .fbtn.med{{border-color:var(--med-border);color:var(--med)}}
  .fbtn.low{{border-color:var(--low-border);color:var(--low)}}
  .fbtn.entropy{{border-color:var(--entropy-border);color:var(--entropy)}}
  .fbtn.active,.fbtn:hover{{color:#fff}}
  .fbtn.all.active,.fbtn.all:hover{{background:var(--accent);border-color:var(--accent)}}
  .fbtn.high.active,.fbtn.high:hover{{background:var(--high);border-color:var(--high)}}
  .fbtn.med.active,.fbtn.med:hover{{background:var(--med);border-color:var(--med)}}
  .fbtn.low.active,.fbtn.low:hover{{background:var(--low);border-color:var(--low)}}
  .fbtn.entropy.active,.fbtn.entropy:hover{{background:var(--entropy);border-color:var(--entropy)}}
  .count-info{{font-size:12px;color:var(--muted);margin-left:auto}}
  .findings{{padding:0 32px 40px;display:flex;flex-direction:column;gap:12px}}
  .finding{{background:var(--surface);border:1px solid var(--border);
    border-radius:var(--radius);overflow:hidden;transition:border-color .15s}}
  .finding:hover{{border-color:#3d4266}}
  .finding.high{{border-left:3px solid var(--high)}}
  .finding.medium{{border-left:3px solid var(--med)}}
  .finding.low{{border-left:3px solid var(--low)}}
  .finding.entropy{{border-left:3px solid var(--entropy)}}
  .finding-header{{display:flex;align-items:center;gap:10px;padding:13px 18px;
    cursor:pointer;user-select:none}}
  .finding-header:hover{{background:var(--surface2)}}
  .badge{{font-size:10px;font-weight:700;padding:3px 8px;border-radius:4px;
    text-transform:uppercase;letter-spacing:.6px;white-space:nowrap}}
  .badge.high{{background:var(--high-bg);color:var(--high);border:1px solid var(--high-border)}}
  .badge.medium{{background:var(--med-bg);color:var(--med);border:1px solid var(--med-border)}}
  .badge.low{{background:var(--low-bg);color:var(--low);border:1px solid var(--low-border)}}
  .badge.entropy{{background:var(--entropy-bg);color:var(--entropy);border:1px solid var(--entropy-border)}}
  .finding-title{{font-weight:600;font-size:14px;flex:1}}
  .hit-count{{font-size:12px;color:var(--muted);background:var(--surface2);
    padding:2px 10px;border-radius:12px;white-space:nowrap}}
  .chevron{{color:var(--muted);font-size:12px;transition:transform .2s}}
  .finding.open .chevron{{transform:rotate(180deg)}}
  .finding-body{{display:none;border-top:1px solid var(--border)}}
  .finding.open .finding-body{{display:block}}
  .hit{{padding:10px 18px;border-bottom:1px solid var(--border);font-size:12px}}
  .hit:last-child{{border-bottom:none}}
  .hit-meta{{color:var(--muted);font-size:11px;margin-bottom:4px}}
  .hit-line{{font-family:'Cascadia Code','Consolas','Courier New',monospace;
    background:var(--surface2);border-radius:5px;padding:7px 10px;
    word-break:break-all;white-space:pre-wrap;line-height:1.5;color:#c8d3e6}}
  .hit-match{{background:var(--match-bg);color:var(--match-text);
    border-radius:3px;padding:0 3px;font-weight:600}}
  .hit-matched-val{{margin-top:6px;font-family:monospace;font-size:11px;
    color:var(--match-text);background:var(--match-bg);
    padding:4px 10px;border-radius:4px;word-break:break-all}}
  .no-results{{text-align:center;padding:60px;color:var(--muted);display:none}}
  .footer{{text-align:center;padding:20px;color:var(--muted);font-size:11px;
    border-top:1px solid var(--border)}}
  ::-webkit-scrollbar{{width:6px}}
  ::-webkit-scrollbar-track{{background:var(--bg)}}
  ::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 Logcat Security Scanner — <span>{package}</span></h1>
  <div class="meta">Generated: {generated} &nbsp;|&nbsp; {log_file} &nbsp;|&nbsp; {total_lines} lines scanned &nbsp;|&nbsp; PID capture: {pid_mode}</div><div class="meta" style="margin-top:4px;opacity:.5;font-size:11px;letter-spacing:.3px">crafted by Slayer</div>
</div>
<div class="summary">
  <div class="card total">  <div class="num">{total}</div>    <div class="lbl">Total Findings</div></div>
  <div class="card high">   <div class="num">{high}</div>     <div class="lbl">High Confidence</div></div>
  <div class="card med">    <div class="num">{medium}</div>   <div class="lbl">Medium Confidence</div></div>
  <div class="card low">    <div class="num">{low}</div>      <div class="lbl">Low Confidence</div></div>
  <div class="card entropy"><div class="num">{entropy_c}</div><div class="lbl">Entropy Secrets</div></div>
  <div class="card" style="border-color:#2e3150"><div class="num" style="color:#e2e8f0">{cats}</div><div class="lbl">Categories</div></div>
</div>
<div class="toolbar">
  <input class="search-box" type="text" id="searchBox" placeholder="🔎  Search findings, matched values, line content…">
  <div class="filter-btns">
    <button class="fbtn all active"   onclick="setFilter('all')"    >All</button>
    <button class="fbtn high"         onclick="setFilter('high')"   >HIGH</button>
    <button class="fbtn med"          onclick="setFilter('medium')" >MEDIUM</button>
    <button class="fbtn low"          onclick="setFilter('low')"    >LOW</button>
    <button class="fbtn entropy"      onclick="setFilter('entropy')">ENTROPY</button>
  </div>
  <span class="count-info" id="countInfo"></span>
</div>
<div class="findings" id="findings">{findings_html}</div>
<div class="no-results" id="noResults"><div style="font-size:40px;margin-bottom:12px">🎉</div><div>No findings match your filter / search.</div></div>
<div class="footer">Android Logcat Security Scanner v3.0 &nbsp;|&nbsp; crafted by <span style="color:var(--accent2);letter-spacing:.5px">Slayer</span> &nbsp;|&nbsp; False positives expected — review all findings carefully.</div>
<script>
let currentFilter='all';
function setFilter(f){{
  currentFilter=f;
  document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));
  const map={{all:'all',high:'high',medium:'med',low:'low',entropy:'entropy'}};
  document.querySelector('.fbtn.'+(map[f]||f)).classList.add('active');
  applyFilters();
}}
function applyFilters(){{
  const q=document.getElementById('searchBox').value.toLowerCase();
  const cards=document.querySelectorAll('.finding');
  let visible=0;
  cards.forEach(card=>{{
    const conf=card.dataset.conf;
    const text=card.dataset.search;
    const matchF=currentFilter==='all'||conf===currentFilter;
    const matchQ=!q||text.includes(q);
    const show=matchF&&matchQ;
    card.style.display=show?'':'none';
    if(show)visible++;
  }});
  document.getElementById('noResults').style.display=visible===0?'block':'none';
  document.getElementById('countInfo').textContent=`Showing ${{visible}} of ${{cards.length}} categories`;
}}
function toggle(el){{el.closest('.finding').classList.toggle('open');}}
document.getElementById('searchBox').addEventListener('input',applyFilters);
document.querySelectorAll('.finding.high').forEach(f=>f.classList.add('open'));
applyFilters();
</script>
</body></html>"""

FINDING_CARD = """<div class="finding {conf_lc}" data-conf="{conf_lc}" data-search="{search_text}">
  <div class="finding-header" onclick="toggle(this)">
    <span class="badge {conf_lc}">{badge_label}</span>
    <span class="finding-title">{label}</span>
    <span class="hit-count">{count} hit{plural}</span>
    <span class="chevron">▼</span>
  </div>
  <div class="finding-body">{hits_html}</div>
</div>"""

HIT_ROW = """<div class="hit">
  <div class="hit-meta">Line {line_no}{entropy_info}</div>
  <div class="hit-line">{line_highlighted}</div>
  <div class="hit-matched-val">▶ {matched_val}</div>
</div>"""

def highlight_match(line_text, matched):
    esc_line    = html_module.escape(line_text)
    esc_matched = html_module.escape(matched)
    return esc_line.replace(esc_matched,
        f'<span class="hit-match">{esc_matched}</span>', 1)

def build_html_report(findings, package, log_file, total_lines, pid_used):
    sorted_items = sorted(findings.items(),
        key=lambda x: (CONF_ORDER.get(x[0][1], 3), -len(x[1])))

    total = sum(len(v) for v in findings.values())
    high_c = sum(len(v) for (t,cf,_),v in findings.items() if cf=="HIGH")
    med_c  = sum(len(v) for (t,cf,_),v in findings.items() if cf=="MEDIUM" and t=="REGEX")
    low_c  = sum(len(v) for (t,cf,_),v in findings.items() if cf=="LOW")
    ent_c  = sum(len(v) for (t,cf,_),v in findings.items() if t=="ENTROPY")

    cards = []
    for (typ, conf, label), hits in sorted_items:
        conf_lc = "entropy" if typ == "ENTROPY" else conf.lower()
        badge   = "ENTROPY" if typ == "ENTROPY" else conf

        hits_parts = []
        for line_no, line_text, matched, ent in hits:
            ent_info = f" &nbsp;·&nbsp; entropy={ent}" if ent else ""
            highlighted = highlight_match(
                line_text[:300] + ("…" if len(line_text) > 300 else ""), matched)
            hits_parts.append(HIT_ROW.format(
                line_no=line_no,
                entropy_info=ent_info,
                line_highlighted=highlighted,
                matched_val=html_module.escape(repr(matched))
            ))

        search_text = (label+" "+conf+" "+"entropy "*(typ=="ENTROPY") +
                       " ".join(lt for _,lt,_,_ in hits) +
                       " ".join(m for _,_,m,_ in hits)).lower()

        cards.append(FINDING_CARD.format(
            conf_lc=conf_lc,
            badge_label=badge,
            label=html_module.escape(label),
            count=len(hits),
            plural="s" if len(hits)!=1 else "",
            search_text=html_module.escape(search_text),
            hits_html="".join(hits_parts),
        ))

    return HTML_TEMPLATE.format(
        package=html_module.escape(package),
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        log_file=html_module.escape(str(log_file)),
        total_lines=total_lines,
        pid_mode="✓ PID" if pid_used else "✗ name filter",
        total=total, high=high_c, medium=med_c, low=low_c,
        entropy_c=ent_c, cats=len(findings),
        findings_html="\n".join(cards),
    )

# ── Text report ───────────────────────────────────────────────────────────────
def save_text_report(findings, log_file):
    sorted_items = sorted(findings.items(),
        key=lambda x: (CONF_ORDER.get(x[0][1], 3), -len(x[1])))
    total = sum(len(v) for v in findings.values())
    high_c = sum(len(v) for (t,cf,_),v in findings.items() if cf=="HIGH")
    med_c  = sum(len(v) for (t,cf,_),v in findings.items() if cf=="MEDIUM")
    low_c  = sum(len(v) for (t,cf,_),v in findings.items() if cf=="LOW")
    ent_c  = sum(len(v) for (t,cf,_),v in findings.items() if t=="ENTROPY")
    rp = log_file.with_name(log_file.stem + "_report.txt")
    with open(rp, "w", encoding="utf-8") as f:
        f.write(f"Security Scan Report\nGenerated : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f"Log file  : {log_file}\n")
        f.write(f"Total     : {total}  (HIGH={high_c} MEDIUM={med_c} LOW={low_c} ENTROPY={ent_c})\n")
        f.write("="*70+"\n")
        cur=None
        for (typ,conf,label),hits in sorted_items:
            section = "ENTROPY" if typ=="ENTROPY" else conf
            if section!=cur:
                cur=section
                f.write(f"\n{'━'*70}\n  {section}\n{'━'*70}\n\n")
            f.write(f"[{len(hits)}] {label}\n{'-'*50}\n")
            for ln,lt,m,ent in hits:
                f.write(f"  Line {ln}: {lt}\n")
                f.write(f"  Matched : {m!r}")
                if ent: f.write(f"  [entropy={ent}]")
                f.write("\n\n")
    return rp

# ── Console summary ───────────────────────────────────────────────────────────
def print_summary(findings):
    if not findings:
        print(GREEN("\n✓ No sensitive data patterns detected.")); return
    total = sum(len(v) for v in findings.values())
    high_c = sum(len(v) for (t,cf,_),v in findings.items() if cf=="HIGH")
    med_c  = sum(len(v) for (t,cf,_),v in findings.items() if cf=="MEDIUM")
    low_c  = sum(len(v) for (t,cf,_),v in findings.items() if cf=="LOW")
    ent_c  = sum(len(v) for (t,cf,_),v in findings.items() if t=="ENTROPY")
    print(f"\n⚠  {BOLD(str(total))} findings  —  "
          f"{RED(str(high_c)+' HIGH')}  "
          f"{YELLOW(str(med_c)+' MEDIUM')}  "
          f"{DIM(str(low_c)+' LOW')}  "
          f"{c(str(ent_c)+' ENTROPY','95')}\n")
    COL = {"HIGH":RED,"MEDIUM":YELLOW,"LOW":DIM}
    sorted_items = sorted(findings.items(),
        key=lambda x: (CONF_ORDER.get(x[0][1],3), -len(x[1])))
    for (typ,conf,label),hits in sorted_items:
        col = (lambda t: c(t,"95")) if typ=="ENTROPY" else COL.get(conf,DIM)
        tag = "ENTROPY" if typ=="ENTROPY" else conf
        print(BOLD(col(f"  [{tag}]")) + BOLD(f" {label}") + DIM(f"  ({len(hits)} hits)"))
        for ln,lt,m,ent in hits[:2]:
            print(DIM(f"         Line {ln}: ") + lt[:100]+("…" if len(lt)>100 else ""))
            suffix = f"  [entropy={ent}]" if ent else ""
            print(DIM(f"         Match  : ") + col(repr(m)) + DIM(suffix))
        if len(hits)>2: print(DIM(f"         … and {len(hits)-2} more"))
        print()

# ── Banner ────────────────────────────────────────────────────────────────────
def banner():
    print()
    print(BOLD(CYAN("╔══════════════════════════════════════════════╗")))
    print(BOLD(CYAN("║   Android Logcat Security Scanner  v3.0      ║")))
    print(BOLD(CYAN("║                              crafted by Slayer ║")))
    print(BOLD(CYAN("╚══════════════════════════════════════════════╝")))
    print()
    print("  Confidence:  " + RED("[HIGH]") + " likely real   " +
          YELLOW("[MEDIUM]") + " review needed   " +
          DIM("[LOW]") + " broad sweep   " +
          c("[ENTROPY]","95") + " high-entropy token")
    print()

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Capture Android logcat and scan for sensitive data.")
    parser.add_argument("-p","--package",  help="Package name. Prompted if not provided.")
    parser.add_argument("-l","--location", help="Output directory. Defaults to current dir.", default=None)
    parser.add_argument("-s","--search",   nargs="*", help="Extra keywords/regex.", default=[])
    args = parser.parse_args()

    banner()
    check_adb()
    check_device()

    package = args.package
    if not package:
        package = input(BOLD("\n📦 Enter the package name to monitor: ")).strip()
        if not package:
            print(RED("✗ Package name cannot be empty.")); sys.exit(1)

    out_dir = Path(args.location) if args.location else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = out_dir / f"logcat_{package.replace('.','_')}_{ts}.txt"

    extra_patterns = []
    if args.search:
        for kw in args.search:
            try:    extra_patterns.append(re.compile(kw, re.I))
            except re.error as e: print(YELLOW(f"⚠  Skipping invalid regex '{kw}': {e}"))
    else:
        raw = input(BOLD(
            "\n🔍 Extra keywords/patterns (comma-separated, or Enter to skip): "
        )).strip()
        if raw:
            for kw in [k.strip() for k in raw.split(",") if k.strip()]:
                try:    extra_patterns.append(re.compile(kw, re.I))
                except re.error as e: print(YELLOW(f"⚠  Skipping invalid pattern '{kw}': {e}"))

    clear_logcat()

    # Try to get PID — make sure app is running first
    print(YELLOW("\n⚡ Make sure your app is open on the device before proceeding."))
    input(BOLD("   Press Enter when app is running to detect PID…"))
    pid = get_pid(package)

    print(f"\n{BOLD('📱 Package :')} {CYAN(package)}")
    print(f"{BOLD('🔢 PID     :')} {CYAN(pid or 'not found — using name filter')}")
    print(f"{BOLD('💾 Log file:')} {CYAN(str(log_file))}")
    if pid:
        print(GREEN("  ✓ PID capture mode: ALL process logs captured "
                    "(OkHttp, WebView, System.out, etc.)"))
    else:
        print(YELLOW("  ⚠  Name filter mode: only lines containing package name captured."))
    print(f"\n{YELLOW('▶  Use your app now. Press')} {BOLD(RED('Enter'))} {YELLOW('when done.')}\n")

    t = threading.Thread(target=capture_logcat,
                         args=(package, pid, log_file), daemon=True)
    t.start()
    try:    input()
    except KeyboardInterrupt: pass
    stop_flag.set(); t.join(timeout=5)

    count = len(log_lines)
    print(f"\n{GREEN('✓ Capture stopped.')} {count} lines captured.")
    if count == 0:
        print(YELLOW("\n⚠  No lines captured. Check package name and that app is running."))
        if log_file.exists():
            fl = log_file.read_text(encoding="utf-8",errors="replace").splitlines()
            if fl: log_lines.extend(fl); print(GREEN(f"   Read {len(fl)} lines from file."))

    print(BOLD("\n🔎 Scanning (regex + entropy)…\n"))
    findings = scan_logs(log_lines, extra_patterns)
    print_summary(findings)

    html_path = log_file.with_name(log_file.stem + "_report.html")
    html_path.write_text(
        build_html_report(findings, package, log_file, len(log_lines), bool(pid)),
        encoding="utf-8")
    print(CYAN(f"🌐 HTML report : {html_path}"))

    txt_path = save_text_report(findings, log_file)
    print(CYAN(f"📄 Text report : {txt_path}"))
    print(f"{BOLD('📁 Raw log     :')} {CYAN(str(log_file))}")
    print(GREEN("\nDone.\n"))

if __name__ == "__main__":
    main()