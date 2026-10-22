#!/usr/bin/env python3
"""phpcheck.py v1.0 JamesLin
Usage:
    python phpcheck.py URL [--deep] [--insecure] [--timeout 10] [--json] [--show-headers]

"""
import argparse
import json
import random
import re
import ssl
import string
import sys
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

VERSION = "1.0.0"

# Vulnerable Versions (As of 2026-10-21)
# CVE-2026-109618 and CVE-2026-109619

VULNERABLE_THROUGH = {
    "5.4": 45, "5.5": 38, "5.6": 40,
    "7.0": 33, "7.1": 33, "7.2": 34, "7.3": 33, "7.4": 33,
    "8.0": 30, "8.1": 34, "8.2": 34, "8.3": 35, "8.4": 26, "8.5": 11,
}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0 Safari/537.36 phpcheck/" + VERSION)
REDIRECT_CODES = {301, 302, 303, 307, 308}
MAX_BODY = 1_000_000

VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)([-+~].*)?$")
DEV_RE = re.compile(r"(?:^|[-+~.])(?:dev|alpha|beta|rc)", re.IGNORECASE)
PHP_VER_RE = re.compile(
    r"\bPHP[ /]v?(\d+\.\d+(?:\.\d+)?(?:[-+~][^\s,;)]*)?)", re.IGNORECASE)
PHPINFO_RE = re.compile(r"PHP Version\s+(\d+\.\d+\.\d+\S*)")
PHP_EGG = "/?=PHPE9568F36-D428-11d2-A769-00AA001ACF42"
PHPINFO_PATHS = [
    "/phpinfo.php", "/info.php", "/php.php", "/test.php", "/i.php",
    "/pi.php", "/php-info.php", "/phpinfo", "/_phpinfo.php", "/infophp.php",
]


def patch_status(version):
    match = VERSION_RE.match(version or "")
    if not match:
        return "unknown"
    cutoff = VULNERABLE_THROUGH.get(f"{int(match[1])}.{int(match[2])}")
    if cutoff is None:
        return "unknown"
    if int(match[3]) <= cutoff:
        return "vulnerable"
    if DEV_RE.search(match[4] or ""):
        return "unknown"
    return "ok"


# ---------------------------------------------------------------- HTTP 
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  


class Resp:
    def __init__(self, url, status, headers, body):
        self.url = url
        self.status = status
        self.headers = headers  
        self.body = body

    def header_values(self, name):
        return [v for k, v in self.headers if k.lower() == name.lower()]

    @property
    def text(self):
        return self.body.decode("utf-8", errors="replace")


def http_get(url, ctx, timeout):
    handlers = [_NoRedirect()]
    if ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Encoding": "identity",
    })
    try:
        r = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:  # 3xx/4xx/5xx responses still contain headers and body content.
        r = exc
    try:
        status = getattr(r, "status", None) or r.code
        headers = list(r.headers.items())
        body = r.read(MAX_BODY)
    finally:
        r.close()
    return Resp(url, status, headers, body)


def fetch_chain(url, ctx, timeout, max_redirects):
    chain, seen = [], {url}
    for _ in range(max_redirects + 1):
        resp = http_get(url, ctx, timeout)
        chain.append(resp)
        location = (resp.header_values("location") or [None])[0]
        if resp.status in REDIRECT_CODES and location:
            url = urljoin(resp.url, location)
            if urlsplit(url).scheme not in ("http", "https") or url in seen:
                break
            seen.add(url)
            continue
        break
    return chain


# ---------------------------------------------------------------- 
def ev(kind, test, url, detail, version=None):
    return {"kind": kind, "test": test, "url": url,
            "detail": detail, "version": version}


def analyze_headers(resp, test):
    found = []
    for name, value in resp.headers:
        lname = name.lower()
        if lname == "x-php-version":
            m = re.match(r"\s*(\d+\.\d+(?:\.\d+)?\S*)", value)
            if m:
                found.append(ev("version", test, resp.url,
                                f"{name}: {value}", m[1]))
            continue
        m = PHP_VER_RE.search(value)
        if m:
            found.append(ev("version", test, resp.url,
                            f"{name}: {value}", m[1]))
        elif lname in ("x-powered-by", "server", "via") and \
                re.search(r"\bPHP\b|mod_php|php-fpm", value, re.I):
            found.append(ev("presence", test, resp.url,
                            f"{name}: {value} (有 PHP 但未顯示版本)"))
        elif lname == "set-cookie" and "PHPSESSID=" in value:
            found.append(ev("presence", test, resp.url,
                            "Set-Cookie 含 PHPSESSID (使用 PHP session)"))
    return found


def analyze_body(resp, test, main_page=False):
    found = []
    body = resp.text
    plain = re.sub(r"<[^>]+>", " ", body)

    m = PHPINFO_RE.search(plain)
    if m:
        found.append(ev("version", test, resp.url,
                        "頁面內容為 phpinfo() 輸出", m[1]))

    addr = re.search(r"<address>(.*?)</address>", body, re.I | re.S)
    if addr:
        m = PHP_VER_RE.search(addr.group(1))
        if m:
            found.append(ev("version", test, resp.url,
                            "伺服器錯誤頁簽名: " + addr.group(1).strip()[:80],
                            m[1]))

    if re.search(r"<b>(?:Warning|Fatal error|Notice|Parse error|Deprecated)</b>:"
                 r"[^\n]{0,300}\.php", body, re.I):
        found.append(ev("presence", test, resp.url,
                        "頁面出現 PHP 錯誤訊息 (display_errors 開啟)"))

    if main_page:
        if re.search(r"""(?:href|src|action)\s*=\s*["'][^"']*\.php\b""",
                     body, re.I):
            found.append(ev("presence", test, resp.url,
                            "頁面內有 .php 連結 (弱證據)"))
        if re.search(r"wp-content/|wp-includes/|wp-json", body, re.I):
            found.append(ev("presence", test, resp.url,
                            "WordPress 網站特徵 (WordPress 以 PHP 執行)"))
    return found


# ----------------------------------------------------------------
def probe_list(rand, deep, is_wp):
    items = [
        ("探測: /index.php", "/index.php", "normal"),
        ("探測: 不存在的 .php 檔 (錯誤頁)", f"/phpcheck-{rand}.php", "normal"),
        ("探測: 不存在的路徑 (404 頁)", f"/phpcheck-{rand}/", "normal"),
        ("探測: PHP logo 彩蛋 (需 expose_php 開啟)", PHP_EGG, "egg"),
    ]
    if is_wp:
        items += [
            ("探測: WordPress /wp-login.php", "/wp-login.php", "normal"),
            ("探測: WordPress /xmlrpc.php", "/xmlrpc.php", "xmlrpc"),
        ]
    if deep:
        items += [(f"深度探測: {p}", p, "phpinfo") for p in PHPINFO_PATHS]
    return items


def run(args):
    ctx = ssl._create_unverified_context() if args.insecure else None
    start = args.url if "://" in args.url else "http://" + args.url
    if urlsplit(start).scheme not in ("http", "https"):
        raise ValueError("請使用 http:// 或 https:// 網址")

    chain = fetch_chain(start, ctx, args.timeout, args.max_redirects)
    final = chain[-1]
    evidence, tests = [], []

    # 最終頁面優先,再看其他跳轉
    ordered = [final] + chain[:-1]
    for resp in ordered:
        label = "最終頁面" if resp is final else "重新導向頁面"
        evidence += analyze_headers(resp, f"{label}標頭")
        evidence += analyze_body(resp, f"{label}內容", main_page=True)

    is_wp = any("WordPress" in e["detail"] for e in evidence)
    parts = urlsplit(final.url)
    origin = f"{parts.scheme}://{parts.netloc}"
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

    for label, path, mode in probe_list(rand, args.deep, is_wp):
        try:
            resp = http_get(origin + path, ctx, args.timeout)
        except Exception as exc:  # noqa: BLE001
            tests.append({"test": label, "url": origin + path,
                          "status": None, "note": str(exc)})
            continue
        tests.append({"test": label, "url": resp.url,
                      "status": resp.status, "note": ""})
        evidence += analyze_headers(resp, label)
        ctype = (resp.header_values("content-type") or [""])[0].lower()
        if mode == "egg" and resp.status == 200 and ctype.startswith("image/"):
            evidence.append(ev("presence", label, resp.url,
                               "PHP logo 彩蛋有回應 (確認為 PHP)"))
        elif mode == "xmlrpc" and "XML-RPC server accepts POST" in resp.text:
            evidence.append(ev("presence", label, resp.url,
                               "xmlrpc.php 有回應 (WordPress/PHP)"))
        elif mode == "phpinfo":
            if resp.status == 200:
                evidence += analyze_body(resp, label)
        else:
            evidence += analyze_body(resp, label)

    # 去除重複證據
    uniq, seen = [], set()
    for e in evidence:
        key = (e["kind"], e["detail"], e["version"])
        if key not in seen:
            seen.add(key)
            uniq.append(e)
    return chain, tests, uniq


def conclude(evidence):
    versions = []
    for e in evidence:
        if e["kind"] == "version" and e["version"] not in versions:
            versions.append(e["version"])
    statuses = {v: patch_status(v) for v in versions}
    if "vulnerable" in statuses.values():
        status = "vulnerable"
        primary = next(v for v in versions if statuses[v] == "vulnerable")
    elif versions and all(s == "ok" for s in statuses.values()):
        status, primary = "ok", versions[0]
    else:
        status, primary = "unknown", (versions[0] if versions else None)

    if versions:
        reason = f"PHP {primary}"
        if len(versions) > 1:
            reason += " (偵測到多個不同版本: " + ", ".join(versions) + ")"
    elif any(e["kind"] == "presence" for e in evidence):
        reason = "偵測到網站使用 PHP,但版本資訊被伺服器隱藏"
    else:
        reason = "沒有發現 PHP 的跡象"
    return status, primary, versions, reason


def main():
    parser = argparse.ArgumentParser(
        prog="phpcheck.py", description="多種方式偵測網站的 PHP 版本")
    parser.add_argument("url")
    parser.add_argument("--deep", action="store_true",
                        help="額外嘗試 phpinfo.php 等常見檔名")
    parser.add_argument("--insecure", action="store_true",
                        help="不驗證 HTTPS 憑證")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--max-redirects", type=int, default=10)
    parser.add_argument("--show-headers", action="store_true",
                        help="列出每一跳的完整回應標頭")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if not 0 < args.timeout <= 60:
        parser.error("--timeout 必須大於 0 且不超過 60 秒")

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    try:
        chain, tests, evidence = run(args)
    except Exception as exc:  # noqa: BLE001
        msg = f"無法連線: {exc}"
        if args.as_json:
            print(json.dumps({"patch_status": "unknown", "php_version": None,
                              "reason": msg, "exit_code": 3},
                             ensure_ascii=False))
        else:
            print("UNKNOWN: " + msg)
        sys.exit(3)

    status, primary, versions, reason = conclude(evidence)
    code = {"ok": 0, "vulnerable": 1, "unknown": 3}[status]

    if args.as_json:
        print(json.dumps({
            "patch_status": status, "php_version": primary,
            "all_versions": versions, "reason": reason, "exit_code": code,
            "redirects": [{"status": r.status, "url": r.url} for r in chain],
            "tests": tests, "evidence": evidence,
        }, ensure_ascii=False, indent=2))
        sys.exit(code)

    print(f"目標: {args.url}\n")
    print("[重新導向鏈]")
    for i, r in enumerate(chain, 1):
        print(f"  {i}. {r.status}  {r.url}")
        if args.show_headers:
            for k, v in r.headers:
                print(f"       {k}: {v}")
    print("\n[探測結果]")
    for t in tests:
        st = t["status"] if t["status"] is not None else "失敗"
        print(f"  {st!s:>4}  {t['test']}  {t['note']}")
    print("\n[偵測證據]")
    if evidence:
        for e in evidence:
            tag = "版本" if e["kind"] == "version" else "存在"
            print(f"  [{tag}] {e['detail']}\n         來源: {e['test']} ({e['url']})")
    else:
        print("  (無)")
    print(f"\n結論: {status.upper()}: {reason}")
    if status == "unknown" and not versions:
        print("提示: 版本被隱藏時,只能從伺服器端確認 (php -v、phpinfo()、"
              "主機控制台,或 WordPress 後台「網站健康狀態 > 資訊」)。")
    sys.exit(code)


if __name__ == "__main__":
    main()