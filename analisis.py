#!/usr/bin/env python3

import requests
import os
import sys
import re
import ast
import json
import time
import argparse
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------
# Configuration
# ---------------------------
GITHUB_API = "https://api.github.com"
RAW_GITHUB = "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
API_REPO = GITHUB_API + "/repos/{owner}/{repo}"
API_TREE = GITHUB_API + "/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
DEFAULT_MAX_FILE_BYTES = 200 * 1024  # 200 KB
THREADS = 8

# Suspicious keywords (case-insensitive)
SUSP_KEYWORDS = [
    "encrypt", "decrypt", "ransom", "ransomware", "webhook", "fernet",
    "subprocess", "os.system", "eval(", "exec(", "compile(", "socket", "udp", "tcp",
    "TYPE_APPLICATION_OVERLAY", "SYSTEM_ALERT_WINDOW", "DeviceAdmin", "AccessibilityService",
    "WindowManager", "addView(", "requests.post", "requests.get", "ftplib", "paramiko",
    "rm -rf", "curl ", "wget ", "base64", "openssl", "keylogger", "password", "credentials",
    "sendto(", "Popen(", "chmod 777"
]

# extension -> language hint
EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".sh": "Shell", ".ps1": "PowerShell",
    ".java": "Java", ".kt": "Kotlin", ".cs": "C#", ".c": "C", ".cpp": "C++",
    ".php": "PHP", ".html": "HTML", ".css": "CSS", ".xml": "XML", ".json": "JSON",
    ".yml": "YAML", ".yaml": "YAML", ".md": "Markdown", ".apk": "Android APK",
    ".jar": "Java JAR", ".go": "Go", ".rs": "Rust",
}

# Regex helpers
URL_RE = re.compile(r"https?://[^\s'\"<>)]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
WEBHOOK_DISCORD_RE = re.compile(r"https?://(?:canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+")
BASE64_LIKE_RE = re.compile(r"\b[A-Za-z0-9\-_]{32,}\={0,2}\b")  # rough
FERNET_KEY_RE = re.compile(r"^[A-Za-z0-9\-_]{43}=$")  # typical Fernet key (44 chars incl '=')

# GitHub token to increase rate limit (optional)
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

# ---------------------------
# Utilities
# ---------------------------
def extract_owner_repo(raw: str):
    raw = raw.strip()
    if raw.startswith("https://") or raw.startswith("http://"):
        p = urlparse(raw)
        if "github.com" not in p.netloc:
            return None, None
        parts = p.path.strip("/").split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
    else:
        # owner/repo allowed
        parts = raw.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
    return None, None

def gh_headers():
    h = {"Accept": "application/vnd.github.v3+json", "User-Agent": "analyzer_full/1.0"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"token {GITHUB_TOKEN}"
    return h

def safe_get(url, stream=False, timeout=10):
    try:
        r = requests.get(url, headers=gh_headers(), timeout=timeout, stream=stream)
        return r
    except Exception as e:
        return None

def detect_lang_from_path(path):
    _, ext = os.path.splitext(path.lower())
    return EXT_LANG.get(ext, ext or "unknown")

def snippet_lines(text, lineno, context=2):
    lines = text.splitlines()
    start = max(0, lineno - 1 - context)
    end = min(len(lines), lineno - 1 + context + 1)
    return "\n".join(f"{i+1:>4}: {lines[i]}" for i in range(start, end))

# ---------------------------
# Python AST analyzer
# ---------------------------
class PyAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.functions = []
        self.classes = []
        self.imports = set()
        self.risky_calls = set()
        self.str_literals = []
        self.assignments = []
    def visit_FunctionDef(self, node):
        self.functions.append((node.name, node.lineno))
        self.generic_visit(node)
    def visit_AsyncFunctionDef(self, node):
        self.functions.append((node.name + " (async)", node.lineno))
        self.generic_visit(node)
    def visit_ClassDef(self, node):
        self.classes.append((node.name, node.lineno))
        self.generic_visit(node)
    def visit_Import(self, node):
        for n in node.names:
            self.imports.add(n.name)
    def visit_ImportFrom(self, node):
        mod = node.module or ""
        self.imports.add(mod)
    def visit_Call(self, node):
        # identify calls: eval/exec/os.system/subprocess/.../requests.post
        try:
            func = node.func
            if isinstance(func, ast.Name):
                if func.id in ("eval", "exec", "compile", "open"):  # open might be used to write files
                    self.risky_calls.add(func.id)
            elif isinstance(func, ast.Attribute):
                # e.g., os.system, subprocess.Popen, requests.post
                attr = func.attr
                if isinstance(func.value, ast.Name):
                    caller = func.value.id
                    self.risky_calls.add(f"{caller}.{attr}")
                else:
                    self.risky_calls.add(attr)
        except Exception:
            pass
        self.generic_visit(node)
    def visit_Constant(self, node):
        if isinstance(node.value, str):
            self.str_literals.append((node.value, getattr(node, "lineno", None)))
    def visit_Str(self, node):
        self.str_literals.append((node.s, getattr(node, "lineno", None)))
    def visit_Assign(self, node):
        for t in node.targets:
            if isinstance(t, ast.Name):
                self.assignments.append((t.id, getattr(node, "lineno", None)))
        self.generic_visit(node)

# ---------------------------
# Core analyzer
# ---------------------------
def fetch_repo_tree(owner, repo):
    repo_api = API_REPO.format(owner=owner, repo=repo)
    r = safe_get(repo_api)
    if not r or r.status_code != 200:
        return None, f"Failed to fetch repo metadata (status {getattr(r,'status_code',None)})"
    repo_meta = r.json()
    default_branch = repo_meta.get("default_branch", "main")
    tree_api = API_TREE.format(owner=owner, repo=repo, branch=default_branch)
    r2 = safe_get(tree_api)
    if not r2 or r2.status_code != 200:
        # fallback: list top-level contents
        contents_api = f"{GITHUB_API}/repos/{owner}/{repo}/contents"
        r3 = safe_get(contents_api)
        if not r3 or r3.status_code != 200:
            return None, "Failed to fetch repo tree or contents (maybe repo is private)"
        items = r3.json()
        tree = [{"path": it["path"], "type": it.get("type", "blob"), "size": it.get("size", 0)} for it in items]
        return {"default_branch": default_branch, "tree": tree}, None
    data = r2.json()
    return {"default_branch": default_branch, "tree": data.get("tree", [])}, None

def analyze_repo(owner, repo, max_file_bytes=DEFAULT_MAX_FILE_BYTES):
    meta, err = fetch_repo_tree(owner, repo)
    if err:
        return None, err
    default_branch = meta["default_branch"]
    tree = meta["tree"]
    files = [t for t in tree if t.get("type") == "blob"]
    result = {
        "repo": f"{owner}/{repo}",
        "default_branch": default_branch,
        "total_files": len(files),
        "languages": {},
        "files": [],
        "dependencies": {},
        "fetched": 0,
        "suspicious": [],
        "python": {},
        "extracted_indicators": {"urls": set(), "ips": set(), "emails": set(), "webhooks": set(), "base64_like": set()},
        "risk_score": 0,
        "risk_notes": []
    }

    # find dependency files
    dep_names = {"requirements.txt", "pyproject.toml", "setup.py", "package.json", "Pipfile", "poetry.lock"}
    dep_map = {}
    for f in files:
        path = f["path"]
        result["files"].append(path)
        lang = detect_lang_from_path(path)
        result["languages"][lang] = result["languages"].get(lang, 0) + 1
        base = os.path.basename(path).lower()
        if base in dep_names:
            dep_map[base] = path

    # fetch dependencies
    for name, path in dep_map.items():
        raw_url = RAW_GITHUB.format(owner=owner, repo=repo, branch=default_branch, path=path)
        r = safe_get(raw_url)
        if r and r.status_code == 200:
            try:
                lines = r.text.splitlines()
                result["dependencies"][name] = lines
            except Exception:
                result["dependencies"][name] = ["(failed to parse)"]
        else:
            result["dependencies"][name] = ["(failed to fetch)"]

    # parallel fetch files (bounded by size)
    def fetch_file_blob(f):
        path = f["path"]
        size = f.get("size", 0)
        if size > max_file_bytes:
            return {"path": path, "skipped_large": True, "size": size}
        raw_url = RAW_GITHUB.format(owner=owner, repo=repo, branch=default_branch, path=path)
        r = safe_get(raw_url)
        if not r or r.status_code != 200:
            return {"path": path, "error": f"fetch failed status {getattr(r,'status_code',None)}"}
        return {"path": path, "text": r.text, "size": size}

    fetched = []
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(fetch_file_blob, f): f for f in files}
        for fut in as_completed(futures):
            try:
                res = fut.result()
                fetched.append(res)
            except Exception as e:
                # ignore individual failures
                pass

    # analyze fetched files
    suspicious_hits = []
    py_details = {}
    indicators = result["extracted_indicators"]
    for item in fetched:
        path = item.get("path")
        if item.get("skipped_large"):
            continue
        text = item.get("text")
        if not text:
            continue
        result["fetched"] += 1
        lower = text.lower()

        # generic keyword matches
        found_kw = [kw for kw in SUSP_KEYWORDS if kw.lower() in lower]
        if found_kw:
            suspicious_hits.append({"path": path, "keywords": sorted(set(found_kw))})

        # extract generic indicators
        for u in URL_RE.findall(text):
            indicators["urls"].add(u)
            # webhook pattern
            if WEBHOOK_DISCORD_RE.search(u):
                indicators["webhooks"].add(u)
        for ip in IP_RE.findall(text):
            indicators["ips"].add(ip)
        for em in EMAIL_RE.findall(text):
            indicators["emails"].add(em)
        # base64-like / potential keys
        for b in BASE64_LIKE_RE.findall(text):
            if len(b) >= 32:
                indicators["base64_like"].add(b)
        # Python-specific deep analysis
        if path.endswith(".py"):
            try:
                tree = ast.parse(text)
                analyzer = PyAnalyzer()
                analyzer.visit(tree)
                pyinfo = {
                    "functions": analyzer.functions,
                    "classes": analyzer.classes,
                    "imports": sorted(list(analyzer.imports))[:200],
                    "risky_calls": sorted(list(analyzer.risky_calls)),
                    "string_literals_sample": analyzer.str_literals[:20],
                    "assignments": analyzer.assignments[:50],
                }
                # detect requests.post with URL argument heuristically
                # naive: search for "requests.post(" and following literal url in same file's strings
                # also capture any occurrence of "requests.post" in risky_calls
                py_details[path] = pyinfo
                # also check string literals for webhook urls
                for s, lineno in analyzer.str_literals:
                    if s and URL_RE.search(s):
                        for u in URL_RE.findall(s):
                            indicators["urls"].add(u)
                            if WEBHOOK_DISCORD_RE.search(u):
                                indicators["webhooks"].add(u)
                # collect suspicious keywords inside python strings
                if any(k.lower() in lower for k in ("encrypt", "ransom", "fernet", "webhook")):
                    suspicious_hits.append({"path": path, "keywords": [k for k in ("encrypt", "ransom", "fernet", "webhook") if k in lower]})
            except Exception as e:
                py_details[path] = {"parse_error": str(e)}

    # finalize sets -> lists
    result["suspicious"] = suspicious_hits
    result["python"] = py_details
    result["extracted_indicators"] = {k: sorted(list(v)) for k, v in indicators.items()}

    # rudimentary scoring
    score = 0
    notes = []
    score += min(30, len(suspicious_hits) * 5)
    enc_hits = sum(1 for s in suspicious_hits for kw in s["keywords"] if any(x in kw.lower() for x in ("encrypt", "ransom", "fernet")))
    if enc_hits:
        score += 30
        notes.append(f"{enc_hits} encryption-related occurrences found.")
    if result["extracted_indicators"]["webhooks"]:
        score += 10
        notes.append("Webhook endpoints found (possible exfiltration).")
    if any("requests.post" in (", ".join(p.get("risky_calls", []))) for p in py_details.values()):
        score += 8
        notes.append("HTTP POST usage detected (possible data exfiltration).")
    if any("os.system" in (", ".join(p.get("risky_calls", []))) for p in py_details.values()):
        score += 6
        notes.append("os.system/subprocess usage detected (shell commands).")
    # overlay/device admin indicators
    overlay_flag = any(any(x in file_lower for x in ("system_alert_window", "deviceadmin", "accessibilityservice", "windowmanager", "addview")) for file_lower in (" ".join(s.get("keywords", [])) for s in suspicious_hits))
    if overlay_flag:
        score += 12
        notes.append("Potential Android overlay/device-admin code detected.")
    # cap
    score = min(100, score)
    result["risk_score"] = score
    result["risk_notes"] = notes or ["No high-level notes found."]

    return result, None

# ---------------------------
# Reporting
# ---------------------------
def report_pretty(res, save_prefix=None):
    lines = []
    lines.append(f"=== Repo Analysis: {res.get('repo')} ===")
    lines.append(f"Default branch: {res.get('default_branch')}")
    lines.append(f"Total files (tree): {res.get('total_files')}")
    lines.append(f"Files fetched (<= limit): {res.get('fetched')}")
    lines.append("\n-- Languages (counts) --")
    for lang, cnt in res.get("languages", {}).items():
        lines.append(f"{lang}: {cnt}")
    lines.append("\n-- Dependency files (lines shown or failure) --")
    if res.get("dependencies"):
        for k, v in res["dependencies"].items():
            lines.append(f"{k}: {len(v)} lines")
    else:
        lines.append("None found")
    lines.append("\n-- Suspicious hits (keyword matches) --")
    if res.get("suspicious"):
        for s in res["suspicious"]:
            lines.append(f"- {s['path']}: {', '.join(s['keywords'])}")
    else:
        lines.append("None")
    lines.append("\n-- Extracted indicators (sample) --")
    for k, arr in res.get("extracted_indicators", {}).items():
        lines.append(f"{k}: {len(arr)} found (sample 5): {arr[:5]}")
    lines.append("\n-- Python file summaries (sample) --")
    for path, info in sorted(res.get("python", {}).items())[:20]:
        lines.append(f"\nFile: {path}")
        if isinstance(info, dict) and info.get("parse_error"):
            lines.append(f"  [parse error] {info['parse_error']}")
            continue
        funcs = [f"{n}@{ln}" for n, ln in info.get("functions", [])[:10]]
        classes = [f"{n}@{ln}" for n, ln in info.get("classes", [])[:10]]
        imports = ", ".join(info.get("imports", [])[:10])
        risky = ", ".join(info.get("risky_calls", [])[:10])
        lines.append(f"  functions: {', '.join(funcs) or '(none)'}")
        lines.append(f"  classes: {', '.join(classes) or '(none)'}")
        lines.append(f"  imports (sample): {imports or '(none)'}")
        lines.append(f"  risky_calls: {risky or '(none)'}")
        if info.get("string_literals_sample"):
            lines.append(f"  string_literals_sample (first {len(info['string_literals_sample'])}): { [s for s,_ in info['string_literals_sample'][:5]] }")
    lines.append("\n-- Risk Summary --")
    lines.append(f"Risk score: {res.get('risk_score')}/100")
    for n in res.get("risk_notes", []):
        lines.append(f"- {n}")

    output = "\n".join(lines)
    print(output)
    if save_prefix:
        txtfile = f"{save_prefix}.txt"
        jsonfile = f"{save_prefix}.json"
        try:
            with open(txtfile, "w", encoding="utf-8") as f:
                f.write(output)
            with open(jsonfile, "w", encoding="utf-8") as f:
                json.dump(res, f, indent=2)
            print(f"\nSaved report: {txtfile} and {jsonfile}")
        except Exception as e:
            print("Failed to save report:", e)

# ---------------------------
# Safe encryption demo (non-destructive)
# ---------------------------
def safe_encrypt_demo():
    try:
        from cryptography.fernet import Fernet
    except Exception:
        print("cryptography not installed (pip install cryptography) — skipping demo.")
        return
    print("\n=== SAFE Encryption Demo (non-destructive) ===")
    key = Fernet.generate_key()
    f = Fernet(key)
    print("Generated key (example):", key.decode())
    os.makedirs("encrypted_demo", exist_ok=True)
    os.makedirs("decrypted_demo", exist_ok=True)
    sample = "demo_plain.txt"
    with open(sample, "wb") as fh:
        fh.write(b"This is a safe demo file. No secrets here.")
    with open(sample, "rb") as fh:
        data = fh.read()
    enc = f.encrypt(data)
    enc_path = os.path.join("encrypted_demo", "demo_plain.txt.enc")
    with open(enc_path, "wb") as fh:
        fh.write(enc)
    print("Encrypted written to:", enc_path)
    # decrypt copy
    with open(enc_path, "rb") as fh:
        dec = f.decrypt(fh.read())
    dec_path = os.path.join("decrypted_demo", "demo_plain.txt.dec")
    with open(dec_path, "wb") as fh:
        fh.write(dec)
    print("Decrypted copy written to:", dec_path)
    print("Demo keeps original file intact and writes separate encrypted/decrypted copies.\n")

# ---------------------------
# CLI main
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="GitHub Repo Full Analyzer (read-only)")
    parser.add_argument("repo", help="Repository URL or owner/repo")
    parser.add_argument("--no-save", action="store_true", help="Do not save report files")
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES, help="Max bytes to fetch per file")
    parser.add_argument("--demo-encrypt", action="store_true", help="Run safe encryption demo at end")
    args = parser.parse_args()

    owner, repo = extract_owner_repo(args.repo)
    if not owner:
        print("Invalid repo input. Use https://github.com/owner/repo or owner/repo")
        sys.exit(1)

    print(f"Analyzing {owner}
