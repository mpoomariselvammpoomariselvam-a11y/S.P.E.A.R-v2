#!/usr/bin/env python3
"""Local-only S.P.E.A.R email inspection demo. Python standard library only."""
import email
import html
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

# Local: 127.0.0.1:8000. On Render the PORT env var is set, so bind to 0.0.0.0.
PORT = int(os.environ.get("PORT", "8000"))
HOST = "0.0.0.0" if "PORT" in os.environ else "127.0.0.1"
# Extra allowed frontend origins, comma separated, e.g. https://spear-site.onrender.com
EXTRA_ORIGINS = tuple(o.strip().rstrip("/") for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip())
MAX_UPLOAD = 5 * 1024 * 1024
DB = Path(os.environ.get("DB_PATH") or Path(__file__).with_name("spear_history.sqlite3"))
LOCK = threading.Lock()
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "goo.gl", "ow.ly", "buff.ly", "rb.gy"}
RISK_WORDS = ("verify your account", "password expires", "urgent action", "wire transfer", "gift card", "account suspended", "confirm your password", "payment overdue", "unusual sign-in")


def db():
    con = sqlite3.connect(DB, timeout=8)
    con.execute("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT NOT NULL, filename TEXT NOT NULL, subject TEXT NOT NULL, sender TEXT NOT NULL, verdict TEXT NOT NULL, score INTEGER NOT NULL, report TEXT NOT NULL)")
    return con


def get_domain(address):
    m = re.search(r"@([^\s>,;]+)", address or "")
    return m.group(1).strip(".>").lower() if m else ""


def val(msg, name):
    v = msg.get(name)
    return str(v).replace("\r", " ").replace("\n", " ").strip() if v is not None else ""


def file_bytes(item):
    raw = item.get_payload(decode=True)
    if raw is not None:
        return raw
    nested = item.get_payload()
    if isinstance(nested, list):
        return b"\r\n".join(part.as_bytes(policy=policy.SMTP) for part in nested)
    if isinstance(nested, str):
        return nested.encode("utf-8", "replace")
    return b""


def analyze(raw, filename):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    if not msg.items():
        raise ValueError("No email headers were found")
    subject = val(msg, "Subject") or "(no subject)"
    from_header = val(msg, "From")
    sender = email.utils.parseaddr(from_header)[1] or from_header
    from_domain = get_domain(sender)
    reply, ret = val(msg, "Reply-To"), val(msg, "Return-Path")
    reply_addr = email.utils.parseaddr(reply)[1] or reply
    return_addr = email.utils.parseaddr(ret)[1] or ret
    auth_all = " | ".join(str(v).replace("\r", " ").replace("\n", " ").strip() for v in msg.get_all("Authentication-Results", []))
    auth = {}
    for name in ("spf", "dkim", "dmarc"):
        vals = re.findall(r"(?<![\w-])" + name + r"\s*=\s*([a-zA-Z]+)", auth_all, re.I)
        auth[name.upper()] = vals[0].lower() if vals else "not provided"
    bodies = []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.get_content_maintype() == "multipart" or part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                bodies.append(str(part.get_content()))
            except Exception:
                pass
    body = "\n".join(bodies)
    links, findings, points = [], [], 0
    for url in URL_RE.findall(body):
        url = url.rstrip(".,);]")
        host = (urlparse(url).hostname or "").lower()
        if not any(x["url"] == url for x in links):
            links.append({"url": url, "domain": host, "signals": []})
        link = next(x for x in links if x["url"] == url)
        if host in SHORTENERS:
            link["signals"].append("Known URL shortener")
        if host.startswith("xn--") or ".xn--" in host:
            link["signals"].append("Internationalized/punycode domain")
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            link["signals"].append("IP address used as link host")
    reply_domain, return_domain = get_domain(reply_addr), get_domain(return_addr)
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append({"level": "warning", "title": "Reply-To domain differs", "detail": f"From uses {from_domain}; replies go to {reply_domain}. This can be legitimate, but verify the sender."}); points += 2
    if return_domain and from_domain and return_domain != from_domain:
        findings.append({"level": "info", "title": "Return-Path domain differs", "detail": f"From uses {from_domain}; Return-Path uses {return_domain}. Mailing services can cause this, so treat it as context."}); points += 1
    for check, result in auth.items():
        if result in ("fail", "softfail", "permerror", "temperror"):
            findings.append({"level": "warning", "title": f"{check} reported {result}", "detail": "Read from supplied Authentication-Results only; not independently verified."}); points += 2 if result == "fail" else 1
    missing = [k for k, v in auth.items() if v == "not provided"]
    if missing:
        findings.append({"level": "info", "title": "Authentication result missing", "detail": "No result found for: " + ", ".join(missing) + ". Missing data is not proof of spoofing."})
    for link in links:
        for signal in link["signals"]:
            findings.append({"level": "warning", "title": signal, "detail": f"A link points to {link['domain']}. Verify it independently."}); points += 1
    clean_body = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", body))).lower()
    matched = [phrase for phrase in RISK_WORDS if phrase in clean_body]
    if matched:
        findings.append({"level": "info", "title": "Urgency or credential language", "detail": "Found phrase(s): " + ", ".join(matched) + ". Context matters."}); points += 1
    attachments = [{"name": part.get_filename() or "(unnamed)", "content_type": part.get_content_type()} for part in msg.walk() if part.get_content_disposition() == "attachment" or part.get_filename()]
    return {"filename": Path(filename).name[:160], "subject": subject[:500], "from": from_header[:500], "sender": sender[:500], "from_domain": from_domain, "reply_to": reply[:500], "return_path": ret[:500], "authentication": auth, "authentication_raw": auth_all[:2000], "received": [str(x).replace("\r", " ").replace("\n", " ")[:1000] for x in msg.get_all("Received", [])[:20]], "links": links[:100], "attachments": attachments[:50], "findings": findings, "score": min(points, 10), "verdict": "Review recommended" if points >= 2 else "No strong warning signals found", "disclaimer": "Heuristic inspection only. No DNS lookup, signature verification, reputation lookup, attachment execution, or malware scanning was performed."}


class Handler(BaseHTTPRequestHandler):
    server_version = "SPEAR/1.0"

    def cors(self):
        origin = self.headers.get("Origin", "")
        allowed = ("http://127.0.0.1:5500", "http://localhost:5500", "http://127.0.0.1:5501", "http://localhost:5501") + EXTRA_ORIGINS
        local_origin = False
        try:
            parsed = urlparse(origin)
            local_origin = (
                parsed.scheme == "http"
                and parsed.hostname in ("127.0.0.1", "localhost")
                and parsed.username is None
                and parsed.password is None
                and not parsed.path
                and not parsed.params
                and not parsed.query
                and not parsed.fragment
                and (parsed.port is None or 1 <= parsed.port <= 65535)
            )
        except ValueError:
            local_origin = False
        if origin in allowed or local_origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.send_header("X-Content-Type-Options", "nosniff"); self.cors(); self.end_headers(); self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204); self.cors(); self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            return self.send_json({"ok": True, "name": "S.P.E.A.R", "max_upload_bytes": MAX_UPLOAD})
        if path == "/api/history":
            try:
                with LOCK, db() as con:
                    rows = con.execute("SELECT id,created,filename,subject,sender,verdict,score FROM history ORDER BY id DESC LIMIT 100").fetchall()
                keys = ("id", "created", "filename", "subject", "sender", "verdict", "score")
                return self.send_json({"items": [dict(zip(keys, row)) for row in rows]})
            except Exception as exc:
                return self.send_json({"error": "History unavailable: " + str(exc)}, 500)
        return self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/ask":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 12000:
                    return self.send_json({"error": "Question is empty or too long (maximum 8,000 characters)"}, 413)
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                question = str(payload.get("question", "")).strip()[:8000]
                if not question:
                    return self.send_json({"error": "Type a question first"}, 400)
                q = question.lower()
                report = payload.get("report") if isinstance(payload.get("report"), dict) else None
                if any(word in q for word in ("this email", "this message", "my email", "my message", "report", "result", "analysis")) and report:
                    auth = report.get("authentication", {})
                    findings = report.get("findings", [])
                    summary = "; ".join(str(x.get("title", "")) for x in findings[:4] if isinstance(x, dict)) or "no configured warning indicators were found"
                    answer = (f"Your latest report says: {report.get('verdict', 'Review the report')} (signal score {report.get('score', '—')}/10). "
                              f"Reported authentication: SPF {auth.get('SPF', 'not provided')}, DKIM {auth.get('DKIM', 'not provided')}, DMARC {auth.get('DMARC', 'not provided')}. "
                              f"Findings: {summary}. These values are read from the message and are not independently verified; a low score does not prove safety. "
                              "If the request matters, verify it using a known contact method.")
                elif any(word in q for word in ("spf", "dkim", "dmarc", "authentication")):
                    answer = "SPF checks whether a sending server is authorized by a domain; DKIM checks a cryptographic signature; DMARC checks whether SPF or DKIM aligns with the visible From domain and applies the domain's policy. A pass is useful evidence, not proof that the message content or account is trustworthy. This demo only displays Authentication-Results written in the email; it does not verify them."
                elif any(word in q for word in ("spoof", "fake sender", "forged", "from address", "sender address")):
                    answer = "Email spoofing means making a message appear to come from an address or domain that did not actually send it. Check the full sender address, Reply-To, authentication results, and unexpected links or requests. A display name is easy to imitate, and a mismatch can also have legitimate causes. Verify important requests through a separate, known channel."
                elif any(word in q for word in ("link", "url", "click", "website")):
                    answer = "Don't follow a link just because its text looks familiar. Check the actual destination carefully, and for banking, work, or account notices, open the service using a bookmark or address you type yourself. This demo extracts readable links but does not open or reputation-check them."
                elif any(word in q for word in ("attachment", "file", "open")):
                    answer = "Treat unexpected attachments cautiously, especially when the message pressures you to open them. Confirm with the sender using a known contact method. This demo lists attachment names and types but does not open, execute, or scan files for malware."
                elif any(word in q for word in ("safe", "real", "legitimate", "trust", "verdict")):
                    answer = "This tool cannot certify that an email is safe or authentic. Its score is a heuristic based on a few visible signals; attackers can evade them, and legitimate mail can trigger warnings. Check the evidence and independently confirm unusual requests before acting."
                elif any(word in q for word in ("reply-to", "return-path", "domain mismatch")):
                    answer = "Reply-To controls where a reply is sent, while Return-Path records the envelope return address used for delivery. Differences from the visible From domain can be legitimate (for example, mailing services), but unexpected reply destinations deserve verification."
                else:
                    answer = "I can explain email spoofing, SPF/DKIM/DMARC, sender and Reply-To mismatches, links, attachments, or your latest analysis report. Ask about one of those, and verify important requests through a known independent channel."
                return self.send_json({"answer": answer, "mode": "offline-guide"})
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                return self.send_json({"error": "Could not read that question"}, 400)
        if path == "/api/history/clear":
            try:
                with LOCK, db() as con: con.execute("DELETE FROM history")
                return self.send_json({"ok": True})
            except Exception as exc:
                return self.send_json({"error": "Could not clear history: " + str(exc)}, 500)
        if path != "/api/analyze":
            return self.send_json({"error": "Not found"}, 404)
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send_json({"error": "Invalid upload size"}, 400)
        if length <= 0 or length > MAX_UPLOAD + 65536:
            return self.send_json({"error": "Upload must be between 1 byte and 5 MB"}, 413)
        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype:
            return self.send_json({"error": "Upload an .eml file using multipart form data"}, 415)
        try:
            multipart = b"Content-Type: " + ctype.encode("ascii", "replace") + b"\r\nMIME-Version: 1.0\r\n\r\n" + self.rfile.read(length)
            form = BytesParser(policy=policy.default).parsebytes(multipart)
            item = next((part for part in form.iter_parts() if part.get_param("name", header="content-disposition") == "file"), None)
            if item is None:
                return self.send_json({"error": "Choose an .eml file first"}, 400)
            filename = Path(item.get_filename() or "email.eml").name
            if not filename.lower().endswith(".eml"):
                return self.send_json({"error": "Only .eml email files are supported"}, 415)
            raw = file_bytes(item)
            if not raw or len(raw) > MAX_UPLOAD:
                return self.send_json({"error": "File is empty or exceeds the 5 MB limit"}, 413)
            report = analyze(raw, filename)
            with LOCK, db() as con:
                cur = con.execute("INSERT INTO history(created,filename,subject,sender,verdict,score,report) VALUES(?,?,?,?,?,?,?)", (datetime.now(timezone.utc).isoformat(), report["filename"], report["subject"], report["sender"], report["verdict"], report["score"], json.dumps(report, ensure_ascii=False)))
                report["id"] = cur.lastrowid
            return self.send_json({"result": report})
        except Exception as exc:
            return self.send_json({"error": "Could not parse this email file. Check that it is a valid .eml message.", "detail": str(exc)[:250]}, 400)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    print(f"S.P.E.A.R backend: http://{HOST}:{PORT}\nLocal-only server. Press Ctrl+C to stop.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
