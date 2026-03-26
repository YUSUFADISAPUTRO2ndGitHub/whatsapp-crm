import sys
import json
import time
import math
import re
import socket
import subprocess
import datetime
import ipaddress
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QPoint, QRectF
from PyQt6.QtGui import QColor, QPainter, QPen, QFont, QPixmap, QAction
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QAbstractItemView,
    QHeaderView,
    QTableWidgetItem,
    QSplitter,
    QTabWidget,
    QLineEdit,
    QComboBox,
    QPlainTextEdit,
    QMessageBox,
    QProgressBar,
    QFormLayout,
    QStatusBar,
)


APP_TITLE = "Master WhatsApp Dashboard"
CLIENT_API_PORT = 5001
CLIENT_API_TOKEN = "PTN_LOCKED_BROWSER_API_TOKEN_2026_STATIC"
CLIENT_API_HEADER_NAME = "X-API-Token"

FLOOR_SUBNETS = [
    "10.20.2.0/24",
    "10.20.3.0/24",
    "10.20.4.0/24",
]

SCAN_TIMEOUT_SECONDS = 0.75
REFRESH_TIMEOUT_SECONDS = 2.5
LIVE_VIEW_TIMEOUT_SECONDS = 5.0
SCAN_MAX_WORKERS = 64
REFRESH_MAX_WORKERS = 16
DISCOVERY_ADJACENT_SUBNET_SPAN = 1
DISCOVERY_ARP_MAX_HOSTS = 256
AUTO_REFRESH_MS = 30 * 1000
AUTO_RESCAN_MS = 3 * 60 * 1000
MESSAGE_PAGE_SIZE = 500
QC_CONVERSATION_PAGE_SIZE = 200
MAX_VISIBLE_MESSAGES = 2500
MAX_VISIBLE_QC_MESSAGES = 500
LIVE_VIEW_MAX_WIDTH = 720
LIVE_VIEW_QUALITY = 55

OUTGOING_SEND_TYPES = {"manual", "bulk_auto", "sync_outgoing"}
INCOMING_SEND_TYPES = {"incoming_reply", "sync_incoming"}

KNOWN_API_ENDPOINTS = [
    {
        "name": "Client Info",
        "method": "GET",
        "path": "/api/v1/get/client-info",
        "default_params": {},
        "description": "Device identity, hostname, MAC, OS, and local IPs."
    },
    {
        "name": "Tab Stats",
        "method": "GET",
        "path": "/api/v1/get/tab-stats",
        "default_params": {},
        "description": "Open tab counts, logged-in WhatsApp tab counts, and touched-vs-idle usage."
    },
    {
        "name": "Templates",
        "method": "GET",
        "path": "/api/v1/get/templates",
        "default_params": {"page": 1, "pageSize": 20},
        "description": "Saved templates on the client."
    },
    {
        "name": "Send / Receive Messages",
        "method": "GET",
        "path": "/api/v1/get/send-receive-messages",
        "default_params": {"page": 1, "pageSize": 50},
        "description": "Recent WhatsApp history rows."
    },
    {
        "name": "Bad Word Stats",
        "method": "GET",
        "path": "/api/v1/get/bad-word-stats",
        "default_params": {},
        "description": "Bad-word event summary by day."
    },
    {
        "name": "QC Conversations",
        "method": "GET",
        "path": "/api/v1/get/qc-conversations",
        "default_params": {"page": 1, "pageSize": 50},
        "description": "Conversation summaries grouped by contact."
    },
    {
        "name": "QC Conversation Messages",
        "method": "GET",
        "path": "/api/v1/get/qc-conversation-messages",
        "default_params": {"contact": ""},
        "description": "Conversation message detail for one contact."
    },
    {
        "name": "Live View",
        "method": "GET",
        "path": "/api/v1/live-view",
        "default_params": {"fps": 1, "quality": 60, "maxWidth": 960, "scope": "tab"},
        "description": "MJPEG live view stream from the client window."
    },
    {
        "name": "Active Tab Screenshot",
        "method": "GET",
        "path": "/api/v1/get/active-tab-screenshot",
        "default_params": {"quality": 82, "maxWidth": 1440},
        "description": "Single JPEG screenshot of the client's current active tab."
    },
    {
        "name": "Show Popup Message",
        "method": "POST",
        "path": "/api/v1/show/popup-message",
        "default_params": {},
        "default_body": {
            "title": "Notice from Master Dashboard",
            "message": "Please review your WhatsApp client.",
            "level": "warning",
            "durationSeconds": 0,
            "source": "Master Dashboard",
        },
        "description": "Show a notice or warning popup on the selected client."
    },
]


def safe_int(value, default=0, minimum=None, maximum=None):
    try:
        result = int(value)
    except Exception:
        result = default
    if minimum is not None:
        result = max(minimum, result)
    if maximum is not None:
        result = min(maximum, result)
    return result


def now_local():
    try:
        return datetime.datetime.now().astimezone()
    except Exception:
        return datetime.datetime.now()


def today_key():
    return now_local().strftime("%Y-%m-%d")


def iso_day_offset(days):
    return (now_local() - datetime.timedelta(days=days)).strftime("%Y-%m-%d")


def parse_timestamp(value):
    text = str(value or "").strip()
    if not text:
        return None

    try:
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        pass

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            return datetime.datetime.strptime(text, fmt)
        except Exception:
            continue
    return None


def format_timestamp(value, fallback="-"):
    dt = value if isinstance(value, datetime.datetime) else parse_timestamp(value)
    if dt is None:
        return fallback
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def format_short_timestamp(value, fallback="-"):
    dt = value if isinstance(value, datetime.datetime) else parse_timestamp(value)
    if dt is None:
        return fallback
    return dt.strftime("%m-%d %H:%M")


def format_latency(value):
    if value is None:
        return "-"
    return f"{int(round(float(value)))} ms"


def shorten_text(value, limit=90):
    text = " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 1)] + "…"


def host_sort_key(host):
    try:
        return int(ipaddress.ip_address(str(host or "").strip()))
    except Exception:
        return 0


def subnet_sort_key(subnet):
    try:
        network = ipaddress.ip_network(str(subnet or "").strip(), strict=False)
        return (network.version, int(network.network_address), int(network.prefixlen))
    except Exception:
        return (0, 0, 0)


def is_private_ipv4_address(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except Exception:
        return False
    return bool(
        getattr(addr, "version", 0) == 4
        and addr.is_private
        and not addr.is_loopback
        and not addr.is_link_local
    )


def normalize_subnet_list(subnets):
    seen = set()
    normalized = []
    for subnet in list(subnets or []):
        try:
            network = ipaddress.ip_network(str(subnet or "").strip(), strict=False)
        except Exception:
            continue
        if getattr(network, "version", 0) != 4:
            continue
        text = str(network)
        if text in seen:
            continue
        seen.add(text)
        normalized.append(text)
    normalized.sort(key=subnet_sort_key)
    return normalized


def detect_local_private_ipv4_addresses():
    addresses = set()

    def add_address(value):
        if is_private_ipv4_address(value):
            addresses.add(str(ipaddress.ip_address(str(value).strip())))

    try:
        hostname = socket.gethostname()
        for _, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM):
            if sockaddr:
                add_address(sockaddr[0])
    except Exception:
        pass

    try:
        _, _, host_list = socket.gethostbyname_ex(socket.gethostname())
        for value in host_list:
            add_address(value)
    except Exception:
        pass

    for probe_host in ("1.1.1.1", "8.8.8.8"):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((probe_host, 80))
            add_address(sock.getsockname()[0])
        except Exception:
            pass
        finally:
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass

    return sorted(addresses, key=host_sort_key)


def build_local_candidate_subnets(local_ips, adjacent_span=DISCOVERY_ADJACENT_SUBNET_SPAN):
    seen = set()
    subnets = []

    for ip_text in list(local_ips or []):
        try:
            network = ipaddress.ip_network(f"{str(ip_text).strip()}/24", strict=False)
        except Exception:
            continue

        base = int(network.network_address)
        for offset in range(-adjacent_span, adjacent_span + 1):
            candidate_base = base + (offset * 256)
            if candidate_base < 0 or candidate_base > (2 ** 32 - 256):
                continue

            try:
                network_address = ipaddress.ip_address(candidate_base)
            except Exception:
                continue

            if not is_private_ipv4_address(network_address):
                continue

            candidate = str(ipaddress.ip_network(f"{network_address}/24", strict=False))
            if candidate in seen:
                continue
            seen.add(candidate)
            subnets.append(candidate)

    subnets.sort(key=subnet_sort_key)
    return subnets


def collect_arp_neighbor_hosts(limit=DISCOVERY_ARP_MAX_HOSTS):
    hosts = set()
    try:
        raw = subprocess.check_output(
            ["arp", "-a"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2.0,
        )
    except Exception:
        raw = ""

    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw):
        if not is_private_ipv4_address(match):
            continue
        hosts.add(str(ipaddress.ip_address(match)))

    return sorted(hosts, key=host_sort_key)[: max(0, int(limit or 0))]


def build_discovery_plan(configured_subnets=None):
    configured = normalize_subnet_list(configured_subnets)
    local_ips = detect_local_private_ipv4_addresses()
    auto_subnets = build_local_candidate_subnets(local_ips)
    subnets = normalize_subnet_list(configured + auto_subnets)
    arp_hosts = collect_arp_neighbor_hosts()
    hosts = sorted(set(collect_hosts_from_subnets(subnets)).union(arp_hosts), key=host_sort_key)
    return {
        "configured_subnets": configured,
        "local_ips": local_ips,
        "subnets": subnets,
        "arp_hosts": arp_hosts,
        "hosts": hosts,
    }


def describe_discovery_plan(plan):
    plan = dict(plan or {})
    subnet_preview = list(plan.get("subnets") or [])
    local_ips = list(plan.get("local_ips") or [])
    arp_hosts = list(plan.get("arp_hosts") or [])

    subnet_text = ", ".join(subnet_preview[:4]) if subnet_preview else "none"
    if len(subnet_preview) > 4:
        subnet_text += f" +{len(subnet_preview) - 4} more"

    local_text = ", ".join(local_ips[:2]) if local_ips else "none"
    if len(local_ips) > 2:
        local_text += f" +{len(local_ips) - 2} more"

    return f"Scan Sources: {subnet_text} | Local IPs: {local_text} | ARP hosts: {len(arp_hosts)}"


def client_chart_label(snapshot):
    label = str(snapshot.get("client_label") or "").strip()
    if not label:
        label = str(snapshot.get("host") or "").strip()
    if len(label) <= 14:
        return label
    return label[:11] + "…"


def build_api_headers():
    return {
        CLIENT_API_HEADER_NAME: CLIENT_API_TOKEN,
        "Accept": "application/json",
        "User-Agent": "MasterWhatsAppDashboard/1.0",
    }


def build_client_url(host, path, params=None):
    query = urllib.parse.urlencode(params or {}, doseq=True)
    url = f"http://{host}:{CLIENT_API_PORT}{path}"
    if query:
        url += "?" + query
    return url


def request_json(host, path, params=None, timeout=REFRESH_TIMEOUT_SECONDS):
    url = build_client_url(host, path, params=params)
    req = urllib.request.Request(url, headers=build_api_headers(), method="GET")
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = safe_int(getattr(resp, "status", resp.getcode()), 200)
            raw = resp.read()
            latency_ms = (time.time() - started) * 1000.0
            payload = json.loads(raw.decode("utf-8")) if raw else {}
            if not isinstance(payload, dict):
                payload = {}
            return {
                "ok": status == 200 and bool(payload.get("ok", True)),
                "status": status,
                "payload": payload,
                "error": "",
                "latency_ms": latency_ms,
                "url": url,
            }
    except urllib.error.HTTPError as exc:
        latency_ms = (time.time() - started) * 1000.0
        raw = b""
        try:
            raw = exc.read()
        except Exception:
            raw = b""
        payload = {}
        if raw:
            try:
                decoded = json.loads(raw.decode("utf-8"))
                if isinstance(decoded, dict):
                    payload = decoded
            except Exception:
                payload = {}
        error_text = payload.get("message") or str(exc)
        return {
            "ok": False,
            "status": safe_int(exc.code, 0),
            "payload": payload,
            "error": str(error_text or "HTTP error"),
            "latency_ms": latency_ms,
            "url": url,
        }
    except Exception as exc:
        latency_ms = (time.time() - started) * 1000.0
        return {
            "ok": False,
            "status": 0,
            "payload": {},
            "error": str(exc),
            "latency_ms": latency_ms,
            "url": url,
        }


def request_json_post(host, path, payload=None, timeout=REFRESH_TIMEOUT_SECONDS):
    url = build_client_url(host, path)
    raw_payload = json.dumps(payload or {}, ensure_ascii=False).encode("utf-8")
    headers = dict(build_api_headers())
    headers["Content-Type"] = "application/json; charset=utf-8"
    req = urllib.request.Request(url, data=raw_payload, headers=headers, method="POST")
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = safe_int(getattr(resp, "status", resp.getcode()), 200)
            raw = resp.read()
            latency_ms = (time.time() - started) * 1000.0
            decoded = json.loads(raw.decode("utf-8")) if raw else {}
            payload_out = decoded if isinstance(decoded, dict) else {}
            return {
                "ok": status == 200 and bool(payload_out.get("ok", True)),
                "status": status,
                "payload": payload_out,
                "error": "",
                "latency_ms": latency_ms,
                "url": url,
            }
    except urllib.error.HTTPError as exc:
        latency_ms = (time.time() - started) * 1000.0
        raw = b""
        try:
            raw = exc.read()
        except Exception:
            raw = b""
        payload_out = {}
        if raw:
            try:
                decoded = json.loads(raw.decode("utf-8"))
                if isinstance(decoded, dict):
                    payload_out = decoded
            except Exception:
                payload_out = {}
        error_text = payload_out.get("message") or str(exc)
        return {
            "ok": False,
            "status": safe_int(exc.code, 0),
            "payload": payload_out,
            "error": str(error_text or "HTTP error"),
            "latency_ms": latency_ms,
            "url": url,
        }
    except Exception as exc:
        latency_ms = (time.time() - started) * 1000.0
        return {
            "ok": False,
            "status": 0,
            "payload": {},
            "error": str(exc),
            "latency_ms": latency_ms,
            "url": url,
        }


def fetch_live_view_frame(host, scope="tab", timeout=LIVE_VIEW_TIMEOUT_SECONDS):
    params = {
        "fps": 1,
        "quality": LIVE_VIEW_QUALITY,
        "maxWidth": LIVE_VIEW_MAX_WIDTH,
        "scope": scope,
    }
    url = build_client_url(host, "/api/v1/live-view", params=params)
    req = urllib.request.Request(url, headers=build_api_headers(), method="GET")
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = safe_int(getattr(resp, "status", resp.getcode()), 200)
            if status != 200:
                return {"ok": False, "status": status, "error": f"HTTP {status}", "image_bytes": b"", "latency_ms": (time.time() - started) * 1000.0}

            buffer = b""
            deadline = time.time() + timeout
            while time.time() < deadline and len(buffer) < (6 * 1024 * 1024):
                chunk = resp.read(4096)
                if not chunk:
                    break
                buffer += chunk
                start_idx = buffer.find(b"\xff\xd8")
                if start_idx < 0:
                    continue
                end_idx = buffer.find(b"\xff\xd9", start_idx + 2)
                if end_idx < 0:
                    continue
                image_bytes = buffer[start_idx:end_idx + 2]
                return {
                    "ok": True,
                    "status": status,
                    "error": "",
                    "image_bytes": image_bytes,
                    "latency_ms": (time.time() - started) * 1000.0,
                }
        return {"ok": False, "status": 0, "error": "No JPEG frame received", "image_bytes": b"", "latency_ms": (time.time() - started) * 1000.0}
    except Exception as exc:
        return {"ok": False, "status": 0, "error": str(exc), "image_bytes": b"", "latency_ms": (time.time() - started) * 1000.0}


def fetch_image_endpoint(host, path, params=None, timeout=LIVE_VIEW_TIMEOUT_SECONDS):
    url = build_client_url(host, path, params=params)
    req = urllib.request.Request(url, headers=build_api_headers(), method="GET")
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = safe_int(getattr(resp, "status", resp.getcode()), 200)
            raw = resp.read()
            latency_ms = (time.time() - started) * 1000.0
            content_type = str(resp.headers.get("Content-Type") or "").strip()
            meta = {
                "captured_at": str(resp.headers.get("X-Captured-At") or "").strip(),
                "current_tab": str(resp.headers.get("X-Current-Tab") or "").strip(),
                "current_url": str(resp.headers.get("X-Current-Url") or "").strip(),
                "scope": str(resp.headers.get("X-Scope") or "").strip(),
                "width": str(resp.headers.get("X-Width") or "").strip(),
                "height": str(resp.headers.get("X-Height") or "").strip(),
            }
            ok = status == 200 and bool(raw) and content_type.lower().startswith("image/")
            return {
                "ok": ok,
                "status": status,
                "error": "" if ok else f"Unexpected response: {content_type or 'unknown content type'}",
                "image_bytes": raw if ok else b"",
                "latency_ms": latency_ms,
                "url": url,
                "content_type": content_type,
                "meta": meta,
                "payload": {},
            }
    except urllib.error.HTTPError as exc:
        latency_ms = (time.time() - started) * 1000.0
        raw = b""
        payload = {}
        try:
            raw = exc.read()
        except Exception:
            raw = b""
        if raw:
            try:
                decoded = json.loads(raw.decode("utf-8"))
                if isinstance(decoded, dict):
                    payload = decoded
            except Exception:
                payload = {}
        return {
            "ok": False,
            "status": safe_int(exc.code, 0, 0),
            "error": str(payload.get("message") or exc),
            "image_bytes": b"",
            "latency_ms": latency_ms,
            "url": url,
            "content_type": str(exc.headers.get("Content-Type") or "").strip() if getattr(exc, "headers", None) else "",
            "meta": {},
            "payload": payload,
        }
    except Exception as exc:
        return {
            "ok": False,
            "status": 0,
            "error": str(exc),
            "image_bytes": b"",
            "latency_ms": (time.time() - started) * 1000.0,
            "url": url,
            "content_type": "",
            "meta": {},
            "payload": {},
        }


def is_outgoing_send_type(send_type):
    return str(send_type or "").strip().lower() in OUTGOING_SEND_TYPES


def is_incoming_send_type(send_type):
    return str(send_type or "").strip().lower() in INCOMING_SEND_TYPES


def normalize_message_rows(host, raw_items):
    rows = []
    for index, item in enumerate(list(raw_items or [])):
        if not isinstance(item, dict):
            continue

        send_type = str(item.get("send_type") or "").strip().lower()
        if is_outgoing_send_type(send_type):
            direction = "outgoing"
        elif is_incoming_send_type(send_type):
            direction = "incoming"
        else:
            direction = "other"

        if direction == "other":
            continue

        timestamp_text = str(item.get("timestamp") or "").strip()
        timestamp_dt = parse_timestamp(timestamp_text)
        account = str(
            item.get("account_label")
            or (item.get("from") if direction == "outgoing" else item.get("to"))
            or ""
        ).strip()
        contact = str(
            item.get("chat_label")
            or item.get("to_phone")
            or item.get("from_phone")
            or item.get("to")
            or item.get("from_display")
            or item.get("from")
            or item.get("conversation_key")
            or ""
        ).strip()
        content = str(item.get("content") or "").strip()
        preview = shorten_text(content, 120)

        row = {
            "host": host,
            "timestamp": timestamp_text,
            "timestamp_dt": timestamp_dt,
            "timestamp_display": format_timestamp(timestamp_dt, fallback=timestamp_text or "-"),
            "direction": direction,
            "send_type": send_type,
            "status": str(item.get("status") or "").strip().lower(),
            "account": account,
            "contact": contact,
            "content": content,
            "preview": preview,
            "conversation_key": str(item.get("conversation_key") or "").strip(),
            "bad_word_count": safe_int(item.get("bad_word_count"), 0, 0),
            "has_attachment": bool(item.get("has_attachment")),
            "trigger": str(item.get("trigger") or "").strip(),
            "message_author": str(item.get("message_author") or "").strip(),
            "index": index,
        }
        rows.append(row)

    rows.sort(
        key=lambda row: (
            row.get("timestamp_dt") or datetime.datetime.min,
            -safe_int(row.get("index"), 0)
        ),
        reverse=True
    )
    return rows


def compute_message_metrics(rows):
    today = today_key()
    sent_today = 0
    received_today = 0
    failed_today = 0
    sent_recent = 0
    received_recent = 0
    failed_recent = 0
    unique_contacts = set()
    active_accounts = set()
    last_activity_dt = None
    last_preview = ""
    last_contact = ""

    hourly_labels = []
    sent_by_hour = []
    received_by_hour = []

    hour_keys = []
    for offset in range(23, -1, -1):
        dt = now_local() - datetime.timedelta(hours=offset)
        hour_keys.append(dt.strftime("%Y-%m-%d %H:00"))
        hourly_labels.append(dt.strftime("%H:%M"))

    sent_hour_map = {key: 0 for key in hour_keys}
    received_hour_map = {key: 0 for key in hour_keys}

    for row in rows:
        if row.get("direction") == "outgoing":
            sent_recent += 1
        elif row.get("direction") == "incoming":
            received_recent += 1

        if row.get("status") == "failed":
            failed_recent += 1

        if row.get("contact"):
            unique_contacts.add(row.get("contact"))
        if row.get("account"):
            active_accounts.add(row.get("account"))

        ts_dt = row.get("timestamp_dt")
        if ts_dt is not None:
            ts_day = ts_dt.strftime("%Y-%m-%d")
            if ts_day == today:
                if row.get("direction") == "outgoing":
                    sent_today += 1
                elif row.get("direction") == "incoming":
                    received_today += 1
                if row.get("status") == "failed":
                    failed_today += 1

            hour_key = ts_dt.strftime("%Y-%m-%d %H:00")
            if hour_key in sent_hour_map:
                if row.get("direction") == "outgoing":
                    sent_hour_map[hour_key] += 1
                elif row.get("direction") == "incoming":
                    received_hour_map[hour_key] += 1

            if last_activity_dt is None or ts_dt > last_activity_dt:
                last_activity_dt = ts_dt
                last_preview = row.get("preview") or ""
                last_contact = row.get("contact") or ""

    for key in hour_keys:
        sent_by_hour.append(sent_hour_map.get(key, 0))
        received_by_hour.append(received_hour_map.get(key, 0))

    return {
        "sent_today": sent_today,
        "received_today": received_today,
        "failed_today": failed_today,
        "sent_recent": sent_recent,
        "received_recent": received_recent,
        "failed_recent": failed_recent,
        "unique_contacts": len(unique_contacts),
        "active_accounts": sorted(active_accounts),
        "active_accounts_text": ", ".join(sorted(active_accounts)),
        "last_activity_dt": last_activity_dt,
        "last_activity_text": format_timestamp(last_activity_dt, fallback="-"),
        "last_preview": last_preview,
        "last_contact": last_contact,
        "hour_labels": hourly_labels,
        "sent_by_hour": sent_by_hour,
        "received_by_hour": received_by_hour,
    }


def build_bad_word_series(items):
    wanted_days = [iso_day_offset(offset) for offset in range(6, -1, -1)]
    event_map = {day: 0 for day in wanted_days}
    hit_map = {day: 0 for day in wanted_days}

    for item in list(items or []):
        if not isinstance(item, dict):
            continue
        day = str(item.get("date") or "").strip()
        if day not in event_map:
            continue
        event_map[day] += safe_int(item.get("events"), 0, 0)
        hit_map[day] += safe_int(item.get("total_hits"), 0, 0)

    return {
        "labels": [day[5:] for day in wanted_days],
        "events": [event_map[day] for day in wanted_days],
        "hits": [hit_map[day] for day in wanted_days],
        "events_today": event_map.get(today_key(), 0),
        "hits_today": hit_map.get(today_key(), 0),
        "events_total": sum(event_map.values()),
        "hits_total": sum(hit_map.values()),
    }


def derive_client_label(host, message_metrics, qc_conversations):
    accounts = list(message_metrics.get("active_accounts") or [])
    if accounts:
        return accounts[0]

    for row in list(qc_conversations or []):
        if not isinstance(row, dict):
            continue
        accounts = [str(x).strip() for x in (row.get("self_accounts") or []) if str(x).strip()]
        if accounts:
            return accounts[0]
        text = str(row.get("self_accounts_text") or "").strip()
        if text:
            return text.split(",")[0].strip()

    return host


def summarize_endpoint_result(result, fallback_name=""):
    payload = dict(result.get("payload") or {})
    return {
        "name": fallback_name,
        "ok": bool(result.get("ok")),
        "status": safe_int(result.get("status"), 0, 0),
        "latency_ms": result.get("latency_ms"),
        "error": str(result.get("error") or payload.get("message") or "").strip(),
        "count": safe_int(payload.get("total"), 0, 0),
    }


def probe_client(host):
    result = request_json(
        host,
        "/api/v1/get/templates",
        params={"page": 1, "pageSize": 1},
        timeout=SCAN_TIMEOUT_SECONDS,
    )
    if not result.get("ok"):
        return None
    return {
        "host": host,
        "port": CLIENT_API_PORT,
        "latency_ms": result.get("latency_ms"),
        "base_url": f"http://{host}:{CLIENT_API_PORT}",
    }


def collect_hosts_from_subnets(subnets):
    hosts = set()
    for subnet in list(subnets or []):
        try:
            network = ipaddress.ip_network(str(subnet).strip(), strict=False)
        except Exception:
            continue
        for host in network.hosts():
            hosts.add(str(host))
    return sorted(hosts, key=host_sort_key)


def fetch_client_snapshot(host):
    today = today_key()
    week_start = iso_day_offset(6)

    templates_result = request_json(
        host,
        "/api/v1/get/templates",
        params={"page": 1, "pageSize": 1},
        timeout=REFRESH_TIMEOUT_SECONDS,
    )

    if not templates_result.get("ok"):
        return {
            "host": host,
            "online": False,
            "client_label": host,
            "base_url": f"http://{host}:{CLIENT_API_PORT}",
            "latency_ms": templates_result.get("latency_ms"),
            "messages": [],
            "qc_conversations": [],
            "bad_word_items": [],
            "endpoint_health": {
                "templates": summarize_endpoint_result(templates_result, "Templates")
            },
            "error": str(templates_result.get("error") or "Client unavailable"),
            "last_refreshed_at": format_timestamp(now_local()),
        }

    messages_result = request_json(
        host,
        "/api/v1/get/send-receive-messages",
        params={"page": 1, "pageSize": MESSAGE_PAGE_SIZE},
        timeout=REFRESH_TIMEOUT_SECONDS,
    )
    qc_result = request_json(
        host,
        "/api/v1/get/qc-conversations",
        params={"page": 1, "pageSize": QC_CONVERSATION_PAGE_SIZE},
        timeout=REFRESH_TIMEOUT_SECONDS,
    )
    bad_word_result = request_json(
        host,
        "/api/v1/get/bad-word-stats",
        params={"from": week_start, "to": today},
        timeout=REFRESH_TIMEOUT_SECONDS,
    )
    client_info_result = request_json(
        host,
        "/api/v1/get/client-info",
        params={},
        timeout=REFRESH_TIMEOUT_SECONDS,
    )
    tab_stats_result = request_json(
        host,
        "/api/v1/get/tab-stats",
        params={},
        timeout=REFRESH_TIMEOUT_SECONDS,
    )

    raw_messages = list(messages_result.get("payload", {}).get("items") or [])
    qc_conversations = list(qc_result.get("payload", {}).get("items") or [])
    bad_word_items = list(bad_word_result.get("payload", {}).get("items") or [])
    client_info = dict(client_info_result.get("payload") or {})
    tab_stats = dict(tab_stats_result.get("payload") or {})

    normalized_messages = normalize_message_rows(host, raw_messages)
    message_metrics = compute_message_metrics(normalized_messages)
    bad_word_metrics = build_bad_word_series(bad_word_items)
    client_label = derive_client_label(host, message_metrics, qc_conversations)
    if client_label == host:
        client_label = str(client_info.get("device_name") or client_info.get("hostname") or host).strip() or host
    endpoint_health = {
        "client_info": summarize_endpoint_result(client_info_result, "Client Info"),
        "tab_stats": summarize_endpoint_result(tab_stats_result, "Tab Stats"),
        "templates": summarize_endpoint_result(templates_result, "Templates"),
        "messages": summarize_endpoint_result(messages_result, "Messages"),
        "qc_conversations": summarize_endpoint_result(qc_result, "QC Conversations"),
        "bad_words": summarize_endpoint_result(bad_word_result, "Bad Word Stats"),
        "live_view": {"name": "Live View", "ok": False, "status": 0, "latency_ms": None, "error": "", "count": 0},
    }

    active_accounts = list(message_metrics.get("active_accounts") or [])
    if not active_accounts:
        account_set = set()
        for row in qc_conversations:
            for account in list(row.get("self_accounts") or []):
                account_text = str(account or "").strip()
                if account_text:
                    account_set.add(account_text)
        active_accounts = sorted(account_set)

    return {
        "host": host,
        "online": True,
        "client_label": client_label,
        "client_info": client_info,
        "tab_stats": tab_stats,
        "base_url": f"http://{host}:{CLIENT_API_PORT}",
        "latency_ms": templates_result.get("latency_ms"),
        "device_name": str(client_info.get("device_name") or client_info.get("hostname") or host),
        "device_id": str(client_info.get("device_id") or client_info.get("device_name") or host),
        "hostname_text": str(client_info.get("hostname") or "-"),
        "mac_address": str(client_info.get("mac_address") or ""),
        "local_ips_text": ", ".join(list(client_info.get("local_ips") or [])),
        "platform_summary": str(client_info.get("platform") or client_info.get("system") or "-"),
        "machine": str(client_info.get("machine") or "-"),
        "current_tab_name": str(tab_stats.get("current_tab") or client_info.get("current_tab") or "-"),
        "tabs_total": safe_int(tab_stats.get("total_tabs"), 0, 0),
        "open_whatsapp_tabs": safe_int(tab_stats.get("open_whatsapp_tabs"), 0, 0),
        "logged_in_tabs": safe_int(tab_stats.get("logged_in_tabs"), 0, 0),
        "touched_tab_count": safe_int(tab_stats.get("touched_tab_count"), 0, 0),
        "untouched_tab_count": safe_int(tab_stats.get("untouched_tab_count"), 0, 0),
        "templates_total": safe_int(templates_result.get("payload", {}).get("total"), 0, 0),
        "message_total": safe_int(messages_result.get("payload", {}).get("total"), 0, 0),
        "qc_conversation_total": safe_int(qc_result.get("payload", {}).get("total"), 0, 0),
        "messages_loaded": len(normalized_messages),
        "messages": normalized_messages,
        "qc_conversations": qc_conversations,
        "bad_word_items": bad_word_items,
        "endpoint_health": endpoint_health,
        "active_accounts": active_accounts,
        "active_accounts_text": ", ".join(active_accounts),
        "today_sent": message_metrics.get("sent_today", 0),
        "today_received": message_metrics.get("received_today", 0),
        "today_failed": message_metrics.get("failed_today", 0),
        "recent_sent": message_metrics.get("sent_recent", 0),
        "recent_received": message_metrics.get("received_recent", 0),
        "recent_failed": message_metrics.get("failed_recent", 0),
        "unique_contacts": message_metrics.get("unique_contacts", 0),
        "last_activity_dt": message_metrics.get("last_activity_dt"),
        "last_activity_text": message_metrics.get("last_activity_text", "-"),
        "last_preview": message_metrics.get("last_preview", ""),
        "last_contact": message_metrics.get("last_contact", ""),
        "hour_labels": message_metrics.get("hour_labels", []),
        "sent_by_hour": message_metrics.get("sent_by_hour", []),
        "received_by_hour": message_metrics.get("received_by_hour", []),
        "bad_word_events_today": bad_word_metrics.get("events_today", 0),
        "bad_word_hits_today": bad_word_metrics.get("hits_today", 0),
        "bad_word_events_total": bad_word_metrics.get("events_total", 0),
        "bad_word_hits_total": bad_word_metrics.get("hits_total", 0),
        "bad_word_labels": bad_word_metrics.get("labels", []),
        "bad_word_event_series": bad_word_metrics.get("events", []),
        "bad_word_hit_series": bad_word_metrics.get("hits", []),
        "error": "",
        "last_refreshed_at": format_timestamp(now_local()),
    }


def fetch_qc_conversation_messages(host, contact_key="", account_filter=""):
    params = {
        "page": 1,
        "pageSize": MAX_VISIBLE_QC_MESSAGES,
        "contact": contact_key,
    }
    if account_filter:
        params["account"] = account_filter
    return request_json(
        host,
        "/api/v1/get/qc-conversation-messages",
        params=params,
        timeout=REFRESH_TIMEOUT_SECONDS,
    )


def make_table_item(value="", user_data=None, align=None):
    item = QTableWidgetItem(str(value))
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    if user_data is not None:
        item.setData(Qt.ItemDataRole.UserRole, user_data)
    if align is not None:
        item.setTextAlignment(int(align))
    return item


def prepare_table_widget(table, headers, stretch_last=False):
    table.setColumnCount(len(headers))
    table.setHorizontalHeaderLabels([str(h) for h in headers])
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setShowGrid(True)
    table.setAlternatingRowColors(True)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setHighlightSections(False)
    table.setWordWrap(False)
    table.setSortingEnabled(False)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    header = table.horizontalHeader()
    if stretch_last:
        header.setStretchLastSection(True)
    else:
        header.setStretchLastSection(False)
    for col in range(len(headers)):
        header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
    return table


def select_first_row(table):
    if table.rowCount() <= 0 or table.columnCount() <= 0:
        return
    table.setCurrentCell(0, 0)
    table.selectRow(0)


def apply_windows_table_theme(window):
    window.setStyleSheet(
        """
        QWidget {
            background: #dfe8f7;
            color: #13325b;
            font-family: "Segoe UI", "Tahoma", sans-serif;
            font-size: 12px;
        }
        QMainWindow, QDialog {
            background: #dfe8f7;
        }
        QLabel {
            color: #123766;
        }
        QPushButton, QToolButton {
            background: #f7faff;
            color: #0d2d63;
            border: 1px solid #8fa9d4;
            padding: 6px 12px;
            font-weight: 700;
        }
        QPushButton:hover, QToolButton:hover {
            background: #edf4ff;
        }
        QPushButton:pressed, QToolButton:pressed {
            background: #dce8fb;
        }
        QLineEdit, QPlainTextEdit, QComboBox, QTableWidget, QTabWidget::pane, QProgressBar {
            background: #ffffff;
            color: #10315e;
            border: 1px solid #8fa9d4;
        }
        QLineEdit, QPlainTextEdit, QComboBox {
            padding: 4px;
        }
        QComboBox::drop-down {
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 24px;
            border-left: 1px solid #8fa9d4;
            background: #dbe7ff;
        }
        QTabBar::tab {
            background: #dbe7ff;
            color: #21467a;
            border: 1px solid #8fa9d4;
            padding: 6px 10px;
            margin-right: 2px;
            font-weight: 700;
        }
        QTabBar::tab:selected {
            background: #ffffff;
            color: #0d2d63;
        }
        QHeaderView::section {
            background: #d8e6ff;
            color: #17386a;
            border: 1px solid #8fa9d4;
            padding: 6px;
            font-weight: 700;
        }
        QTableWidget {
            gridline-color: #c1d3f0;
            selection-background-color: #2b5fd9;
            selection-color: #ffffff;
        }
        QProgressBar {
            min-height: 18px;
            text-align: center;
        }
        QProgressBar::chunk {
            background: #2b5fd9;
        }
        QStatusBar {
            background: #d8e6ff;
            color: #14376a;
            border-top: 1px solid #8fa9d4;
        }
        """
    )


class ChartCard(QWidget):
    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self.title = str(title or "").strip()
        self._empty_text = "No data"
        self.setMinimumHeight(260)

    def set_empty_text(self, text):
        self._empty_text = str(text or "").strip() or "No data"
        self.update()

    def draw_card_background(self, painter):
        rect = self.rect().adjusted(0, 0, -1, -1)
        painter.fillRect(rect, QColor("#ffffff"))
        painter.setPen(QPen(QColor("#8fa9d4"), 1))
        painter.drawRect(rect)

        if self.title:
            title_rect = QRectF(14, 10, rect.width() - 28, 22)
            painter.setPen(QColor("#0d2d63"))
            font = QFont(painter.font())
            font.setBold(True)
            font.setPointSize(11)
            painter.setFont(font)
            painter.drawText(title_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, self.title)

    def draw_empty(self, painter):
        painter.setPen(QColor("#6f86a7"))
        painter.drawText(
            self.rect().adjusted(12, 42, -12, -12),
            Qt.AlignmentFlag.AlignCenter,
            self._empty_text
        )


class GroupedBarChartWidget(ChartCard):
    def __init__(self, title="", parent=None):
        super().__init__(title=title, parent=parent)
        self.labels = []
        self.series = []

    def set_chart_data(self, labels, series):
        self.labels = list(labels or [])
        self.series = list(series or [])
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        self.draw_card_background(painter)

        if not self.labels or not self.series:
            self.draw_empty(painter)
            return

        chart_rect = self.rect().adjusted(48, 44, -18, -48)
        if chart_rect.width() <= 20 or chart_rect.height() <= 20:
            return

        max_value = max([max(list(s.get("values") or [0])) for s in self.series] + [1])
        if max_value <= 0:
            max_value = 1

        painter.setPen(QPen(QColor("#d1def4"), 1))
        for step in range(6):
            y = chart_rect.bottom() - (chart_rect.height() * step / 5.0)
            painter.drawLine(chart_rect.left(), int(y), chart_rect.right(), int(y))

        painter.setPen(QPen(QColor("#7f95b9"), 1))
        painter.drawLine(chart_rect.left(), chart_rect.top(), chart_rect.left(), chart_rect.bottom())
        painter.drawLine(chart_rect.left(), chart_rect.bottom(), chart_rect.right(), chart_rect.bottom())

        label_count = max(1, len(self.labels))
        group_width = chart_rect.width() / label_count
        inner_group_width = max(12.0, group_width * 0.72)
        series_count = max(1, len(self.series))
        bar_width = max(6.0, inner_group_width / series_count)

        value_font = QFont(painter.font())
        value_font.setPointSize(8)
        painter.setFont(value_font)

        for idx, label in enumerate(self.labels):
            group_left = chart_rect.left() + idx * group_width + (group_width - inner_group_width) / 2.0
            for series_index, series in enumerate(self.series):
                values = list(series.get("values") or [])
                value = values[idx] if idx < len(values) else 0
                color = QColor(series.get("color") or "#2b5fd9")
                bar_left = group_left + series_index * bar_width + 1
                bar_height = 0 if max_value <= 0 else (chart_rect.height() * float(value) / float(max_value))
                bar_rect = QRectF(bar_left, chart_rect.bottom() - bar_height, max(4.0, bar_width - 3), bar_height)
                painter.fillRect(bar_rect, color)
                painter.setPen(QPen(color.darker(115), 1))
                painter.drawRect(bar_rect)

            painter.setPen(QColor("#274a7b"))
            text_rect = QRectF(group_left - 6, chart_rect.bottom() + 6, inner_group_width + 12, 28)
            painter.drawText(text_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, shorten_text(label, 12))

        painter.setPen(QColor("#536d93"))
        for step in range(6):
            value = int(round(max_value * step / 5.0))
            y = chart_rect.bottom() - (chart_rect.height() * step / 5.0)
            painter.drawText(QRectF(4, y - 8, 38, 16), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, str(value))

        legend_x = chart_rect.left()
        legend_y = 18
        for series in self.series:
            color = QColor(series.get("color") or "#2b5fd9")
            painter.fillRect(QRectF(legend_x, legend_y, 14, 10), color)
            painter.setPen(QColor("#17386a"))
            painter.drawRect(QRectF(legend_x, legend_y, 14, 10))
            painter.drawText(QRectF(legend_x + 20, legend_y - 4, 140, 18), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, str(series.get("name") or "Series"))
            legend_x += 150


class MultiLineChartWidget(ChartCard):
    def __init__(self, title="", parent=None):
        super().__init__(title=title, parent=parent)
        self.labels = []
        self.series = []

    def set_chart_data(self, labels, series):
        self.labels = list(labels or [])
        self.series = list(series or [])
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        self.draw_card_background(painter)

        if not self.labels or not self.series:
            self.draw_empty(painter)
            return

        chart_rect = self.rect().adjusted(48, 44, -18, -48)
        if chart_rect.width() <= 20 or chart_rect.height() <= 20:
            return

        max_value = max([max(list(s.get("values") or [0])) for s in self.series] + [1])
        if max_value <= 0:
            max_value = 1

        painter.setPen(QPen(QColor("#d1def4"), 1))
        for step in range(6):
            y = chart_rect.bottom() - (chart_rect.height() * step / 5.0)
            painter.drawLine(chart_rect.left(), int(y), chart_rect.right(), int(y))

        painter.setPen(QPen(QColor("#7f95b9"), 1))
        painter.drawLine(chart_rect.left(), chart_rect.top(), chart_rect.left(), chart_rect.bottom())
        painter.drawLine(chart_rect.left(), chart_rect.bottom(), chart_rect.right(), chart_rect.bottom())

        count = max(1, len(self.labels))
        x_step = chart_rect.width() / max(1, count - 1)

        value_font = QFont(painter.font())
        value_font.setPointSize(8)
        painter.setFont(value_font)

        for series in self.series:
            values = list(series.get("values") or [])
            color = QColor(series.get("color") or "#2b5fd9")
            pen = QPen(color, 2)
            painter.setPen(pen)

            previous_point = None
            for idx in range(count):
                value = values[idx] if idx < len(values) else 0
                x = chart_rect.left() + idx * x_step
                y = chart_rect.bottom() - (chart_rect.height() * float(value) / float(max_value))
                point = QPoint(int(round(x)), int(round(y)))
                if previous_point is not None:
                    painter.drawLine(previous_point, point)
                painter.setBrush(color)
                painter.drawEllipse(point, 3, 3)
                previous_point = point

        painter.setPen(QColor("#536d93"))
        for step in range(6):
            value = int(round(max_value * step / 5.0))
            y = chart_rect.bottom() - (chart_rect.height() * step / 5.0)
            painter.drawText(QRectF(4, y - 8, 38, 16), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, str(value))

        label_step = max(1, int(math.ceil(len(self.labels) / 8.0)))
        painter.setPen(QColor("#274a7b"))
        for idx, label in enumerate(self.labels):
            if idx % label_step != 0 and idx != len(self.labels) - 1:
                continue
            x = chart_rect.left() + idx * x_step
            text_rect = QRectF(x - 30, chart_rect.bottom() + 6, 60, 24)
            painter.drawText(text_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, shorten_text(label, 10))

        legend_x = chart_rect.left()
        legend_y = 18
        for series in self.series:
            color = QColor(series.get("color") or "#2b5fd9")
            painter.fillRect(QRectF(legend_x, legend_y, 14, 10), color)
            painter.setPen(QColor("#17386a"))
            painter.drawRect(QRectF(legend_x, legend_y, 14, 10))
            painter.drawText(QRectF(legend_x + 20, legend_y - 4, 160, 18), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, str(series.get("name") or "Series"))
            legend_x += 165


class DiscoveryWorker(QThread):
    progress = pyqtSignal(int, int)
    finished_scan = pyqtSignal(object)

    def __init__(self, discovery_plan, parent=None):
        super().__init__(parent)
        self.discovery_plan = dict(discovery_plan or {})

    def run(self):
        hosts = [str(host or "").strip() for host in (self.discovery_plan.get("hosts") or []) if str(host or "").strip()]
        total = len(hosts)
        discovered = []
        completed = 0

        if total <= 0:
            self.progress.emit(0, 0)
            self.finished_scan.emit([])
            return

        with ThreadPoolExecutor(max_workers=SCAN_MAX_WORKERS) as executor:
            futures = {executor.submit(probe_client, host): host for host in hosts}
            for future in as_completed(futures):
                completed += 1
                if completed == 1 or completed == total or (completed % 12 == 0):
                    self.progress.emit(completed, total)
                try:
                    result = future.result()
                except Exception:
                    result = None
                if result:
                    discovered.append(result)

        discovered.sort(key=lambda item: host_sort_key(item.get("host")))
        self.progress.emit(total, total)
        self.finished_scan.emit(discovered)


class RefreshWorker(QThread):
    finished_refresh = pyqtSignal(object)

    def __init__(self, hosts, parent=None):
        super().__init__(parent)
        self.hosts = [str(host or "").strip() for host in (hosts or []) if str(host or "").strip()]

    def run(self):
        snapshots = []
        if not self.hosts:
            self.finished_refresh.emit([])
            return

        max_workers = min(REFRESH_MAX_WORKERS, max(1, len(self.hosts)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(fetch_client_snapshot, host): host for host in self.hosts}
            for future in as_completed(futures):
                try:
                    snapshot = future.result()
                except Exception as exc:
                    host = futures.get(future, "")
                    snapshot = {
                        "host": host,
                        "online": False,
                        "client_label": host,
                        "base_url": f"http://{host}:{CLIENT_API_PORT}",
                        "latency_ms": None,
                        "messages": [],
                        "qc_conversations": [],
                        "bad_word_items": [],
                        "endpoint_health": {},
                        "error": str(exc),
                        "last_refreshed_at": format_timestamp(now_local()),
                    }
                snapshots.append(snapshot)

        snapshots.sort(key=lambda item: host_sort_key(item.get("host")))
        self.finished_refresh.emit(snapshots)


class ConversationWorker(QThread):
    finished_messages = pyqtSignal(str, object)

    def __init__(self, host, contact_key, account_filter="", parent=None):
        super().__init__(parent)
        self.host = str(host or "").strip()
        self.contact_key = str(contact_key or "").strip()
        self.account_filter = str(account_filter or "").strip()

    def run(self):
        result = fetch_qc_conversation_messages(
            self.host,
            contact_key=self.contact_key,
            account_filter=self.account_filter,
        )
        self.finished_messages.emit(self.host, result)


class PreviewWorker(QThread):
    finished_preview = pyqtSignal(str, object)

    def __init__(self, host, parent=None):
        super().__init__(parent)
        self.host = str(host or "").strip()

    def run(self):
        result = fetch_live_view_frame(self.host, scope="tab")
        self.finished_preview.emit(self.host, result)


class MasterDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1680, 980)

        self.known_hosts = []
        self.client_snapshots = {}
        self.scan_thread = None
        self.refresh_thread = None
        self.conversation_thread = None
        self.preview_thread = None
        self.current_preview_host = ""
        self.current_scan_plan = {}
        self.api_image_bytes = b""
        self.current_api_image_host = ""
        self.current_conversation_host = ""
        self.current_conversation_key = ""

        self._build_ui()
        apply_windows_table_theme(self)

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.start_refresh)
        self.refresh_timer.start(AUTO_REFRESH_MS)

        self.scan_timer = QTimer(self)
        self.scan_timer.timeout.connect(self.start_scan)
        self.scan_timer.start(AUTO_RESCAN_MS)

        QTimer.singleShot(200, self.start_scan)

    def _build_ui(self):
        central = QWidget(self)
        root = QVBoxLayout(central)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        top_bar = QHBoxLayout()
        top_bar.setSpacing(8)

        self.rescan_btn = QPushButton("Rescan Network", self)
        self.rescan_btn.clicked.connect(self.start_scan)
        top_bar.addWidget(self.rescan_btn)

        self.refresh_btn = QPushButton("Refresh Now", self)
        self.refresh_btn.clicked.connect(self.start_refresh)
        top_bar.addWidget(self.refresh_btn)

        self.scan_progress = QProgressBar(self)
        self.scan_progress.setMaximumWidth(240)
        self.scan_progress.setTextVisible(True)
        self.scan_progress.setRange(0, 1)
        self.scan_progress.setValue(0)
        top_bar.addWidget(self.scan_progress)

        self.network_label = QLabel("Scan Sources: configured subnets + local LAN auto-detect + ARP neighbors", self)
        top_bar.addWidget(self.network_label, 1)

        self.status_label = QLabel("Idle", self)
        top_bar.addWidget(self.status_label)

        root.addLayout(top_bar)

        self.tabs = QTabWidget(self)
        root.addWidget(self.tabs, 1)

        self._build_overview_tab()
        self._build_clients_tab()
        self._build_messages_tab()
        self._build_qc_tab()
        self._build_api_tab()

        self.setCentralWidget(central)
        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Waiting for first network scan.")

    def _build_overview_tab(self):
        tab = QWidget(self)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        self.summary_table = QTableWidget(0, 3, self)
        prepare_table_widget(self.summary_table, ["Metric", "Value", "Notes"], stretch_last=True)
        self.summary_table.setMinimumHeight(210)
        self.summary_table.setColumnWidth(0, 180)
        self.summary_table.setColumnWidth(1, 180)
        layout.addWidget(self.summary_table)

        charts = QHBoxLayout()
        charts.setSpacing(8)

        self.client_bar_chart = GroupedBarChartWidget("Recent Sent vs Received by Client", self)
        charts.addWidget(self.client_bar_chart, 1)

        self.bad_word_line_chart = MultiLineChartWidget("Bad Word Events / Hits (Last 7 Days)", self)
        charts.addWidget(self.bad_word_line_chart, 1)

        layout.addLayout(charts)

        self.overview_client_table = QTableWidget(0, 12, self)
        prepare_table_widget(
            self.overview_client_table,
            [
                "Host", "Status", "Client Label", "Accounts", "Latency",
                "Templates", "Sent Today", "Received Today", "Failed Today",
                "QC Conv", "Bad Hits Today", "Last Activity"
            ],
            stretch_last=False,
        )
        self.overview_client_table.setColumnWidth(0, 120)
        self.overview_client_table.setColumnWidth(1, 85)
        self.overview_client_table.setColumnWidth(2, 220)
        self.overview_client_table.setColumnWidth(3, 220)
        self.overview_client_table.setColumnWidth(4, 90)
        self.overview_client_table.setColumnWidth(5, 80)
        self.overview_client_table.setColumnWidth(6, 90)
        self.overview_client_table.setColumnWidth(7, 105)
        self.overview_client_table.setColumnWidth(8, 90)
        self.overview_client_table.setColumnWidth(9, 80)
        self.overview_client_table.setColumnWidth(10, 110)
        self.overview_client_table.setColumnWidth(11, 150)
        self.overview_client_table.itemSelectionChanged.connect(self._sync_selected_client_from_overview)
        layout.addWidget(self.overview_client_table, 1)

        self.tabs.addTab(tab, "Overview")

    def _build_clients_tab(self):
        tab = QWidget(self)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)

        self.client_table = QTableWidget(0, 13, self)
        prepare_table_widget(
            self.client_table,
            [
                "Host", "Status", "Device", "Client Label", "Accounts",
                "Tabs", "Logged In", "Latency", "Stored Msg", "Recent Msg",
                "Unique Contacts", "Templates", "Last Refresh"
            ],
            stretch_last=False,
        )
        self.client_table.setColumnWidth(0, 120)
        self.client_table.setColumnWidth(1, 80)
        self.client_table.setColumnWidth(2, 210)
        self.client_table.setColumnWidth(3, 220)
        self.client_table.setColumnWidth(4, 220)
        self.client_table.setColumnWidth(5, 70)
        self.client_table.setColumnWidth(6, 80)
        self.client_table.setColumnWidth(7, 90)
        self.client_table.setColumnWidth(8, 90)
        self.client_table.setColumnWidth(9, 90)
        self.client_table.setColumnWidth(10, 110)
        self.client_table.setColumnWidth(11, 85)
        self.client_table.setColumnWidth(12, 150)
        self.client_table.itemSelectionChanged.connect(self.update_selected_client_detail)
        splitter.addWidget(self.client_table)

        right = QWidget(self)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        self.client_detail_table = QTableWidget(0, 3, self)
        prepare_table_widget(self.client_detail_table, ["Metric", "Value", "Notes"], stretch_last=True)
        self.client_detail_table.setMinimumHeight(210)
        self.client_detail_table.setColumnWidth(0, 170)
        self.client_detail_table.setColumnWidth(1, 220)
        right_layout.addWidget(self.client_detail_table)

        self.endpoint_table = QTableWidget(0, 5, self)
        prepare_table_widget(self.endpoint_table, ["Endpoint", "State", "HTTP", "Latency", "Error"], stretch_last=True)
        self.endpoint_table.setMinimumHeight(220)
        self.endpoint_table.setColumnWidth(0, 180)
        self.endpoint_table.setColumnWidth(1, 80)
        self.endpoint_table.setColumnWidth(2, 70)
        self.endpoint_table.setColumnWidth(3, 90)
        right_layout.addWidget(self.endpoint_table)

        preview_tools = QHBoxLayout()
        self.preview_title = QLabel("Selected Client Preview", self)
        preview_tools.addWidget(self.preview_title, 1)

        self.preview_refresh_btn = QPushButton("Refresh Preview", self)
        self.preview_refresh_btn.clicked.connect(self.refresh_selected_preview)
        preview_tools.addWidget(self.preview_refresh_btn)
        right_layout.addLayout(preview_tools)

        self.preview_label = QLabel("No preview loaded.", self)
        self.preview_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview_label.setMinimumHeight(280)
        self.preview_label.setStyleSheet("background:#ffffff;border:1px solid #8fa9d4;")
        right_layout.addWidget(self.preview_label)

        popup_panel = QWidget(self)
        popup_layout = QVBoxLayout(popup_panel)
        popup_layout.setContentsMargins(0, 0, 0, 0)
        popup_layout.setSpacing(6)

        popup_title = QLabel("Client Notice", self)
        popup_title.setStyleSheet("font-weight:600;")
        popup_layout.addWidget(popup_title)

        popup_form = QFormLayout()
        popup_form.setContentsMargins(0, 0, 0, 0)
        popup_form.setHorizontalSpacing(8)
        popup_form.setVerticalSpacing(6)

        self.client_popup_level_combo = QComboBox(self)
        self.client_popup_level_combo.addItems(["warning", "info", "error", "success"])
        popup_form.addRow("Level:", self.client_popup_level_combo)

        self.client_popup_title_edit = QLineEdit(self)
        self.client_popup_title_edit.setText("Notice from Master Dashboard")
        popup_form.addRow("Title:", self.client_popup_title_edit)

        self.client_popup_duration_edit = QLineEdit(self)
        self.client_popup_duration_edit.setPlaceholderText("0 = sticky until closed")
        self.client_popup_duration_edit.setText("0")
        popup_form.addRow("Duration (s):", self.client_popup_duration_edit)

        self.client_popup_message_edit = QPlainTextEdit(self)
        self.client_popup_message_edit.setPlaceholderText("Write the notice or warning to show on the selected client...")
        self.client_popup_message_edit.setMaximumHeight(110)
        popup_form.addRow("Message:", self.client_popup_message_edit)
        popup_layout.addLayout(popup_form)

        popup_actions = QHBoxLayout()
        self.client_popup_status_label = QLabel("Send a popup notice to the selected client.", self)
        popup_actions.addWidget(self.client_popup_status_label, 1)
        self.client_popup_send_btn = QPushButton("Send Popup", self)
        self.client_popup_send_btn.clicked.connect(self.send_popup_to_selected_client)
        popup_actions.addWidget(self.client_popup_send_btn)
        popup_layout.addLayout(popup_actions)

        right_layout.addWidget(popup_panel)

        self.client_recent_table = QTableWidget(0, 6, self)
        prepare_table_widget(self.client_recent_table, ["Timestamp", "Direction", "Account", "Contact", "Preview", "Status"], stretch_last=True)
        self.client_recent_table.setColumnWidth(0, 150)
        self.client_recent_table.setColumnWidth(1, 90)
        self.client_recent_table.setColumnWidth(2, 180)
        self.client_recent_table.setColumnWidth(3, 180)
        self.client_recent_table.setColumnWidth(5, 90)
        right_layout.addWidget(self.client_recent_table, 1)

        splitter.addWidget(right)
        splitter.setSizes([760, 880])
        layout.addWidget(splitter, 1)

        self.tabs.addTab(tab, "Clients")

    def _build_messages_tab(self):
        tab = QWidget(self)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        filters = QHBoxLayout()
        filters.setSpacing(8)
        filters.addWidget(QLabel("Client:", self))
        self.message_client_filter = QComboBox(self)
        self.message_client_filter.currentIndexChanged.connect(self.render_messages_tab)
        filters.addWidget(self.message_client_filter)

        filters.addWidget(QLabel("Direction:", self))
        self.message_direction_filter = QComboBox(self)
        self.message_direction_filter.addItems(["All", "Outgoing", "Incoming", "Failed"])
        self.message_direction_filter.currentIndexChanged.connect(self.render_messages_tab)
        filters.addWidget(self.message_direction_filter)

        filters.addWidget(QLabel("Search:", self))
        self.message_search_edit = QLineEdit(self)
        self.message_search_edit.setPlaceholderText("Client, account, contact, preview...")
        self.message_search_edit.textChanged.connect(self.render_messages_tab)
        filters.addWidget(self.message_search_edit, 1)

        layout.addLayout(filters)

        self.message_activity_chart = MultiLineChartWidget("Recent Activity (Last 24 Hours)", self)
        layout.addWidget(self.message_activity_chart)

        splitter = QSplitter(Qt.Orientation.Vertical, self)

        self.message_table = QTableWidget(0, 9, self)
        prepare_table_widget(
            self.message_table,
            ["Timestamp", "Client", "Account", "Direction", "Contact", "Preview", "Status", "Send Type", "Bad Words"],
            stretch_last=False,
        )
        self.message_table.setColumnWidth(0, 150)
        self.message_table.setColumnWidth(1, 140)
        self.message_table.setColumnWidth(2, 220)
        self.message_table.setColumnWidth(3, 90)
        self.message_table.setColumnWidth(4, 180)
        self.message_table.setColumnWidth(5, 360)
        self.message_table.setColumnWidth(6, 90)
        self.message_table.setColumnWidth(7, 110)
        self.message_table.setColumnWidth(8, 90)
        self.message_table.itemSelectionChanged.connect(self.update_message_detail)
        splitter.addWidget(self.message_table)

        self.message_detail = QPlainTextEdit(self)
        self.message_detail.setReadOnly(True)
        splitter.addWidget(self.message_detail)
        splitter.setSizes([560, 180])

        layout.addWidget(splitter, 1)
        self.tabs.addTab(tab, "Messages")

    def _build_qc_tab(self):
        tab = QWidget(self)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        filters = QHBoxLayout()
        filters.setSpacing(8)
        filters.addWidget(QLabel("Client:", self))
        self.qc_client_filter = QComboBox(self)
        self.qc_client_filter.currentIndexChanged.connect(self.render_qc_tab)
        filters.addWidget(self.qc_client_filter)

        filters.addWidget(QLabel("Search:", self))
        self.qc_search_edit = QLineEdit(self)
        self.qc_search_edit.setPlaceholderText("Contact, phone, account...")
        self.qc_search_edit.textChanged.connect(self.render_qc_tab)
        filters.addWidget(self.qc_search_edit, 1)

        layout.addLayout(filters)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)

        self.qc_conversation_table = QTableWidget(0, 8, self)
        prepare_table_widget(
            self.qc_conversation_table,
            ["Client", "Contact", "Phone", "Accounts", "Sent", "Received", "Total", "Last Message"],
            stretch_last=False,
        )
        self.qc_conversation_table.setColumnWidth(0, 140)
        self.qc_conversation_table.setColumnWidth(1, 220)
        self.qc_conversation_table.setColumnWidth(2, 150)
        self.qc_conversation_table.setColumnWidth(3, 220)
        self.qc_conversation_table.setColumnWidth(4, 70)
        self.qc_conversation_table.setColumnWidth(5, 80)
        self.qc_conversation_table.setColumnWidth(6, 70)
        self.qc_conversation_table.setColumnWidth(7, 150)
        self.qc_conversation_table.itemSelectionChanged.connect(self.load_selected_qc_conversation)
        splitter.addWidget(self.qc_conversation_table)

        right = QSplitter(Qt.Orientation.Vertical, self)

        self.qc_message_table = QTableWidget(0, 8, self)
        prepare_table_widget(
            self.qc_message_table,
            ["Timestamp", "Direction", "From", "To", "Preview", "Status", "Trigger", "Bad Words"],
            stretch_last=False,
        )
        self.qc_message_table.setColumnWidth(0, 150)
        self.qc_message_table.setColumnWidth(1, 90)
        self.qc_message_table.setColumnWidth(2, 180)
        self.qc_message_table.setColumnWidth(3, 180)
        self.qc_message_table.setColumnWidth(4, 320)
        self.qc_message_table.setColumnWidth(5, 90)
        self.qc_message_table.setColumnWidth(6, 110)
        self.qc_message_table.setColumnWidth(7, 90)
        self.qc_message_table.itemSelectionChanged.connect(self.update_qc_message_detail)
        right.addWidget(self.qc_message_table)

        self.qc_detail = QPlainTextEdit(self)
        self.qc_detail.setReadOnly(True)
        right.addWidget(self.qc_detail)
        right.setSizes([520, 180])

        splitter.addWidget(right)
        splitter.setSizes([700, 880])
        layout.addWidget(splitter, 1)

        self.tabs.addTab(tab, "QC Conversations")

    def _build_api_tab(self):
        tab = QWidget(self)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        top = QHBoxLayout()
        top.addWidget(QLabel("Client:", self))
        self.api_client_combo = QComboBox(self)
        self.api_client_combo.currentIndexChanged.connect(self.render_api_tab)
        top.addWidget(self.api_client_combo)

        top.addWidget(QLabel("Query:", self))
        self.api_query_edit = QLineEdit(self)
        self.api_query_edit.setPlaceholderText("Optional query string, e.g. page=1&pageSize=20")
        top.addWidget(self.api_query_edit, 1)

        self.api_fetch_btn = QPushButton("Fetch Selected", self)
        self.api_fetch_btn.clicked.connect(self.fetch_selected_api_endpoint)
        top.addWidget(self.api_fetch_btn)
        layout.addLayout(top)

        self.api_body_edit = QPlainTextEdit(self)
        self.api_body_edit.setPlaceholderText("Optional JSON body for POST endpoints.")
        self.api_body_edit.setMaximumHeight(120)
        layout.addWidget(self.api_body_edit)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)

        self.api_table = QTableWidget(0, 5, self)
        prepare_table_widget(self.api_table, ["Method", "Path", "Description", "State", "Latency"], stretch_last=False)
        self.api_table.setColumnWidth(0, 80)
        self.api_table.setColumnWidth(1, 250)
        self.api_table.setColumnWidth(2, 360)
        self.api_table.setColumnWidth(3, 80)
        self.api_table.setColumnWidth(4, 90)
        self.api_table.itemSelectionChanged.connect(self.on_api_endpoint_selected)
        splitter.addWidget(self.api_table)

        right_panel = QWidget(self)
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        self.api_response = QPlainTextEdit(right_panel)
        self.api_response.setReadOnly(True)
        right_layout.addWidget(self.api_response, 1)

        self.api_image_label = QLabel("Image responses will appear here.", right_panel)
        self.api_image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.api_image_label.setMinimumHeight(260)
        self.api_image_label.setStyleSheet("background:#ffffff;border:1px solid #8fa9d4;")
        right_layout.addWidget(self.api_image_label, 1)

        splitter.addWidget(right_panel)

        splitter.setSizes([820, 780])
        layout.addWidget(splitter, 1)

        self.tabs.addTab(tab, "API Explorer")

    def clear_api_image_preview(self, text="Image responses will appear here."):
        self.api_image_bytes = b""
        if hasattr(self, "api_image_label"):
            self.api_image_label.setPixmap(QPixmap())
            self.api_image_label.setText(str(text or "Image responses will appear here."))

    def set_api_image_preview(self, image_bytes, host=""):
        raw = bytes(image_bytes or b"")
        if not raw:
            self.clear_api_image_preview("No image response returned.")
            return False

        pixmap = QPixmap()
        if not pixmap.loadFromData(raw):
            self.clear_api_image_preview("Image response could not be decoded.")
            return False

        self.api_image_bytes = raw
        self.current_api_image_host = str(host or "").strip()
        target_width = max(1, self.api_image_label.width() - 12)
        target_height = max(1, self.api_image_label.height() - 12)
        scaled = pixmap.scaled(
            target_width,
            target_height,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.api_image_label.setPixmap(scaled)
        self.api_image_label.setText("")
        return True

    def update_endpoint_health_for_path(self, host, path, result):
        host = str(host or "").strip()
        if not host:
            return

        snapshot = dict(self.client_snapshots.get(host) or {})
        endpoint_health = dict(snapshot.get("endpoint_health") or {})
        endpoint_health[self.map_endpoint_path_to_health_key(path)] = {
            "name": str(path or "").strip() or "API",
            "ok": bool(result.get("ok")),
            "status": safe_int(result.get("status"), 0, 0),
            "latency_ms": result.get("latency_ms"),
            "error": str(result.get("error") or "").strip(),
            "count": 0,
        }
        snapshot["host"] = host
        snapshot["client_label"] = str(snapshot.get("client_label") or host)
        snapshot["endpoint_health"] = endpoint_health
        self.client_snapshots[host] = snapshot

    def update_api_table_row_state(self, row_index, result):
        if row_index < 0:
            return

        state = "OK" if result.get("ok") else "FAIL"
        latency_text = format_latency(result.get("latency_ms"))

        state_item = make_table_item(state)
        if state == "OK":
            state_item.setBackground(QColor("#d1e7dd"))
            state_item.setForeground(QColor("#0f5132"))
        else:
            state_item.setBackground(QColor("#f8d7da"))
            state_item.setForeground(QColor("#842029"))

        self.api_table.setItem(row_index, 3, state_item)
        self.api_table.setItem(row_index, 4, make_table_item(latency_text))

    def start_scan(self):
        if self.scan_thread is not None and self.scan_thread.isRunning():
            return

        self.current_scan_plan = build_discovery_plan(FLOOR_SUBNETS)
        host_count = len(self.current_scan_plan.get("hosts") or [])
        subnet_count = len(self.current_scan_plan.get("subnets") or [])
        arp_count = len(self.current_scan_plan.get("arp_hosts") or [])

        self.status_label.setText("Scanning LAN...")
        self.network_label.setText(describe_discovery_plan(self.current_scan_plan))
        self.status_bar.showMessage(
            f"Scanning {host_count} host(s) across {subnet_count} subnet(s) with {arp_count} ARP neighbor candidate(s)..."
        )
        self.scan_progress.setRange(0, 100)
        self.scan_progress.setValue(0)

        self.scan_thread = DiscoveryWorker(self.current_scan_plan, self)
        self.scan_thread.progress.connect(self.on_scan_progress)
        self.scan_thread.finished_scan.connect(self.on_scan_finished)
        self.scan_thread.start()

    def on_scan_progress(self, done, total):
        if total <= 0:
            self.scan_progress.setRange(0, 1)
            self.scan_progress.setValue(0)
            return
        self.scan_progress.setRange(0, total)
        self.scan_progress.setValue(done)

    def on_scan_finished(self, discovered):
        discovered = list(discovered or [])
        live_hosts = [str(item.get("host") or "").strip() for item in discovered if str(item.get("host") or "").strip()]
        self.known_hosts = sorted(set(self.known_hosts).union(live_hosts), key=host_sort_key)

        current_live_set = set(live_hosts)
        for host in list(self.client_snapshots.keys()):
            if host not in current_live_set:
                snapshot = dict(self.client_snapshots.get(host) or {})
                snapshot["online"] = False
                snapshot["error"] = "Not found in latest scan"
                snapshot["last_refreshed_at"] = format_timestamp(now_local())
                self.client_snapshots[host] = snapshot

        self.status_label.setText(f"Scan complete: {len(live_hosts)} online")
        self.status_bar.showMessage(
            f"Discovered {len(live_hosts)} live client(s) from {len(self.current_scan_plan.get('hosts') or [])} scanned target(s)."
        )
        self.start_refresh(hosts=live_hosts)

    def start_refresh(self, hosts=None):
        if self.refresh_thread is not None and self.refresh_thread.isRunning():
            return

        target_hosts = [str(x or "").strip() for x in (hosts or self.known_hosts) if str(x or "").strip()]
        if not target_hosts:
            self.render_all()
            return

        self.status_label.setText("Refreshing clients...")
        self.status_bar.showMessage(f"Refreshing {len(target_hosts)} client(s)...")

        self.refresh_thread = RefreshWorker(target_hosts, self)
        self.refresh_thread.finished_refresh.connect(self.on_refresh_finished)
        self.refresh_thread.start()

    def on_refresh_finished(self, snapshots):
        for snapshot in list(snapshots or []):
            host = str(snapshot.get("host") or "").strip()
            if not host:
                continue
            self.client_snapshots[host] = snapshot
            if host not in self.known_hosts:
                self.known_hosts.append(host)

        self.known_hosts = sorted(set(self.known_hosts), key=host_sort_key)
        online_count = sum(1 for host in self.known_hosts if bool(self.client_snapshots.get(host, {}).get("online")))
        self.status_label.setText(f"Online: {online_count}/{len(self.known_hosts)}")
        self.status_bar.showMessage(f"Refresh completed. {online_count}/{len(self.known_hosts)} client(s) online.")
        self.render_all()

    def get_sorted_snapshots(self):
        items = []
        for host in self.known_hosts:
            snapshot = dict(self.client_snapshots.get(host) or {})
            if not snapshot:
                snapshot = {
                    "host": host,
                    "client_label": host,
                    "online": False,
                    "messages": [],
                    "qc_conversations": [],
                    "bad_word_items": [],
                    "endpoint_health": {},
                    "error": "Waiting for refresh",
                }
            items.append(snapshot)
        items.sort(key=lambda item: host_sort_key(item.get("host")))
        return items

    def render_all(self):
        self.populate_client_filter_combos()
        self.render_overview()
        self.render_clients_tab()
        self.render_messages_tab()
        self.render_qc_tab()
        self.render_api_tab()

    def populate_client_filter_combos(self):
        current_msg = self.message_client_filter.currentData()
        current_qc = self.qc_client_filter.currentData()
        current_api = self.api_client_combo.currentData()

        options = [("", "All Clients")]
        for snapshot in self.get_sorted_snapshots():
            host = str(snapshot.get("host") or "").strip()
            label = str(snapshot.get("client_label") or host).strip()
            options.append((host, f"{label} ({host})"))

        for combo, previous in (
            (self.message_client_filter, current_msg),
            (self.qc_client_filter, current_qc),
            (self.api_client_combo, current_api),
        ):
            combo.blockSignals(True)
            combo.clear()
            for value, label in options:
                combo.addItem(label, value)
            index = combo.findData(previous)
            combo.setCurrentIndex(index if index >= 0 else 0)
            combo.blockSignals(False)

    def render_overview(self):
        snapshots = self.get_sorted_snapshots()
        online_clients = [snap for snap in snapshots if snap.get("online")]
        total_clients = len(snapshots)
        online_count = len(online_clients)
        total_templates = sum(safe_int(snap.get("templates_total"), 0, 0) for snap in online_clients)
        total_today_sent = sum(safe_int(snap.get("today_sent"), 0, 0) for snap in online_clients)
        total_today_received = sum(safe_int(snap.get("today_received"), 0, 0) for snap in online_clients)
        total_today_failed = sum(safe_int(snap.get("today_failed"), 0, 0) for snap in online_clients)
        total_qc = sum(safe_int(snap.get("qc_conversation_total"), 0, 0) for snap in online_clients)
        total_bad_hits = sum(safe_int(snap.get("bad_word_hits_today"), 0, 0) for snap in online_clients)
        total_stored_messages = sum(safe_int(snap.get("message_total"), 0, 0) for snap in online_clients)

        summary_rows = [
            ("Clients Online", f"{online_count} / {total_clients}", "Live clients currently reachable on the configured and auto-detected LAN ranges."),
            ("Stored Messages", str(total_stored_messages), "Total stored WhatsApp history rows reported by online clients."),
            ("Today Sent", str(total_today_sent), "Recent loaded history rows from today marked as outgoing."),
            ("Today Received", str(total_today_received), "Recent loaded history rows from today marked as incoming."),
            ("Today Failed", str(total_today_failed), "Recent loaded history rows from today marked as failed."),
            ("Templates", str(total_templates), "Saved template count summed from online clients."),
            ("QC Conversations", str(total_qc), "Total grouped conversation summaries across online clients."),
            ("Bad Hits Today", str(total_bad_hits), "Bad-word hits reported for today across online clients."),
        ]

        self.summary_table.setRowCount(len(summary_rows))
        for row_index, (metric, value, notes) in enumerate(summary_rows):
            self.summary_table.setItem(row_index, 0, make_table_item(metric))
            self.summary_table.setItem(row_index, 1, make_table_item(value))
            self.summary_table.setItem(row_index, 2, make_table_item(notes))
        if self.summary_table.rowCount() > 0:
            select_first_row(self.summary_table)

        self.populate_overview_client_table(snapshots)

        bar_labels = [client_chart_label(snap) for snap in online_clients[:12]]
        sent_values = [safe_int(snap.get("today_sent"), 0, 0) for snap in online_clients[:12]]
        received_values = [safe_int(snap.get("today_received"), 0, 0) for snap in online_clients[:12]]
        self.client_bar_chart.set_chart_data(
            bar_labels,
            [
                {"name": "Sent", "values": sent_values, "color": "#2b5fd9"},
                {"name": "Received", "values": received_values, "color": "#17a673"},
            ],
        )

        labels = [iso_day_offset(offset)[5:] for offset in range(6, -1, -1)]
        events = [0] * len(labels)
        hits = [0] * len(labels)
        for snap in online_clients:
            event_series = list(snap.get("bad_word_event_series") or [])
            hit_series = list(snap.get("bad_word_hit_series") or [])
            for idx in range(min(len(labels), len(event_series))):
                events[idx] += safe_int(event_series[idx], 0, 0)
            for idx in range(min(len(labels), len(hit_series))):
                hits[idx] += safe_int(hit_series[idx], 0, 0)
        self.bad_word_line_chart.set_chart_data(
            labels,
            [
                {"name": "Events", "values": events, "color": "#c77d00"},
                {"name": "Hits", "values": hits, "color": "#d9485f"},
            ],
        )

    def populate_overview_client_table(self, snapshots):
        self.overview_client_table.setRowCount(len(snapshots))
        for row_index, snap in enumerate(snapshots):
            host = str(snap.get("host") or "")
            online = bool(snap.get("online"))
            values = [
                host,
                "ONLINE" if online else "OFFLINE",
                str(snap.get("client_label") or host),
                str(snap.get("active_accounts_text") or "-"),
                format_latency(snap.get("latency_ms")),
                str(safe_int(snap.get("templates_total"), 0, 0)),
                str(safe_int(snap.get("today_sent"), 0, 0)),
                str(safe_int(snap.get("today_received"), 0, 0)),
                str(safe_int(snap.get("today_failed"), 0, 0)),
                str(safe_int(snap.get("qc_conversation_total"), 0, 0)),
                str(safe_int(snap.get("bad_word_hits_today"), 0, 0)),
                str(snap.get("last_activity_text") or "-"),
            ]
            for col, value in enumerate(values):
                align = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter if col in {5, 6, 7, 8, 9, 10} else None
                item = make_table_item(value, user_data=host if col == 0 else None, align=align)
                if col == 1:
                    if online:
                        item.setBackground(QColor("#d1e7dd"))
                        item.setForeground(QColor("#0f5132"))
                    else:
                        item.setBackground(QColor("#f8d7da"))
                        item.setForeground(QColor("#842029"))
                self.overview_client_table.setItem(row_index, col, item)
        if self.overview_client_table.rowCount() > 0:
            select_first_row(self.overview_client_table)

    def render_clients_tab(self):
        snapshots = self.get_sorted_snapshots()
        self.client_table.setRowCount(len(snapshots))
        for row_index, snap in enumerate(snapshots):
            host = str(snap.get("host") or "")
            online = bool(snap.get("online"))
            values = [
                host,
                "ONLINE" if online else "OFFLINE",
                str(snap.get("device_name") or snap.get("hostname_text") or host),
                str(snap.get("client_label") or host),
                str(snap.get("active_accounts_text") or "-"),
                str(safe_int(snap.get("tabs_total"), 0, 0)),
                str(safe_int(snap.get("logged_in_tabs"), 0, 0)),
                format_latency(snap.get("latency_ms")),
                str(safe_int(snap.get("message_total"), 0, 0)),
                str(safe_int(snap.get("messages_loaded"), 0, 0)),
                str(safe_int(snap.get("unique_contacts"), 0, 0)),
                str(safe_int(snap.get("templates_total"), 0, 0)),
                str(snap.get("last_refreshed_at") or "-"),
            ]
            for col, value in enumerate(values):
                align = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter if col in {5, 6, 7, 8, 9, 10, 11} else None
                item = make_table_item(value, user_data=host if col == 0 else None, align=align)
                if col == 1:
                    if online:
                        item.setBackground(QColor("#d1e7dd"))
                        item.setForeground(QColor("#0f5132"))
                    else:
                        item.setBackground(QColor("#f8d7da"))
                        item.setForeground(QColor("#842029"))
                self.client_table.setItem(row_index, col, item)
        if self.client_table.rowCount() > 0 and self.client_table.currentRow() < 0:
            select_first_row(self.client_table)
        self.update_selected_client_detail()

    def get_selected_client_host(self, preferred_table=None):
        tables = []
        if preferred_table is not None:
            tables.append(preferred_table)
        tables.extend([self.client_table, self.overview_client_table])
        for table in tables:
            row = table.currentRow()
            if row < 0:
                continue
            item = table.item(row, 0)
            if item is None:
                continue
            host = str(item.data(Qt.ItemDataRole.UserRole) or item.text() or "").strip()
            if host:
                return host
        return ""

    def _sync_selected_client_from_overview(self):
        host = self.get_selected_client_host(self.overview_client_table)
        if not host:
            return
        row = self.find_row_by_host(self.client_table, host)
        if row >= 0:
            self.client_table.blockSignals(True)
            self.client_table.setCurrentCell(row, 0)
            self.client_table.selectRow(row)
            self.client_table.blockSignals(False)
        self.update_selected_client_detail()

    def find_row_by_host(self, table, host):
        host = str(host or "").strip()
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item is None:
                continue
            candidate = str(item.data(Qt.ItemDataRole.UserRole) or item.text() or "").strip()
            if candidate == host:
                return row
        return -1

    def update_selected_client_detail(self):
        host = self.get_selected_client_host(self.client_table)
        snapshot = dict(self.client_snapshots.get(host) or {})
        client_info = dict(snapshot.get("client_info") or {})
        tab_stats = dict(snapshot.get("tab_stats") or {})

        local_ips = ", ".join(list(client_info.get("local_ips") or [])) or "-"
        touched_tabs = list(tab_stats.get("touched_tabs") or [])
        untouched_tabs = list(tab_stats.get("untouched_tabs") or [])
        touched_note = "Used today: " + (", ".join(touched_tabs[:4]) if touched_tabs else "-")
        if len(touched_tabs) > 4:
            touched_note += f" +{len(touched_tabs) - 4} more"

        detail_rows = [
            ("Host", host or "-", "Client IP and API port target."),
            ("Device", str(snapshot.get("device_name") or client_info.get("device_name") or "-"), "Device-friendly name reported by the client."),
            ("MAC Address", str(snapshot.get("mac_address") or client_info.get("mac_address") or "-"), "Primary MAC-style identifier reported by the client."),
            ("Hostname / User", f"{client_info.get('hostname') or '-'} / {client_info.get('username') or '-'}", "Host and local OS account used by the client app."),
            ("Platform", str(snapshot.get("platform_summary") or client_info.get("platform") or "-"), str(client_info.get("machine") or snapshot.get("machine") or "-")),
            ("Local IPs", local_ips, "Private IPv4 addresses detected on the client machine."),
            ("Client Label", str(snapshot.get("client_label") or "-"), "Derived from recent active WhatsApp accounts on that client."),
            ("Status", "ONLINE" if snapshot.get("online") else "OFFLINE", str(snapshot.get("error") or "Client responded normally.") or "-"),
            ("Accounts", str(snapshot.get("active_accounts_text") or "-"), "Active account labels seen in the recent loaded history."),
            ("Open Tabs", str(safe_int(snapshot.get("tabs_total"), 0, 0)), f"WhatsApp tabs: {safe_int(snapshot.get('open_whatsapp_tabs'), 0, 0)}"),
            ("Logged In WA Tabs", str(safe_int(snapshot.get("logged_in_tabs"), 0, 0)), "WhatsApp tabs that appear signed in and ready."),
            ("Touched / Idle Tabs", f"{safe_int(snapshot.get('touched_tab_count'), 0, 0)} / {safe_int(snapshot.get('untouched_tab_count'), 0, 0)}", touched_note),
            ("Current Tab", str(snapshot.get("current_tab_name") or tab_stats.get("current_tab") or client_info.get("current_tab") or "-"), shorten_text(client_info.get("current_url") or "-", 120)),
            ("Stored Messages", str(safe_int(snapshot.get("message_total"), 0, 0)), "Total history rows reported by the client API."),
            ("Recent Loaded", str(safe_int(snapshot.get("messages_loaded"), 0, 0)), "Recent history rows loaded into the master dashboard sample."),
            ("Unique Contacts", str(safe_int(snapshot.get("unique_contacts"), 0, 0)), "Unique recent contacts seen in the loaded message sample."),
            ("Templates", str(safe_int(snapshot.get("templates_total"), 0, 0)), "Total templates reported by the client."),
            ("QC Conversations", str(safe_int(snapshot.get("qc_conversation_total"), 0, 0)), "Grouped conversation summaries on the client."),
            ("Last Activity", str(snapshot.get("last_activity_text") or "-"), shorten_text(snapshot.get("last_preview") or "No recent preview.", 120)),
        ]

        self.client_detail_table.setRowCount(len(detail_rows))
        for row_index, (metric, value, notes) in enumerate(detail_rows):
            self.client_detail_table.setItem(row_index, 0, make_table_item(metric))
            self.client_detail_table.setItem(row_index, 1, make_table_item(value))
            self.client_detail_table.setItem(row_index, 2, make_table_item(notes))
        if self.client_detail_table.rowCount() > 0:
            select_first_row(self.client_detail_table)

        endpoint_rows = []
        endpoint_health = dict(snapshot.get("endpoint_health") or {})
        for key in ("client_info", "tab_stats", "templates", "messages", "qc_conversations", "bad_words", "live_view", "popup_message"):
            info = dict(endpoint_health.get(key) or {})
            if info:
                state = "OK" if info.get("ok") else "FAIL"
                http_text = str(info.get("status") or "-")
                latency_text = format_latency(info.get("latency_ms"))
                error_text = str(info.get("error") or "-")
            else:
                state = "N/A"
                http_text = "-"
                latency_text = "-"
                error_text = "-"
            endpoint_rows.append(
                (
                    str(info.get("name") or key),
                    state,
                    http_text,
                    latency_text,
                    error_text,
                )
            )

        self.endpoint_table.setRowCount(len(endpoint_rows))
        for row_index, values in enumerate(endpoint_rows):
            for col, value in enumerate(values):
                item = make_table_item(value)
                if col == 1:
                    if value == "OK":
                        item.setBackground(QColor("#d1e7dd"))
                        item.setForeground(QColor("#0f5132"))
                    else:
                        item.setBackground(QColor("#f8d7da"))
                        item.setForeground(QColor("#842029"))
                self.endpoint_table.setItem(row_index, col, item)
        if self.endpoint_table.rowCount() > 0:
            select_first_row(self.endpoint_table)

        recent_rows = list(snapshot.get("messages") or [])[:15]
        self.client_recent_table.setRowCount(len(recent_rows))
        for row_index, row in enumerate(recent_rows):
            values = [
                row.get("timestamp_display") or "-",
                str(row.get("direction") or "").upper(),
                row.get("account") or "-",
                row.get("contact") or "-",
                row.get("preview") or "",
                str(row.get("status") or "-").upper(),
            ]
            for col, value in enumerate(values):
                self.client_recent_table.setItem(row_index, col, make_table_item(value))
        if self.client_recent_table.rowCount() > 0:
            select_first_row(self.client_recent_table)

        if host and host != self.current_preview_host:
            self.preview_label.setText("Preview not loaded yet.\nClick Refresh Preview to fetch the current screen.")
            self.preview_label.setPixmap(QPixmap())
            self.current_preview_host = host
        if host:
            self.client_popup_status_label.setText(f"Ready to send popup to {snapshot.get('device_name') or host}.")
        else:
            self.client_popup_status_label.setText("Send a popup notice to the selected client.")

    def refresh_selected_preview(self):
        host = self.get_selected_client_host(self.client_table)
        if not host:
            QMessageBox.information(self, "Preview", "Select a client first.")
            return
        if self.preview_thread is not None and self.preview_thread.isRunning():
            return
        self.preview_label.setText("Loading preview...")
        self.preview_label.setPixmap(QPixmap())
        self.preview_thread = PreviewWorker(host, self)
        self.preview_thread.finished_preview.connect(self.on_preview_loaded)
        self.preview_thread.start()

    def on_preview_loaded(self, host, result):
        endpoint_health = dict(self.client_snapshots.get(host, {}).get("endpoint_health") or {})
        endpoint_health["live_view"] = {
            "name": "Live View",
            "ok": bool(result.get("ok")),
            "status": safe_int(result.get("status"), 0, 0),
            "latency_ms": result.get("latency_ms"),
            "error": str(result.get("error") or ""),
            "count": 0,
        }
        if host in self.client_snapshots:
            self.client_snapshots[host]["endpoint_health"] = endpoint_health

        if host != self.current_preview_host:
            return

        if not result.get("ok"):
            self.preview_label.setText(f"Preview failed:\n{result.get('error') or 'Unknown error'}")
            self.preview_label.setPixmap(QPixmap())
            self.update_selected_client_detail()
            return

        pixmap = QPixmap()
        if not pixmap.loadFromData(result.get("image_bytes") or b"", "JPG"):
            self.preview_label.setText("Preview frame could not be decoded.")
            self.preview_label.setPixmap(QPixmap())
            self.update_selected_client_detail()
            return

        scaled = pixmap.scaled(
            self.preview_label.size(),
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.preview_label.setPixmap(scaled)
        self.preview_label.setText("")
        self.update_selected_client_detail()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.preview_label.pixmap() is not None and not self.preview_label.pixmap().isNull():
            host = self.get_selected_client_host(self.client_table)
            if host:
                QTimer.singleShot(0, self.refresh_selected_preview)
        if self.api_image_bytes:
            QTimer.singleShot(0, lambda: self.set_api_image_preview(self.api_image_bytes, host=self.current_api_image_host))

    def get_filtered_messages(self):
        client_filter = str(self.message_client_filter.currentData() or "").strip()
        direction_filter = str(self.message_direction_filter.currentText() or "All").strip().lower()
        query_text = str(self.message_search_edit.text() or "").strip().lower()

        rows = []
        for snapshot in self.get_sorted_snapshots():
            host = str(snapshot.get("host") or "").strip()
            if client_filter and host != client_filter:
                continue
            client_label = str(snapshot.get("client_label") or host)
            for row in list(snapshot.get("messages") or []):
                enriched = dict(row)
                enriched["client_label"] = client_label
                rows.append(enriched)

        filtered = []
        for row in rows:
            status = str(row.get("status") or "").strip().lower()
            direction = str(row.get("direction") or "").strip().lower()
            if direction_filter == "outgoing" and direction != "outgoing":
                continue
            if direction_filter == "incoming" and direction != "incoming":
                continue
            if direction_filter == "failed" and status != "failed":
                continue
            if query_text:
                haystacks = [
                    str(row.get("host") or "").lower(),
                    str(row.get("client_label") or "").lower(),
                    str(row.get("account") or "").lower(),
                    str(row.get("contact") or "").lower(),
                    str(row.get("preview") or "").lower(),
                    str(row.get("send_type") or "").lower(),
                ]
                if not any(query_text in hay for hay in haystacks if hay):
                    continue
            filtered.append(row)

        filtered.sort(
            key=lambda row: (
                row.get("timestamp_dt") or datetime.datetime.min,
                -safe_int(row.get("index"), 0)
            ),
            reverse=True
        )
        return filtered[:MAX_VISIBLE_MESSAGES]

    def render_messages_tab(self):
        rows = self.get_filtered_messages()

        self.message_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            values = [
                row.get("timestamp_display") or "-",
                str(row.get("client_label") or row.get("host") or ""),
                row.get("account") or "-",
                str(row.get("direction") or "").upper(),
                row.get("contact") or "-",
                row.get("preview") or "",
                str(row.get("status") or "-").upper(),
                row.get("send_type") or "-",
                str(safe_int(row.get("bad_word_count"), 0, 0)),
            ]
            for col, value in enumerate(values):
                user_data = row if col == 0 else None
                self.message_table.setItem(row_index, col, make_table_item(value, user_data=user_data))
        if self.message_table.rowCount() > 0:
            select_first_row(self.message_table)
        else:
            self.message_detail.setPlainText("")

        hour_labels = []
        sent_series = []
        received_series = []
        if rows:
            hour_keys = []
            for offset in range(23, -1, -1):
                dt = now_local() - datetime.timedelta(hours=offset)
                hour_keys.append(dt.strftime("%Y-%m-%d %H:00"))
                hour_labels.append(dt.strftime("%H:%M"))
            sent_map = {key: 0 for key in hour_keys}
            recv_map = {key: 0 for key in hour_keys}
            for row in rows:
                ts_dt = row.get("timestamp_dt")
                if ts_dt is None:
                    continue
                key = ts_dt.strftime("%Y-%m-%d %H:00")
                if key not in sent_map:
                    continue
                if row.get("direction") == "outgoing":
                    sent_map[key] += 1
                elif row.get("direction") == "incoming":
                    recv_map[key] += 1
            sent_series = [sent_map[key] for key in hour_keys]
            received_series = [recv_map[key] for key in hour_keys]
        self.message_activity_chart.set_chart_data(
            hour_labels,
            [
                {"name": "Sent", "values": sent_series, "color": "#2b5fd9"},
                {"name": "Received", "values": received_series, "color": "#17a673"},
            ],
        )

    def update_message_detail(self):
        row_index = self.message_table.currentRow()
        if row_index < 0:
            self.message_detail.setPlainText("")
            return
        item = self.message_table.item(row_index, 0)
        row = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not isinstance(row, dict):
            self.message_detail.setPlainText("")
            return

        lines = [
            f"Client: {row.get('client_label') or row.get('host') or '-'}",
            f"Timestamp: {row.get('timestamp_display') or '-'}",
            f"Direction: {str(row.get('direction') or '-').upper()}",
            f"Account: {row.get('account') or '-'}",
            f"Contact: {row.get('contact') or '-'}",
            f"Status: {str(row.get('status') or '-').upper()}",
            f"Send Type: {row.get('send_type') or '-'}",
            f"Trigger: {row.get('trigger') or '-'}",
            f"Attachment: {'YES' if row.get('has_attachment') else 'NO'}",
            f"Bad Words: {safe_int(row.get('bad_word_count'), 0, 0)}",
            "",
            row.get("content") or row.get("preview") or "",
        ]
        self.message_detail.setPlainText("\n".join(lines))

    def get_filtered_qc_conversations(self):
        client_filter = str(self.qc_client_filter.currentData() or "").strip()
        query_text = str(self.qc_search_edit.text() or "").strip().lower()
        rows = []
        for snapshot in self.get_sorted_snapshots():
            host = str(snapshot.get("host") or "").strip()
            if client_filter and host != client_filter:
                continue
            client_label = str(snapshot.get("client_label") or host)
            for row in list(snapshot.get("qc_conversations") or []):
                enriched = dict(row)
                enriched["host"] = host
                enriched["client_label"] = client_label
                if query_text:
                    haystacks = [
                        client_label.lower(),
                        str(row.get("contact_display") or "").lower(),
                        str(row.get("contact_phone") or "").lower(),
                        str(row.get("self_accounts_text") or "").lower(),
                        str(row.get("last_preview") or "").lower(),
                    ]
                    if not any(query_text in hay for hay in haystacks if hay):
                        continue
                rows.append(enriched)

        rows.sort(key=lambda row: parse_timestamp(row.get("last_message_at")) or datetime.datetime.min, reverse=True)
        return rows

    def render_qc_tab(self):
        rows = self.get_filtered_qc_conversations()
        self.qc_conversation_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            values = [
                row.get("client_label") or row.get("host") or "",
                row.get("contact_display") or "-",
                row.get("contact_phone") or "-",
                row.get("self_accounts_text") or "-",
                str(safe_int(row.get("sent_count"), 0, 0)),
                str(safe_int(row.get("received_count"), 0, 0)),
                str(safe_int(row.get("total_count"), 0, 0)),
                row.get("last_message_at") or "-",
            ]
            for col, value in enumerate(values):
                user_data = row if col == 0 else None
                align = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter if col in {4, 5, 6} else None
                self.qc_conversation_table.setItem(row_index, col, make_table_item(value, user_data=user_data, align=align))
        if self.qc_conversation_table.rowCount() > 0:
            select_first_row(self.qc_conversation_table)
        else:
            self.qc_message_table.setRowCount(0)
            self.qc_detail.setPlainText("")

    def load_selected_qc_conversation(self):
        row_index = self.qc_conversation_table.currentRow()
        if row_index < 0:
            self.qc_message_table.setRowCount(0)
            self.qc_detail.setPlainText("")
            return

        item = self.qc_conversation_table.item(row_index, 0)
        row = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not isinstance(row, dict):
            self.qc_message_table.setRowCount(0)
            self.qc_detail.setPlainText("")
            return

        host = str(row.get("host") or "").strip()
        contact_key = str(row.get("contact_key") or row.get("contact_phone") or row.get("contact_display") or "").strip()
        if not host or not contact_key:
            self.qc_message_table.setRowCount(0)
            self.qc_detail.setPlainText("")
            return

        self.current_conversation_host = host
        self.current_conversation_key = contact_key
        self.qc_detail.setPlainText("Loading conversation messages...")

        if self.conversation_thread is not None and self.conversation_thread.isRunning():
            return

        self.conversation_thread = ConversationWorker(host, contact_key, account_filter="", parent=self)
        self.conversation_thread.finished_messages.connect(self.on_qc_conversation_loaded)
        self.conversation_thread.start()

    def on_qc_conversation_loaded(self, host, result):
        if host != self.current_conversation_host:
            return

        payload = dict(result.get("payload") or {})
        if not result.get("ok"):
            self.qc_message_table.setRowCount(0)
            self.qc_detail.setPlainText(f"Failed to load conversation.\n\n{result.get('error') or payload.get('message') or 'Unknown error'}")
            return

        conversation = dict(payload.get("conversation") or {})
        items = list(payload.get("items") or [])[:MAX_VISIBLE_QC_MESSAGES]
        self.qc_message_table.setRowCount(len(items))
        for row_index, row in enumerate(items):
            values = [
                row.get("timestamp_display") or row.get("timestamp") or "-",
                str(row.get("direction") or "").upper(),
                row.get("from") or "-",
                row.get("to") or "-",
                row.get("preview") or shorten_text(row.get("content") or "", 120),
                str(row.get("status") or "-").upper(),
                row.get("trigger") or "-",
                str(safe_int(row.get("bad_word_count"), 0, 0)),
            ]
            for col, value in enumerate(values):
                user_data = row if col == 0 else None
                align = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter if col == 7 else None
                self.qc_message_table.setItem(row_index, col, make_table_item(value, user_data=user_data, align=align))
        if self.qc_message_table.rowCount() > 0:
            select_first_row(self.qc_message_table)

        header_lines = [
            f"Client: {self.get_client_label_for_host(host)}",
            f"Contact: {conversation.get('contact_display') or '-'}",
            f"Phone: {conversation.get('contact_phone') or '-'}",
            f"Accounts: {conversation.get('self_accounts_text') or '-'}",
            f"Sent: {safe_int(conversation.get('sent_count'), 0, 0)}",
            f"Received: {safe_int(conversation.get('received_count'), 0, 0)}",
            f"Total: {safe_int(conversation.get('total_count'), 0, 0)}",
            f"First: {conversation.get('first_message_at') or '-'}",
            f"Last: {conversation.get('last_message_at') or '-'}",
            "",
            f"Last Preview: {conversation.get('last_preview') or '-'}",
        ]
        self.qc_detail.setPlainText("\n".join(header_lines))

    def update_qc_message_detail(self):
        row_index = self.qc_message_table.currentRow()
        if row_index < 0:
            return
        item = self.qc_message_table.item(row_index, 0)
        row = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not isinstance(row, dict):
            return

        lines = [
            f"Timestamp: {row.get('timestamp_display') or row.get('timestamp') or '-'}",
            f"Direction: {str(row.get('direction') or '-').upper()}",
            f"Send Type: {row.get('send_type') or '-'}",
            f"Status: {str(row.get('status') or '-').upper()}",
            f"Self Account: {row.get('self_account') or '-'}",
            f"From: {row.get('from') or '-'}",
            f"To: {row.get('to') or '-'}",
            f"Attachment: {'YES' if row.get('has_attachment') else 'NO'}",
            f"Trigger: {row.get('trigger') or '-'}",
            f"Bad Words: {safe_int(row.get('bad_word_count'), 0, 0)}",
            "",
            row.get("content") or row.get("preview") or "",
        ]
        self.qc_detail.setPlainText("\n".join(lines))

    def get_client_label_for_host(self, host):
        snapshot = dict(self.client_snapshots.get(str(host or "").strip()) or {})
        return str(snapshot.get("client_label") or host or "-")

    def render_api_tab(self):
        host = str(self.api_client_combo.currentData() or "").strip()
        snapshot = dict(self.client_snapshots.get(host) or {})
        endpoint_health = dict(snapshot.get("endpoint_health") or {})

        self.api_table.setRowCount(len(KNOWN_API_ENDPOINTS))
        for row_index, endpoint in enumerate(KNOWN_API_ENDPOINTS):
            key = self.map_endpoint_path_to_health_key(endpoint.get("path"))
            info = dict(endpoint_health.get(key) or {})
            if host and info:
                state = "OK" if info.get("ok") else "FAIL"
                latency_text = format_latency(info.get("latency_ms"))
            else:
                state = "N/A"
                latency_text = "-"
            values = [
                endpoint.get("method") or "GET",
                endpoint.get("path") or "",
                endpoint.get("description") or "",
                state,
                latency_text,
            ]
            for col, value in enumerate(values):
                user_data = endpoint if col == 0 else None
                item = make_table_item(value, user_data=user_data)
                if col == 3:
                    if value == "OK":
                        item.setBackground(QColor("#d1e7dd"))
                        item.setForeground(QColor("#0f5132"))
                    elif value == "FAIL":
                        item.setBackground(QColor("#f8d7da"))
                        item.setForeground(QColor("#842029"))
                self.api_table.setItem(row_index, col, item)
        if self.api_table.rowCount() > 0:
            select_first_row(self.api_table)
        self.on_api_endpoint_selected()

        if host != self.current_api_image_host:
            self.clear_api_image_preview("Image responses will appear here.\nFetch an image endpoint to preview it here.")
            self.current_api_image_host = host

        if not host:
            self.api_response.setPlainText("Select a client to inspect available APIs.")

    def map_endpoint_path_to_health_key(self, path):
        path = str(path or "").strip().lower()
        if path.endswith("/client-info"):
            return "client_info"
        if path.endswith("/tab-stats"):
            return "tab_stats"
        if path.endswith("/templates"):
            return "templates"
        if path.endswith("/send-receive-messages"):
            return "messages"
        if path.endswith("/qc-conversations"):
            return "qc_conversations"
        if path.endswith("/bad-word-stats"):
            return "bad_words"
        if path.endswith("/live-view"):
            return "live_view"
        if path.endswith("/active-tab-screenshot"):
            return "active_tab_screenshot"
        if path.endswith("/show/popup-message"):
            return "popup_message"
        return path

    def on_api_endpoint_selected(self):
        row_index = self.api_table.currentRow()
        if row_index < 0:
            return

        item = self.api_table.item(row_index, 0)
        endpoint = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not isinstance(endpoint, dict):
            return

        method = str(endpoint.get("method") or "GET").strip().upper()
        default_body = dict(endpoint.get("default_body") or {})
        if method == "POST":
            self.api_body_edit.setPlainText(json.dumps(default_body, ensure_ascii=False, indent=2))
        else:
            self.api_body_edit.setPlainText("")

    def fetch_selected_api_endpoint(self):
        host = str(self.api_client_combo.currentData() or "").strip()
        if not host:
            QMessageBox.information(self, "API Explorer", "Select a client first.")
            self.clear_api_image_preview("Image responses will appear here.\nFetch an image endpoint to preview it here.")
            return
        row_index = self.api_table.currentRow()
        if row_index < 0:
            QMessageBox.information(self, "API Explorer", "Select an endpoint first.")
            return
        item = self.api_table.item(row_index, 0)
        endpoint = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not isinstance(endpoint, dict):
            return

        method = str(endpoint.get("method") or "GET").strip().upper()
        path = str(endpoint.get("path") or "").strip()
        params = dict(endpoint.get("default_params") or {})
        raw_query = str(self.api_query_edit.text() or "").strip()
        if raw_query:
            parsed = urllib.parse.parse_qs(raw_query, keep_blank_values=True)
            params = {k: v[-1] if isinstance(v, list) and len(v) == 1 else v for k, v in parsed.items()}

        if path.endswith("/active-tab-screenshot"):
            self.api_response.setPlainText("Fetching active-tab screenshot...")
            self.clear_api_image_preview("Loading screenshot...")
            result = fetch_image_endpoint(host, path, params=params, timeout=LIVE_VIEW_TIMEOUT_SECONDS)
            self.update_endpoint_health_for_path(host, path, result)
            self.update_api_table_row_state(row_index, result)

            display = {
                "request_url": result.get("url"),
                "ok": result.get("ok"),
                "status": result.get("status"),
                "latency_ms": result.get("latency_ms"),
                "content_type": result.get("content_type"),
                "error": result.get("error"),
                "meta": result.get("meta"),
                "payload": result.get("payload"),
                "bytes": len(result.get("image_bytes") or b""),
            }
            self.api_response.setPlainText(json.dumps(display, ensure_ascii=False, indent=2))
            if result.get("ok"):
                self.set_api_image_preview(result.get("image_bytes") or b"", host=host)
            return

        if path.endswith("/live-view"):
            self.api_response.setPlainText("Fetching live-view frame...")
            self.clear_api_image_preview("Loading live-view frame...")
            result = fetch_live_view_frame(host, scope=str(params.get("scope") or "tab"))
            self.update_endpoint_health_for_path(host, path, result)
            self.update_api_table_row_state(row_index, result)
            display = {
                "request_url": build_client_url(host, path, params=params),
                "ok": result.get("ok"),
                "status": result.get("status"),
                "latency_ms": result.get("latency_ms"),
                "error": result.get("error"),
                "bytes": len(result.get("image_bytes") or b""),
                "message": "Single JPEG frame extracted from the live-view stream."
            }
            self.api_response.setPlainText(json.dumps(display, ensure_ascii=False, indent=2))
            if result.get("ok"):
                self.set_api_image_preview(result.get("image_bytes") or b"", host=host)
            return

        if path.endswith("/bad-word-stats") and not params:
            params = {"from": iso_day_offset(6), "to": today_key()}

        if method == "POST":
            raw_body = str(self.api_body_edit.toPlainText() or "").strip()
            if raw_body:
                try:
                    payload = json.loads(raw_body)
                except Exception as exc:
                    QMessageBox.warning(self, "API Explorer", f"Invalid JSON body:\n{exc}")
                    return
                if not isinstance(payload, dict):
                    QMessageBox.warning(self, "API Explorer", "POST body must decode to a JSON object.")
                    return
            else:
                payload = dict(endpoint.get("default_body") or {})

            self.clear_api_image_preview("Image responses will appear here.\nFetch an image endpoint to preview it here.")
            result = request_json_post(host, path, payload=payload, timeout=REFRESH_TIMEOUT_SECONDS)
            self.update_endpoint_health_for_path(host, path, result)
            self.update_api_table_row_state(row_index, result)
            display = {
                "request_url": result.get("url"),
                "method": method,
                "payload_sent": payload,
                "ok": result.get("ok"),
                "status": result.get("status"),
                "latency_ms": result.get("latency_ms"),
                "error": result.get("error"),
                "payload": result.get("payload"),
            }
            self.api_response.setPlainText(json.dumps(display, ensure_ascii=False, indent=2))
            return

        self.clear_api_image_preview("Image responses will appear here.\nFetch an image endpoint to preview it here.")
        result = request_json(host, path, params=params, timeout=REFRESH_TIMEOUT_SECONDS)
        self.update_endpoint_health_for_path(host, path, result)
        self.update_api_table_row_state(row_index, result)
        display = {
            "request_url": result.get("url"),
            "ok": result.get("ok"),
            "status": result.get("status"),
            "latency_ms": result.get("latency_ms"),
            "error": result.get("error"),
            "payload": result.get("payload"),
        }
        self.api_response.setPlainText(json.dumps(display, ensure_ascii=False, indent=2))

    def send_popup_to_selected_client(self):
        host = self.get_selected_client_host(self.client_table)
        if not host:
            QMessageBox.information(self, "Client Notice", "Select a client first.")
            return

        title = str(self.client_popup_title_edit.text() or "").strip() or "Notice from Master Dashboard"
        message = str(self.client_popup_message_edit.toPlainText() or "").strip()
        if not message:
            QMessageBox.warning(self, "Client Notice", "Write a popup message first.")
            return

        level = str(self.client_popup_level_combo.currentText() or "warning").strip().lower()
        duration = safe_int(self.client_popup_duration_edit.text(), 0, 0, 24 * 60 * 60)
        payload = {
            "title": title,
            "message": message,
            "level": level,
            "durationSeconds": duration,
            "source": "Master Dashboard",
        }

        self.client_popup_status_label.setText("Sending popup...")
        result = request_json_post(host, "/api/v1/show/popup-message", payload=payload, timeout=REFRESH_TIMEOUT_SECONDS)
        self.update_endpoint_health_for_path(host, "/api/v1/show/popup-message", result)
        self.update_selected_client_detail()

        if result.get("ok"):
            shown_at = str(result.get("payload", {}).get("shown_at") or "-")
            self.client_popup_status_label.setText(f"Popup sent at {shown_at}.")
            self.status_bar.showMessage(f"Popup notice sent to {host}.", 5000)
            return

        error_text = str(result.get("error") or "Unknown error")
        self.client_popup_status_label.setText(f"Popup failed: {error_text}")
        QMessageBox.warning(self, "Client Notice", f"Failed to send popup.\n\n{error_text}")

    def closeEvent(self, event):
        for thread in (self.scan_thread, self.refresh_thread, self.conversation_thread, self.preview_thread):
            try:
                if thread is not None and thread.isRunning():
                    thread.quit()
                    thread.wait(300)
            except Exception:
                pass
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    window = MasterDashboard()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
