import sys
import re
import time
import os
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-logging --log-level=3")
import json
import random
import socket
import datetime
import uuid
from cryptography.fernet import Fernet
from PyQt6.QtCore import *
from PyQt6.QtWidgets import *
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (
    QWebEnginePage,
    QWebEngineProfile,
    QWebEngineScript,
    QWebEngineUrlRequestInterceptor,
    QWebEngineSettings
)
from urllib.parse import urlparse
from PyQt6.QtGui import (
    QIcon, QAction, QPixmap, QKeySequence,
    QStandardItemModel, QStandardItem,
    QBrush, QColor, QPainter, QPen, QFont, QPalette, QLinearGradient
)
from PyQt6.QtNetwork import (
    QNetworkProxy,
    QNetworkProxyFactory,
    QNetworkAccessManager,
    QNetworkRequest
)
import urllib.parse
from PyQt6.QtCore import QTimer
import pandas as pd
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

# --------------------------
# CONFIGURATION
# --------------------------
ADMIN_PASSWORD = "Yusuf2509"
FALLBACK_TIMEZONE_NAME = "Asia/Jakarta"
ATTENDANCE_IDLE_THRESHOLD_SECONDS = 5 * 60
ATTENDANCE_TOUCH_DEBOUNCE_SECONDS = 12
MAX_ATTENDANCE_SEGMENTS = 1200
MAX_BULK_RECIPIENTS = 20


def get_runtime_resource_dir():
    frozen_resource_dir = getattr(sys, "_MEIPASS", "")
    if frozen_resource_dir:
        return os.path.abspath(frozen_resource_dir)

    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))

    return os.path.dirname(os.path.abspath(__file__))

def detect_user_timezone_info():
    try:
        local_dt = datetime.datetime.now().astimezone()
        if local_dt.tzinfo is not None:
            detected_name = getattr(local_dt.tzinfo, "key", None) or str(local_dt.tzinfo) or FALLBACK_TIMEZONE_NAME
            return local_dt.tzinfo, detected_name
    except Exception:
        pass

    if ZoneInfo is not None:
        try:
            return ZoneInfo(FALLBACK_TIMEZONE_NAME), FALLBACK_TIMEZONE_NAME
        except Exception:
            pass

    return datetime.timezone(datetime.timedelta(hours=7)), FALLBACK_TIMEZONE_NAME

USER_TIMEZONE, USER_TIMEZONE_NAME = detect_user_timezone_info()

NEW_TAB_ENABLED_GROUPS = {"Google", "Tencent", "Pendanaan"}

TAB_CONFIG = [
    {
        "name": "WhatsApp",
        "allowed_sites": ["https://web.whatsapp.com/"],
        "home": "https://web.whatsapp.com/"
    },
    # {
    #     "name": "Lark",
    #     "allowed_sites": [
    #         "https://accounts.larksuite.com/",
    #         "https://larksuite.com/",
    #         "https://feishu.cn/"
    #     ],
    #     "home": "https://lilbqlfsvt.feishu.cn/"
    # },
    # {
    #     "name": "WeChat",
    #     "allowed_sites": ["https://web.wechat.com/"],
    #     "home": "https://web.wechat.com/"
    # },
    # {
    #     "name": "Collection",
    #     "allowed_sites": ["http://collection.pendanaan.com/"],
    #     "home": "http://collection.pendanaan.com/"
    # },
    # {
    #     "name": "Callcenter",
    #     "allowed_sites": ["http://callcenter.pendanaan.com/"],
    #     "home": "http://callcenter.pendanaan.com/"
    # },
]

FORCED_LANGUAGE = "en-US,en;q=0.9"
DNS_SERVER = "1.1.1.1"

# Spoofing note:
# - ENABLE_SPOOF = False by default because header spoofing / JS geolocation spoofing
#   does NOT change the real exit IP seen by the server.
# - If enabled, it only fakes some client-side signals.
ENABLE_SPOOF = False
ENABLE_GEO_JS_SPOOF = False

# Encryption and file management
if os.name == "nt":
    APP_BASE = os.path.join(os.environ.get("LOCALAPPDATA", os.getcwd()), "LockedBrowser")
else:
    APP_BASE = os.path.join(os.path.expanduser("~"), ".lockedbrowser")

BASE_DIR = APP_BASE
os.makedirs(BASE_DIR, exist_ok=True)

H_DIR = os.path.join(BASE_DIR, "h")
os.makedirs(H_DIR, exist_ok=True)

RUN_DIR = get_runtime_resource_dir()
DEFAULT_BAD_WORDS_FILE = os.path.join(RUN_DIR, "bw.txt")
BAD_WORDS_FILE = os.path.join(BASE_DIR, "bw.txt")
BAD_WORD_COUNTER_FILE = os.path.join(H_DIR, "bw_counter.dat")

KEY_FILE = os.path.join(H_DIR, "k.dat")
FILES_CONFIG = os.path.join(H_DIR, "f.dat")
TEMPLATES_FILE = os.path.join(H_DIR, "tpl.dat")
ACTIVITY_STATS_FILE = os.path.join(H_DIR, "activity.dat")
CONTACTS_FILE = os.path.join(H_DIR, "contacts.dat")

CONTACT_FLAG_META = {
    "none":   {"label": "No Flag", "bg": "#e9ecef", "fg": "#212529"},
    "green":  {"label": "Green",   "bg": "#d1e7dd", "fg": "#0f5132"},
    "yellow": {"label": "Yellow",  "bg": "#fff3cd", "fg": "#664d03"},
    "red":    {"label": "Red",     "bg": "#f8d7da", "fg": "#842029"},
}

API_HOST = "0.0.0.0"
API_PORT = 5001
API_TOKEN = "PTN_LOCKED_BROWSER_API_TOKEN_2026_STATIC"
API_HEADER_NAME = "X-API-Token"

ACTIVITY_LOCK = threading.RLock()

HISTORY_FILE = None
NETWORK_LOG_FILE = None
LAST_BLAST_FILE = None
MANUAL_SEND_LOG_FILE = None

APP_STATE_FILE = os.path.join(H_DIR, "s.dat")
PROFILE_BASE_DIR = os.path.join(BASE_DIR, "profiles")

ALLOWED_DOWNLOAD_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.mp3', '.mp4', '.pdf'}

SPOOF_COUNTRIES = {
    "Singapore": (1.3521, 103.8198),
    "Malaysia": (4.2105, 101.9758),
    "Vietnam": (14.0583, 108.2772),
    "Thailand": (15.8700, 100.9925),
    "Australia": (-25.2744, 133.7751)
}

def normalize_chat_key(raw):
    s = str(raw or "").strip()
    if not s:
        return ""

    send_number, _ = normalize_indonesia_mobile(s)
    if send_number:
        return send_number

    digits = normalize_phone_number(s).lstrip("+")
    if digits:
        if digits.startswith("0"):
            digits = "62" + digits[1:]
        if len(digits) >= 8:
            return digits

    return s.lower()


WHATSAPP_OUTGOING_SEND_TYPES = {"manual", "bulk_auto", "sync_outgoing"}
WHATSAPP_INCOMING_SEND_TYPES = {"incoming_reply", "sync_incoming"}


def is_whatsapp_outgoing_history_send_type(send_type):
    return str(send_type or "").strip().lower() in WHATSAPP_OUTGOING_SEND_TYPES


def is_whatsapp_incoming_history_send_type(send_type):
    return str(send_type or "").strip().lower() in WHATSAPP_INCOMING_SEND_TYPES


def get_whatsapp_history_direction(send_type):
    if is_whatsapp_incoming_history_send_type(send_type):
        return "incoming"
    if is_whatsapp_outgoing_history_send_type(send_type):
        return "outgoing"
    return "other"


def history_timestamp_sort_key(value):
    dt = ensure_user_datetime(value)
    if dt is not None:
        return (0, dt.timestamp())
    return (1, str(value or "").strip())


def format_history_endpoint(phone_value="", label_value="", fallback="-"):
    phone_text = str(phone_value or "").strip()
    label_text = str(label_value or "").strip()

    if phone_text and label_text and phone_text.lower() != label_text.lower():
        return f"{phone_text} ({label_text})"
    if phone_text:
        return phone_text
    if label_text:
        return label_text
    return fallback


def normalize_whatsapp_history_entry(item, bad_words=None):
    if not isinstance(item, dict):
        return item, False

    entry = dict(item)
    original_entry = dict(item)
    send_type = str(entry.get("send_type") or "").strip().lower()
    direction = get_whatsapp_history_direction(send_type)

    content = str(entry.get("content") or "")
    try:
        message_length = int(entry.get("message_length") or len(content))
    except Exception:
        message_length = len(content)
    entry["message_length"] = message_length
    entry["has_attachment"] = bool(entry.get("has_attachment"))

    stored_bad_words = [
        str(x).strip().lower()
        for x in (entry.get("bad_words") or [])
        if str(x).strip()
    ]
    stored_bad_count = int(entry.get("bad_word_count") or 0)
    _, bad_word_hits = mask_bad_words(content, bad_words or [])
    if stored_bad_words or stored_bad_count > 0:
        repaired_bad_words = sorted(set(stored_bad_words or bad_word_hits))
        repaired_bad_count = max(stored_bad_count, len(repaired_bad_words), len(bad_word_hits))
    else:
        repaired_bad_words = sorted(set(bad_word_hits))
        repaired_bad_count = len(bad_word_hits)
    entry["bad_words"] = repaired_bad_words
    entry["bad_word_count"] = repaired_bad_count

    if direction == "incoming":
        from_phone = normalize_chat_key(entry.get("from_phone") or entry.get("from"))
        chat_label = str(
            entry.get("chat_label")
            or entry.get("from_display")
            or entry.get("from")
            or ""
        ).strip()
        from_display = str(entry.get("from_display") or chat_label or from_phone or "Customer").strip()
        conversation_key = normalize_chat_key(
            entry.get("conversation_key") or from_phone or chat_label or from_display
        )

        entry["from_phone"] = from_phone or ""
        if from_phone:
            entry["from"] = from_phone
        entry["chat_label"] = chat_label
        entry["from_display"] = from_display
        entry["conversation_key"] = conversation_key
        entry["status"] = "received"

    elif direction == "outgoing":
        to_phone = normalize_chat_key(entry.get("to_phone") or entry.get("to"))
        to_label = str(entry.get("chat_label") or entry.get("to") or "").strip()
        conversation_key = normalize_chat_key(
            entry.get("conversation_key") or to_phone or to_label
        )

        entry["to_phone"] = to_phone or ""
        if not str(entry.get("to") or "").strip():
            entry["to"] = to_phone or to_label
        entry["chat_label"] = to_label
        entry["conversation_key"] = conversation_key
        if str(entry.get("status") or "").strip().lower() not in {"sent", "failed"}:
            entry["status"] = "sent"

    if not str(entry.get("sig") or "").strip():
        derived_sig = derive_whatsapp_history_signature_from_log_item(entry)
        if derived_sig:
            entry["sig"] = derived_sig

    changed = (entry != original_entry)
    return entry, changed


def repair_whatsapp_history_log_entries(log_entries, bad_words=None):
    repaired = []
    changed = False

    for item in list(log_entries or []):
        fixed_item, item_changed = normalize_whatsapp_history_entry(item, bad_words=bad_words)
        repaired.append(fixed_item)
        if item_changed:
            changed = True

    chronological = []
    indexed_rows = list(enumerate(repaired))
    indexed_rows.sort(key=lambda pair: (history_timestamp_sort_key(pair[1].get("timestamp") if isinstance(pair[1], dict) else ""), pair[0]))

    for _, entry in indexed_rows:
        if not isinstance(entry, dict):
            chronological.append(entry)
            continue

        send_type = str(entry.get("send_type") or "").strip().lower()
        status = str(entry.get("status") or "").strip().lower()
        if is_whatsapp_outgoing_history_send_type(send_type) and status == "sent":
            reply_speed_seconds = compute_reply_speed_for_outgoing(
                chronological,
                entry.get("conversation_key") or entry.get("to_phone") or entry.get("to"),
                entry.get("timestamp")
            )
            reply_speed_hms = format_duration_hms(reply_speed_seconds) if reply_speed_seconds is not None else ""

            if entry.get("reply_speed_seconds") != reply_speed_seconds:
                entry["reply_speed_seconds"] = reply_speed_seconds
                changed = True
            if str(entry.get("reply_speed_hms") or "") != reply_speed_hms:
                entry["reply_speed_hms"] = reply_speed_hms
                changed = True

        chronological.append(entry)

    return repaired, changed


def build_whatsapp_history_rows(log_entries):
    rows = []

    for index, item in enumerate(list(log_entries or [])):
        if not isinstance(item, dict):
            continue

        send_type = str(item.get("send_type") or "").strip().lower()
        direction = get_whatsapp_history_direction(send_type)
        if direction == "other":
            continue

        content = str(item.get("content") or "")
        status = str(item.get("status") or "").strip()
        conversation_key = normalize_chat_key(item.get("conversation_key"))
        timestamp_value = item.get("timestamp")
        timestamp_display = format_user_datetime_text(timestamp_value, default="-")
        chat_label = str(item.get("chat_label") or "").strip()
        trigger = str(item.get("trigger") or "").strip()
        message_author = str(item.get("message_author") or "").strip()
        bad_words = item.get("bad_words") or []
        bad_words_text = ", ".join(str(x) for x in bad_words if str(x).strip())
        bad_word_count = int(item.get("bad_word_count") or 0)
        has_attachment = bool(item.get("has_attachment"))
        try:
            message_length = int(item.get("message_length") or len(content))
        except Exception:
            message_length = len(content)
        preview = make_text_preview(content, 240)
        if not preview and has_attachment:
            preview = "[Attachment only]"

        if direction == "incoming":
            contact_phone = normalize_chat_key(item.get("from_phone") or item.get("from"))
            contact_label = str(item.get("from_display") or chat_label or item.get("from") or "").strip()
            self_account = str(item.get("to") or "").strip()
            from_text = format_history_endpoint(contact_phone, contact_label)
            to_text = self_account or "-"
        else:
            contact_phone = normalize_chat_key(item.get("to_phone") or item.get("to"))
            contact_label = str(chat_label or item.get("to") or "").strip()
            self_account = str(item.get("from") or "").strip()
            from_text = self_account or "-"
            to_text = format_history_endpoint(contact_phone, contact_label)

        contact_key = normalize_chat_key(conversation_key or contact_phone or contact_label)
        contact_display = format_history_endpoint(contact_phone, contact_label, fallback=contact_key or "-")

        rows.append({
            "index": index,
            "timestamp": timestamp_value,
            "timestamp_display": timestamp_display,
            "sort_key": history_timestamp_sort_key(timestamp_value),
            "direction": direction,
            "send_type": send_type,
            "status": status,
            "contact_key": contact_key,
            "contact_phone": contact_phone,
            "contact_display": contact_display,
            "conversation_key": conversation_key or contact_key,
            "self_account": self_account,
            "from_text": from_text,
            "to_text": to_text,
            "content": content,
            "preview": preview or "-",
            "message_length": message_length,
            "has_attachment": has_attachment,
            "trigger": trigger,
            "bad_word_count": bad_word_count,
            "bad_words": bad_words,
            "bad_words_text": bad_words_text,
            "reply_speed_seconds": item.get("reply_speed_seconds"),
            "reply_speed_hms": str(item.get("reply_speed_hms") or ""),
            "message_author": message_author,
            "raw": item
        })

    return rows


def build_whatsapp_conversation_summaries(rows):
    buckets = {}

    for row in list(rows or []):
        if not isinstance(row, dict):
            continue
        key = str(row.get("contact_key") or "").strip()
        if not key:
            continue

        bucket = buckets.setdefault(key, {
            "contact_key": key,
            "contact_display": row.get("contact_display") or key,
            "contact_phone": row.get("contact_phone") or "",
            "self_accounts": set(),
            "sent_count": 0,
            "received_count": 0,
            "total_count": 0,
            "first_timestamp": row.get("timestamp"),
            "last_timestamp": row.get("timestamp"),
            "last_preview": row.get("preview") or "",
            "rows": []
        })

        bucket["rows"].append(row)
        bucket["total_count"] += 1
        if row.get("direction") == "incoming":
            bucket["received_count"] += 1
        else:
            bucket["sent_count"] += 1

        if row.get("self_account"):
            bucket["self_accounts"].add(str(row.get("self_account")))

        if history_timestamp_sort_key(row.get("timestamp")) < history_timestamp_sort_key(bucket.get("first_timestamp")):
            bucket["first_timestamp"] = row.get("timestamp")
        if history_timestamp_sort_key(row.get("timestamp")) >= history_timestamp_sort_key(bucket.get("last_timestamp")):
            bucket["last_timestamp"] = row.get("timestamp")
            bucket["last_preview"] = row.get("preview") or bucket.get("last_preview") or ""

    summaries = []
    for bucket in buckets.values():
        bucket["rows"] = sorted(bucket.get("rows") or [], key=lambda row: (row.get("sort_key"), row.get("index", 0)))
        bucket["self_accounts_text"] = ", ".join(sorted(bucket.get("self_accounts") or []))
        summaries.append(bucket)

    summaries.sort(key=lambda bucket: history_timestamp_sort_key(bucket.get("last_timestamp")), reverse=True)
    return summaries


def build_whatsapp_history_detail_text(row):
    if not isinstance(row, dict):
        return ""

    lines = [
        f"Timestamp: {row.get('timestamp_display') or '-'}",
        f"Direction: {str(row.get('direction') or '-').upper()}",
        f"Send Type: {row.get('send_type') or '-'}",
        f"Status: {str(row.get('status') or '-').upper()}",
        f"Contact: {row.get('contact_display') or '-'}",
        f"Account: {row.get('self_account') or '-'}",
        f"From: {row.get('from_text') or '-'}",
        f"To: {row.get('to_text') or '-'}",
        f"Conversation Key: {row.get('conversation_key') or row.get('contact_key') or '-'}",
        f"Trigger: {row.get('trigger') or '-'}",
        f"Message Length: {row.get('message_length') or 0}",
        f"Attachment: {'Yes' if row.get('has_attachment') else 'No'}",
        f"Bad Words: {row.get('bad_word_count') or 0}",
    ]

    if row.get("bad_words_text"):
        lines.append(f"Matched Bad Words: {row.get('bad_words_text')}")
    if row.get("reply_speed_hms"):
        lines.append(f"Reply Speed: {row.get('reply_speed_hms')}")
    if row.get("message_author"):
        lines.append(f"Message Author: {row.get('message_author')}")

    lines.extend(["", "Full Message Content:", str(row.get("content") or "")])
    return "\n".join(lines)


def compute_reply_speed_for_outgoing(existing_logs, conversation_key, outgoing_ts):
    key = normalize_chat_key(conversation_key)
    if not key:
        return None

    out_dt = parse_iso_dt(outgoing_ts)
    if not out_dt:
        return None

    latest_incoming_dt = None

    for item in existing_logs:
        if not is_whatsapp_incoming_history_send_type(item.get("send_type")):
            continue

        item_key = normalize_chat_key(
            item.get("conversation_key") or item.get("from_phone") or item.get("from")
        )
        item_dt = parse_iso_dt(item.get("timestamp"))

        if item_key == key and item_dt and item_dt <= out_dt:
            if latest_incoming_dt is None or item_dt > latest_incoming_dt:
                latest_incoming_dt = item_dt

    if latest_incoming_dt is None:
        return None

    # first outgoing after latest incoming gets the reply speed
    for item in existing_logs:
        if not is_whatsapp_outgoing_history_send_type(item.get("send_type")):
            continue

        item_key = normalize_chat_key(
            item.get("conversation_key") or item.get("to_phone") or item.get("to")
        )
        item_dt = parse_iso_dt(item.get("timestamp"))

        if item_key == key and item_dt and latest_incoming_dt < item_dt <= out_dt:
            return None

    return max(0, int((out_dt - latest_incoming_dt).total_seconds()))

def parse_iso_dt(value):
    s = str(value or "").strip()
    if not s:
        return None

    dt = None

    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(s)
    except Exception:
        pass

    if dt is None:
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d"
        ):
            try:
                dt = datetime.datetime.strptime(s, fmt)
                break
            except Exception:
                continue

    if dt is None:
        return None

    # Very important:
    # naive timestamps are treated as USER timezone, not UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=USER_TIMEZONE)

    return dt.astimezone(datetime.timezone.utc)


DISPLAY_DATETIME_KEYS = {
    "timestamp",
    "ts",
    "updated_at",
    "last_updated",
    "last_chat_at",
    "last_outgoing_at",
    "last_incoming_at",
    "captured_at",
    "started_at",
    "finished_at",
    "created_at"
}


def ensure_user_datetime(value=None):
    if value is None:
        return datetime.datetime.now(USER_TIMEZONE)

    if isinstance(value, datetime.datetime):
        dt = value
    else:
        dt = parse_iso_dt(value)
        if dt is None:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=USER_TIMEZONE)
    else:
        dt = dt.astimezone(USER_TIMEZONE)

    return dt


def format_user_datetime_text(value, default="", include_tz=False):
    dt = ensure_user_datetime(value)
    if dt is None:
        raw = str(value or "").strip()
        return raw or default

    text = dt.strftime("%Y-%m-%d %H:%M:%S")
    if include_tz:
        tz_label = dt.tzname() or USER_TIMEZONE_NAME
        text = f"{text} {tz_label}"
    return text


def make_timestamps_display_friendly(value):
    if isinstance(value, list):
        return [make_timestamps_display_friendly(x) for x in value]

    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key_text = str(k or "").strip().lower()
            if isinstance(v, (dict, list)):
                out[k] = make_timestamps_display_friendly(v)
            elif key_text in DISPLAY_DATETIME_KEYS:
                out[k] = format_user_datetime_text(v, default=str(v or ""))
            else:
                out[k] = v
        return out

    return value

def normalize_indonesia_mobile(raw):
    digits = "".join(ch for ch in str(raw or "") if ch.isdigit())
    if not digits:
        return None, None

    # Accept:
    # 87850303779
    # 087850303779
    # 6287850303779
    if digits.startswith("0"):
        national = digits[1:]
    elif digits.startswith("62"):
        national = digits[2:]
    elif digits.startswith("8"):
        national = digits
    else:
        return None, None

    if len(national) < 8:
        return None, None

    send_number = "62" + national

    # Display format: +62 878-5030-3779
    parts = [national[:3]]
    rest = national[3:]
    while rest:
        take = 4 if len(rest) > 4 else len(rest)
        parts.append(rest[:take])
        rest = rest[take:]

    display_number = "+62 " + "-".join(parts)
    return send_number, display_number


def extract_uid_mobile_pairs(payload):
    found = []
    seen = set()

    def walk(node):
        if isinstance(node, dict):
            if "uid" in node and "mobile_no" in node:
                uid = node.get("uid")
                mobile_no = node.get("mobile_no")

                send_number, display_number = normalize_indonesia_mobile(mobile_no)
                if uid is not None and send_number:
                    key = (str(uid), send_number)
                    if key not in seen:
                        seen.add(key)
                        found.append({
                            "uid": str(uid),
                            "mobile_raw": str(mobile_no),
                            "send_number": send_number,
                            "display_number": display_number
                        })

            for value in node.values():
                walk(value)

        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return found

PLACEHOLDER_RE = re.compile(r"\$\{([^}]+)\}")


def extract_template_placeholder_keys(template):
    keys = []
    seen = set()

    for match in PLACEHOLDER_RE.finditer(str(template or "")):
        key = str(match.group(1) or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        keys.append(key)

    return keys


def is_missing_template_value(value):
    if value is None:
        return True

    text = str(value).strip()
    return (not text) or (text.upper() == "NULL")


def build_template_render_values(recipient, global_values=None):
    recipient = dict(recipient or {})
    values = {
        str(k).strip(): v
        for k, v in dict(recipient.get("template_vars") or {}).items()
        if str(k).strip()
    }

    name_value = recipient.get("name")
    if not is_missing_template_value(name_value):
        values["name"] = str(name_value).strip()
    else:
        values.setdefault("name", name_value if name_value is not None else "NULL")

    phone_value = recipient.get("send_number") or recipient.get("display_number") or ""
    if not is_missing_template_value(phone_value):
        values["phone"] = str(phone_value).strip()
    else:
        values.setdefault("phone", "NULL")

    for key, value in dict(global_values or {}).items():
        clean_key = str(key or "").strip()
        if not clean_key:
            continue

        if is_missing_template_value(values.get(clean_key)) and not is_missing_template_value(value):
            values[clean_key] = str(value).strip()

    for key, value in list(values.items()):
        if is_missing_template_value(value):
            values[key] = "NULL"
        else:
            values[key] = str(value).strip()

    return values


def apply_template_global_values_to_recipient(recipient, global_values=None):
    rec = dict(recipient or {})
    values = build_template_render_values(rec, global_values=global_values)
    template_vars = dict(rec.get("template_vars") or {})

    for key, value in values.items():
        if key == "phone":
            continue

        if key == "name" and is_missing_template_value(rec.get("name")) and not is_missing_template_value(value):
            rec["name"] = value

        if key not in template_vars or is_missing_template_value(template_vars.get(key)):
            template_vars[key] = value

    rec["template_vars"] = template_vars
    return rec


def find_missing_template_keys(template, recipients, global_values=None):
    placeholder_keys = extract_template_placeholder_keys(template)
    if not placeholder_keys:
        return []

    if isinstance(recipients, dict):
        recipients = [recipients]
    else:
        recipients = list(recipients or [])

    if not recipients:
        recipients = [{}]

    missing = []

    for key in placeholder_keys:
        for rec in recipients:
            values = build_template_render_values(rec, global_values=global_values)
            if is_missing_template_value(values.get(key)):
                missing.append(key)
                break

    return missing


def prompt_template_global_values(parent, template_text, recipients, action_label="this action"):
    missing_keys = find_missing_template_keys(template_text, recipients)
    if not missing_keys:
        return {}

    dlg = QDialog(parent)
    dlg.setWindowTitle("Missing Template Values")
    dlg.setMinimumWidth(520)

    root = QVBoxLayout(dlg)

    info = QLabel(
        "Some placeholders in this template still do not have data.\n\n"
        f"Enter one temporary global value for each missing placeholder below. "
        f"It will be used only for {action_label}. Leave blank if you want it to stay as NULL."
    )
    info.setWordWrap(True)
    info.setStyleSheet("padding:8px;border:1px solid #ddd;border-radius:6px;")
    root.addWidget(info)

    form = QFormLayout()
    edits = {}

    for key in missing_keys:
        edit = QLineEdit(dlg)
        edit.setPlaceholderText(f"Temporary value for ${{{key}}}")
        form.addRow(f"${{{key}}}", edit)
        edits[key] = edit

    root.addLayout(form)

    buttons = QDialogButtonBox(
        QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
    )
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    root.addWidget(buttons)

    if dlg.exec() != QDialog.DialogCode.Accepted:
        return None

    return {
        key: edit.text().strip()
        for key, edit in edits.items()
    }


def require_admin_password_from_widget(widget):
    current = widget
    seen = set()

    while current is not None and id(current) not in seen:
        seen.add(id(current))
        checker = getattr(current, "require_admin_password", None)
        if callable(checker):
            return bool(checker())
        current = current.parent()

    pwd, ok = QInputDialog.getText(
        widget,
        "Admin Login",
        "Enter Password:",
        QLineEdit.EchoMode.Password
    )
    return ok and pwd == ADMIN_PASSWORD


def configure_scrollable_text_edit(edit, min_height=None, always_show_scroll=False):
    if not isinstance(edit, QTextEdit):
        return edit

    if min_height is not None:
        edit.setMinimumHeight(int(min_height))

    edit.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
    edit.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    edit.setVerticalScrollBarPolicy(
        Qt.ScrollBarPolicy.ScrollBarAlwaysOn
        if always_show_scroll else
        Qt.ScrollBarPolicy.ScrollBarAsNeeded
    )
    edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    return edit


def apply_ios_button_shadow(button):
    if not isinstance(button, (QPushButton, QToolButton)):
        return

    existing = button.graphicsEffect()
    if existing is not None:
        button.setGraphicsEffect(None)


def configure_rounded_combo_popup(combo):
    if not isinstance(combo, QComboBox):
        return combo

    current_view = combo.view()
    if not isinstance(current_view, QListView):
        current_view = QListView(combo)
        combo.setView(current_view)

    current_view.setSpacing(4)
    current_view.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    current_view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    current_view.setStyleSheet("""
        QListView {
            background: #ffffff;
            color: #10315e;
            border: 1px solid #8fa9d4;
            padding: 2px;
            outline: 0;
        }
        QListView::item {
            padding: 4px 8px;
            margin: 0px;
        }
        QListView::item:selected {
            background: #2b5fd9;
            color: #ffffff;
        }
    """)
    return combo


def make_table_item(value="", user_data=None, align=None):
    item = QTableWidgetItem("" if value is None else str(value))
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    if user_data is not None:
        item.setData(Qt.ItemDataRole.UserRole, user_data)
    if align is not None:
        item.setTextAlignment(int(align))
    return item


def prepare_plain_table_widget(table, headers, stretch_last=False):
    if not isinstance(table, QTableWidget):
        return table

    header_labels = [str(h or "") for h in list(headers or [])]
    table.setColumnCount(len(header_labels))
    table.setHorizontalHeaderLabels(header_labels)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSortingEnabled(False)
    table.setShowGrid(True)
    table.setCornerButtonEnabled(False)
    table.verticalHeader().setVisible(False)
    configure_data_table_widget(table, stretch_last=stretch_last)
    return table


def select_first_table_row(table):
    if not isinstance(table, QTableWidget):
        return
    if table.rowCount() <= 0 or table.columnCount() <= 0:
        return
    table.setCurrentCell(0, 0)
    table.selectRow(0)


def configure_data_table_widget(table, stretch_last=False):
    if not isinstance(table, (QTableWidget, QTableView)):
        return table

    table.setAlternatingRowColors(True)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    table.setSizeAdjustPolicy(QAbstractScrollArea.SizeAdjustPolicy.AdjustIgnored)
    table.setWordWrap(False)
    table.setTextElideMode(Qt.TextElideMode.ElideRight)

    vheader = table.verticalHeader()
    if vheader is not None:
        vheader.setDefaultSectionSize(max(vheader.defaultSectionSize(), 30))

    header = table.horizontalHeader()
    if header is not None:
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setMinimumSectionSize(120)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        column_count = 0
        model = table.model()
        if model is not None:
            try:
                column_count = int(model.columnCount())
            except Exception:
                column_count = 0
        default_width = 190 if 0 < column_count <= 4 else 150
        header.setDefaultSectionSize(default_width)
        header.setStretchLastSection(bool(stretch_last))

        if column_count and hasattr(table, "setColumnWidth"):
            for col in range(column_count):
                base_width = 130 if col == 0 else default_width
                try:
                    current_width = int(table.columnWidth(col))
                except Exception:
                    current_width = 0
                table.setColumnWidth(col, max(current_width, base_width))

    return table


def configure_card_list_widget(list_widget, spacing=10):
    if not isinstance(list_widget, QListWidget):
        return list_widget

    list_widget.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    list_widget.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    list_widget.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    list_widget.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    list_widget.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    list_widget.setFrameShape(QFrame.Shape.NoFrame)
    list_widget.setSpacing(int(spacing))
    list_widget.setWordWrap(True)
    list_widget.setUniformItemSizes(False)
    list_widget.setResizeMode(QListView.ResizeMode.Adjust)
    list_widget.setStyleSheet(
        "QListWidget {"
        "background: transparent;"
        "border: none;"
        "padding: 4px;"
        "outline: 0;"
        "}"
        "QListWidget::item {"
        "border: none;"
        "background: transparent;"
        "padding: 0px;"
        "margin: 0px;"
        "}"
        "QListWidget::item:selected {"
        "background: transparent;"
        "}"
    )
    return list_widget


def make_text_preview(value, limit=220):
    text = str(value or "").replace("\r", "").strip()
    if not text:
        return ""

    compact = re.sub(r"\n{3,}", "\n\n", text)
    if len(compact) <= int(limit):
        return compact
    return compact[: max(0, int(limit) - 1)].rstrip() + "..."


def refresh_card_list_selection_styles(list_widget):
    if not isinstance(list_widget, QListWidget):
        return

    current_item = list_widget.currentItem()
    for idx in range(list_widget.count()):
        item = list_widget.item(idx)
        widget = list_widget.itemWidget(item)
        if hasattr(widget, "set_selected"):
            widget.set_selected(item is current_item)


class CleanInfoCardWidget(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setMinimumHeight(112)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(7)

        header = QHBoxLayout()
        header.setSpacing(8)

        self.badge_label = QLabel("")
        self.badge_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge_label.setMinimumWidth(76)
        header.addWidget(self.badge_label, 0)

        self.title_label = QLabel("")
        self.title_label.setWordWrap(True)
        self.title_label.setStyleSheet("font-size:15px;font-weight:800;color:#0d2d63;")
        header.addWidget(self.title_label, 1)

        self.right_label = QLabel("")
        self.right_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        self.right_label.setWordWrap(True)
        self.right_label.setStyleSheet("font-size:12px;font-weight:800;color:#3f5f8c;")
        header.addWidget(self.right_label, 0)

        root.addLayout(header)

        self.subtitle_label = QLabel("")
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setStyleSheet("font-size:12px;font-weight:700;color:#2f4f79;")
        root.addWidget(self.subtitle_label)

        self.body_label = QLabel("")
        self.body_label.setWordWrap(True)
        self.body_label.setStyleSheet("font-size:12px;color:#50688d;")
        root.addWidget(self.body_label)

        self.footer_label = QLabel("")
        self.footer_label.setWordWrap(True)
        self.footer_label.setStyleSheet("font-size:11px;font-weight:700;color:#6380a3;")
        root.addWidget(self.footer_label)

        self.set_selected(False)

    def set_content(
        self,
        title="",
        right_text="",
        subtitle="",
        body="",
        footer="",
        badge_text="",
        badge_bg="#edf4ff",
        badge_fg="#0d2d63"
    ):
        self.title_label.setText(str(title or ""))
        self.right_label.setText(str(right_text or ""))
        self.right_label.setVisible(bool(str(right_text or "").strip()))

        self.subtitle_label.setText(str(subtitle or ""))
        self.subtitle_label.setVisible(bool(str(subtitle or "").strip()))

        self.body_label.setText(str(body or ""))
        self.body_label.setVisible(bool(str(body or "").strip()))

        self.footer_label.setText(str(footer or ""))
        self.footer_label.setVisible(bool(str(footer or "").strip()))

        badge_text = str(badge_text or "").strip()
        if badge_text:
            self.badge_label.setText(badge_text)
            self.badge_label.setStyleSheet(
                f"background:{badge_bg};color:{badge_fg};"
                "border-radius:12px;padding:6px 10px;font-weight:800;"
            )
            self.badge_label.setVisible(True)
        else:
            self.badge_label.setVisible(False)

    def set_selected(self, selected):
        if selected:
            self.setStyleSheet(
                "QFrame {"
                "background:#eef5ff;"
                "border:2px solid #7ea8e6;"
                "border-radius:22px;"
                "}"
            )
        else:
            self.setStyleSheet(
                "QFrame {"
                "background:#ffffff;"
                "border:1px solid #d4e2f7;"
                "border-radius:22px;"
                "}"
            )

BUILTIN_TEMPLATE_DEFS = [
    {
        "id": "builtin_deskcollection_id",
        "name": "[System] Desk Collection - Tagihan Tertunggak",
        "content": (
            "Yth. ${name},\n\n"
            "Kami dari Desk Collection PT Pendanaan Teknologi Nusa menginformasikan bahwa terdapat "
            "kewajiban pembayaran yang telah jatuh tempo sebesar Rp ${data1}.\n"
            "Mohon melakukan pembayaran sebelum ${data2}.\n\n"
            "Jika pembayaran sudah dilakukan, mohon abaikan pesan ini atau kirimkan bukti pembayaran "
            "agar dapat segera kami bantu pengecekannya.\n\n"
            "Terima kasih."
        ),
        "attachment_path": "",
        "updated_at": "System Built-in"
    },
    {
        "id": "builtin_cashier_receipt_id",
        "name": "[System] Cashier - Tagihan / Kuitansi",
        "content": (
            "Yth. ${name},\n\n"
            "Berikut kami kirimkan rincian tagihan / kuitansi Anda:\n"
            "Nomor invoice: ${data1}\n"
            "Nominal: Rp ${data2}\n"
            "Jatuh tempo: ${data3}\n\n"
            "Apabila pembayaran sudah dilakukan, mohon kirimkan bukti pembayaran kepada kami.\n\n"
            "Terima kasih."
        ),
        "attachment_path": "",
        "updated_at": "System Built-in"
    }
]

DEFAULT_BUILTIN_TEMPLATE_ENABLED = {
    str(item["id"]): True
    for item in BUILTIN_TEMPLATE_DEFS
}

TEMPLATE_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png"}


def normalize_template_attachment_path(value):
    raw = str(value or "").strip()
    if not raw:
        return ""

    try:
        return os.path.abspath(os.path.expanduser(raw))
    except Exception:
        return raw


def is_supported_template_image_path(path, require_exists=True):
    normalized = normalize_template_attachment_path(path)
    if not normalized:
        return False

    ext = os.path.splitext(normalized)[1].lower()
    if ext not in TEMPLATE_IMAGE_EXTENSIONS:
        return False

    if require_exists and not os.path.exists(normalized):
        return False

    return True


def format_template_attachment_label(path):
    normalized = normalize_template_attachment_path(path)
    if not normalized:
        return "No image attachment"

    label = os.path.basename(normalized) or normalized
    if os.path.exists(normalized):
        return label
    return f"{label} (missing)"

def clean_cell_value(value):
    if value is None:
        return None

    try:
        if pd.isna(value):
            return None
    except Exception:
        pass

    s = str(value).strip()
    if not s:
        return None

    if s.lower() in {"nan", "none", "null"}:
        return None

    # Excel sometimes turns numbers into "6281234567890.0"
    if re.fullmatch(r"\d+\.0+", s):
        s = s.split(".", 1)[0]

    return s


def read_recipients_from_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".csv":
        df = pd.read_csv(file_path, dtype=str, keep_default_na=False)
    elif ext in (".xlsx", ".xls"):
        df = pd.read_excel(file_path, dtype=str).fillna("")
    else:
        raise ValueError("Only .csv, .xlsx, and .xls files are supported.")

    if df.shape[1] < 1:
        raise ValueError("The file must contain at least 1 column for phone number.")

    recipients = []
    invalid = []

    # pandas already uses row 1 as header, so first data row is Excel row 2
    for row_idx, row in df.iterrows():
        excel_row_no = row_idx + 2

        raw_phone = clean_cell_value(row.iloc[0] if len(row) >= 1 else None)
        send_number, display_number = normalize_indonesia_mobile(raw_phone)

        if not send_number:
            invalid.append((excel_row_no, raw_phone or ""))
            continue

        name = clean_cell_value(row.iloc[1] if len(row) >= 2 else None)

        template_vars = {
            "name": name or "NULL"
        }

        # Column 3 => data1, column 4 => data2, ...
        for col_idx in range(2, len(row)):
            key = f"data{col_idx - 1}"   # index 2 -> data1
            value = clean_cell_value(row.iloc[col_idx])
            template_vars[key] = value or "NULL"

        recipients.append({
            "source_row": excel_row_no,
            "mobile_raw": raw_phone or "",
            "send_number": send_number,
            "display_number": display_number,
            "name": name,
            "template_vars": template_vars
        })

    return recipients, invalid


def render_message_template(template, recipient, global_values=None):
    values = build_template_render_values(recipient, global_values=global_values)

    def repl(match):
        key = match.group(1).strip()
        value = values.get(key)
        if value is None:
            return "NULL"
        text = str(value).strip()
        return text if text else "NULL"

    return PLACEHOLDER_RE.sub(repl, str(template or ""))


def build_bulk_recipients(selected_items, template_text, bad_words=None, global_values=None):
    recipients = []

    for item in (selected_items or []):
        if isinstance(item, dict):
            send_number = str(item.get("send_number") or "").strip()
            display_number = str(item.get("display_number") or send_number).strip()
            name = item.get("name")
            template_vars = dict(item.get("template_vars") or {})
            source_row = item.get("source_row")
        else:
            raw = str(item or "").strip()
            send_number, display_number = normalize_indonesia_mobile(raw)

            if not send_number:
                send_number = normalize_phone_number(raw).lstrip("+")
                display_number = raw or send_number

            name = None
            template_vars = {}
            source_row = None

        recipient_data = apply_template_global_values_to_recipient({
            "send_number": send_number,
            "display_number": display_number,
            "name": name,
            "template_vars": template_vars
        }, global_values=global_values)

        rendered_message = render_message_template(
            template_text,
            recipient_data,
            global_values=global_values
        )

        masked_message, bad_word_hits = mask_bad_words(rendered_message, bad_words or [])

        recipients.append({
            "source_row": source_row,
            "send_number": send_number,
            "display_number": display_number,
            "name": recipient_data.get("name"),
            "template_vars": dict(recipient_data.get("template_vars") or {}),
            "message": masked_message,
            "bad_word_hits": list(bad_word_hits),
            "bad_words": sorted(set(bad_word_hits))
        })

    return recipients


def _bulk_recipient_identity_key(item):
    candidate = dict(item or {})
    return normalize_chat_key(
        candidate.get("send_number") or
        candidate.get("display_number") or
        candidate.get("phone") or
        candidate.get("number")
    )


def _bulk_recipient_detail_score(item):
    candidate = dict(item or {})
    score = 0

    if str(candidate.get("source_row") or "").strip():
        score += 1

    if not is_missing_template_value(candidate.get("name")):
        score += 2

    if str(candidate.get("display_number") or "").strip():
        score += 1

    for value in dict(candidate.get("template_vars") or {}).values():
        if not is_missing_template_value(value):
            score += 1

    return score


def _merge_bulk_recipient_record(primary, secondary):
    merged = dict(primary or {})
    other = dict(secondary or {})

    if not str(merged.get("send_number") or "").strip():
        merged["send_number"] = _bulk_recipient_identity_key(other) or str(other.get("send_number") or "").strip()

    if not str(merged.get("display_number") or "").strip():
        merged["display_number"] = str(other.get("display_number") or other.get("send_number") or "").strip()

    if is_missing_template_value(merged.get("name")) and not is_missing_template_value(other.get("name")):
        merged["name"] = other.get("name")

    if not merged.get("source_row") and other.get("source_row"):
        merged["source_row"] = other.get("source_row")

    merged_vars = dict(merged.get("template_vars") or {})
    for key, value in dict(other.get("template_vars") or {}).items():
        if key not in merged_vars or is_missing_template_value(merged_vars.get(key)):
            merged_vars[key] = value
    merged["template_vars"] = merged_vars

    return merged


def dedupe_bulk_recipients(items):
    ordered_keys = []
    unique_map = {}
    duplicate_count = 0

    for item in items or []:
        candidate = dict(item or {})
        key = _bulk_recipient_identity_key(candidate)
        if not key:
            continue

        candidate["send_number"] = key
        if not str(candidate.get("display_number") or "").strip():
            candidate["display_number"] = str(item.get("display_number") or key)

        if key not in unique_map:
            unique_map[key] = candidate
            ordered_keys.append(key)
            continue

        duplicate_count += 1
        existing = unique_map[key]
        if _bulk_recipient_detail_score(candidate) > _bulk_recipient_detail_score(existing):
            unique_map[key] = _merge_bulk_recipient_record(candidate, existing)
        else:
            unique_map[key] = _merge_bulk_recipient_record(existing, candidate)

    return [unique_map[k] for k in ordered_keys], duplicate_count


def normalize_name_key(value):
    return re.sub(r"\s+", " ", str(value or "").strip()).lower()


def find_last_blast_recipient_for_chat(chat_context, last_blast=None):
    chat_context = dict(chat_context or {})
    last_blast = last_blast or load_last_blast()
    recipients = list(last_blast.get("recipients") or [])

    chat_phone = normalize_chat_key(
        chat_context.get("phone") or chat_context.get("conversation_key")
    )
    chat_name_key = normalize_name_key(chat_context.get("title"))

    for rec in recipients:
        rec_phone = normalize_chat_key(
            rec.get("send_number") or rec.get("display_number") or rec.get("mobile_raw")
        )
        if chat_phone and rec_phone and chat_phone == rec_phone:
            return dict(rec)

    for rec in recipients:
        vars_map = dict(rec.get("template_vars") or {})
        candidate_names = [
            rec.get("name"),
            vars_map.get("name")
        ]
        for candidate in candidate_names:
            if chat_name_key and normalize_name_key(candidate) == chat_name_key:
                return dict(rec)

    return None


def build_reply_template_recipient(chat_context, matched_recipient=None):
    chat_context = dict(chat_context or {})
    matched_recipient = dict(matched_recipient or {})
    template_vars = dict(matched_recipient.get("template_vars") or {})

    chat_title = str(chat_context.get("title") or "").strip()
    chat_phone = str(chat_context.get("phone") or "").strip()
    display_phone = str(chat_context.get("display_phone") or chat_phone).strip()

    name = clean_cell_value(matched_recipient.get("name"))
    if not name:
        name = clean_cell_value(template_vars.get("name"))
    if not name and chat_title and normalize_name_key(chat_title) != normalize_name_key(chat_phone):
        name = chat_title

    if name:
        template_vars["name"] = name
    else:
        template_vars.setdefault("name", "NULL")

    if chat_phone:
        template_vars["phone"] = chat_phone
    else:
        template_vars.setdefault("phone", matched_recipient.get("send_number") or "NULL")

    return {
        "send_number": chat_phone or matched_recipient.get("send_number") or "",
        "display_number": display_phone or matched_recipient.get("display_number") or "",
        "name": name,
        "template_vars": template_vars
    }

def is_lark_host(host):
    host = (host or "").lower().strip()
    return (
        host == "larksuite.com" or host.endswith(".larksuite.com") or
        host == "feishu.cn" or host.endswith(".feishu.cn")
    )

def append_network_logs(entries):
    if not entries:
        return
    log = load_network_log()
    log.extend(entries)
    with open(NETWORK_LOG_FILE, "wb") as f:
        f.write(encrypt_data(log))

def is_scalar(value):
    return value is None or isinstance(value, (str, int, float, bool))


def summarize_value(value):
    if value is None:
        return ""
    if isinstance(value, dict):
        return f"{{{len(value)} fields}}"
    if isinstance(value, list):
        if all(isinstance(x, dict) for x in value):
            return f"[{len(value)} objects]"
        return f"[{len(value)} items]"
    return str(value)


def flatten_scalars(data, parent_key="", sep="."):
    out = {}
    if not isinstance(data, dict):
        return {"value": summarize_value(data)}

    for k, v in data.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
        if is_scalar(v):
            out[new_key] = v
        elif isinstance(v, dict):
            nested_scalars = flatten_scalars(v, new_key, sep=sep)
            out.update(nested_scalars)
        else:
            # list / non-scalar object becomes summary only in main table
            out[new_key] = summarize_value(v)
    return out


def extract_nested_parts(data, parent_key=""):
    """
    Return:
      objects: dict[path -> dict]
      tables: dict[path -> list[dict] or list[scalar]]
    """
    objects = {}
    tables = {}

    if isinstance(data, dict):
        for k, v in data.items():
            new_key = f"{parent_key}.{k}" if parent_key else str(k)
            if isinstance(v, dict):
                objects[new_key] = v
                child_objects, child_tables = extract_nested_parts(v, new_key)
                objects.update(child_objects)
                tables.update(child_tables)
            elif isinstance(v, list):
                tables[new_key] = v
                for idx, item in enumerate(v):
                    if isinstance(item, dict):
                        child_objects, child_tables = extract_nested_parts(item, f"{new_key}[{idx}]")
                        objects.update(child_objects)
                        tables.update(child_tables)
    return objects, tables


def find_table_candidates(payload, path="root"):
    candidates = []

    if isinstance(payload, list):
        if payload and all(isinstance(item, dict) for item in payload):
            candidates.append((path, payload))
        for i, item in enumerate(payload):
            candidates.extend(find_table_candidates(item, f"{path}[{i}]"))

    elif isinstance(payload, dict):
        for k, v in payload.items():
            child_path = f"{path}.{k}" if path else k
            candidates.extend(find_table_candidates(v, child_path))

    return candidates


def choose_primary_table(payload):
    """
    Prefer the largest list[dict] found anywhere in the response.
    Fallback to payload itself if it is a dict/list.
    """
    candidates = find_table_candidates(payload)
    if candidates:
        candidates.sort(key=lambda x: len(x[1]), reverse=True)
        return candidates[0][0], candidates[0][1]

    if isinstance(payload, dict):
        return "root", [payload]
    if isinstance(payload, list):
        return "root", [{"value": x} for x in payload]
    return "root", [{"value": payload}]

# --------------------------
# Encryption helpers
# --------------------------
def get_or_create_key():
    """Load existing key or generate a new one."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return Fernet(key)

def get_or_create_filenames():
    global HISTORY_FILE, NETWORK_LOG_FILE, LAST_BLAST_FILE, MANUAL_SEND_LOG_FILE

    os.makedirs(H_DIR, exist_ok=True)

    names = {}
    if os.path.exists(FILES_CONFIG):
        try:
            with open(FILES_CONFIG, "r", encoding="utf-8") as f:
                names = json.load(f)
        except Exception:
            names = {}

    changed = False

    def anon_name():
        return uuid.uuid4().hex[:18] + ".dat"

    if "history" not in names:
        names["history"] = anon_name()
        changed = True

    if "network" not in names:
        names["network"] = anon_name()
        changed = True

    if "last_blast" not in names:
        names["last_blast"] = anon_name()
        changed = True

    if "manual_send" not in names:
        names["manual_send"] = anon_name()
        changed = True

    HISTORY_FILE = os.path.join(H_DIR, names["history"])
    NETWORK_LOG_FILE = os.path.join(H_DIR, names["network"])
    LAST_BLAST_FILE = os.path.join(H_DIR, names["last_blast"])
    MANUAL_SEND_LOG_FILE = os.path.join(H_DIR, names["manual_send"])

    if changed or not os.path.exists(FILES_CONFIG):
        with open(FILES_CONFIG, "w", encoding="utf-8") as f:
            json.dump(names, f)

# Initialize encryption and filenames at module level
fernet = get_or_create_key()
get_or_create_filenames()

def encrypt_data(data):
    """Encrypt a Python object and return bytes."""
    json_str = json.dumps(data, indent=2)
    return fernet.encrypt(json_str.encode())

def decrypt_data(encrypted_bytes):
    """Decrypt bytes and return Python object."""
    decrypted = fernet.decrypt(encrypted_bytes)
    return json.loads(decrypted.decode())

# --------------------------
# History helpers (encrypted)
# --------------------------
def load_bad_words():
    source_path = BAD_WORDS_FILE if os.path.exists(BAD_WORDS_FILE) else DEFAULT_BAD_WORDS_FILE
    if not os.path.exists(source_path):
        return []

    words = []
    seen = set()

    try:
        with open(source_path, "r", encoding="utf-8-sig") as f:
            for line in f:
                w = line.strip().lower()
                if not w or w.startswith("#"):
                    continue
                if w not in seen:
                    seen.add(w)
                    words.append(w)
    except Exception as e:
        print("Failed to load bad words:", e)
        return []

    return words


def mask_bad_words(text, bad_words=None):
    text = str(text or "")
    bad_words = [str(x).strip().lower() for x in (bad_words or []) if str(x).strip()]
    if not text or not bad_words:
        return text, []

    escaped = [re.escape(w) for w in sorted(set(bad_words), key=len, reverse=True)]
    if not escaped:
        return text, []

    pattern = re.compile(r"\b(" + "|".join(escaped) + r")\b", re.IGNORECASE)
    hits = []

    def repl(match):
        found = match.group(0)
        hits.append(found.lower())
        return "*" * len(found)

    masked = pattern.sub(repl, text)
    return masked, hits


def load_bad_word_counter():
    if os.path.exists(BAD_WORD_COUNTER_FILE):
        try:
            with open(BAD_WORD_COUNTER_FILE, "rb") as f:
                encrypted = f.read()
            return decrypt_data(encrypted)
        except Exception:
            return {"days": {}}
    return {"days": {}}


def save_bad_word_counter(data):
    with open(BAD_WORD_COUNTER_FILE, "wb") as f:
        f.write(encrypt_data(data))


def clear_bad_word_counter():
    save_bad_word_counter({"days": {}})


def increment_bad_word_counter(
    hit_words,
    source="unknown",
    when_dt=None,
    sender="",
    receiver="",
    message_preview="",
    trigger="",
    send_type=""
):
    hit_words = [str(x).strip().lower() for x in (hit_words or []) if str(x).strip()]
    if not hit_words:
        return

    if when_dt is None:
        when_dt = datetime.datetime.now(USER_TIMEZONE)

    user_dt = ensure_user_datetime(when_dt) or datetime.datetime.now(USER_TIMEZONE)
    day_key = user_dt.strftime("%Y-%m-%d")
    sender = str(sender or "").strip()
    receiver = str(receiver or "").strip()
    trigger = str(trigger or "").strip()
    send_type = str(send_type or "").strip()
    preview = str(message_preview or "").strip()
    if len(preview) > 240:
        preview = preview[:239] + "…"

    data = load_bad_word_counter()
    days = data.setdefault("days", {})
    bucket = days.setdefault(day_key, {
        "events": 0,
        "total_hits": 0,
        "by_word": {},
        "by_source": {},
        "by_sender": {},
        "by_receiver": {},
        "event_details": []
    })

    bucket.setdefault("by_word", {})
    bucket.setdefault("by_source", {})
    bucket.setdefault("by_sender", {})
    bucket.setdefault("by_receiver", {})
    bucket.setdefault("event_details", [])

    bucket["events"] += 1
    bucket["total_hits"] += len(hit_words)
    bucket["by_source"][source] = bucket["by_source"].get(source, 0) + len(hit_words)
    if sender:
        bucket["by_sender"][sender] = bucket["by_sender"].get(sender, 0) + len(hit_words)
    if receiver:
        bucket["by_receiver"][receiver] = bucket["by_receiver"].get(receiver, 0) + len(hit_words)

    for word in hit_words:
        bucket["by_word"][word] = bucket["by_word"].get(word, 0) + 1

    detail = {
        "timestamp": user_dt.isoformat(),
        "source": source,
        "sender": sender,
        "receiver": receiver,
        "message_preview": preview,
        "bad_word_count": len(hit_words),
        "bad_words": sorted(set(hit_words)),
        "bad_word_hits": list(hit_words),
        "trigger": trigger,
        "send_type": send_type
    }
    bucket["event_details"].insert(0, detail)
    if len(bucket["event_details"]) > 400:
        bucket["event_details"] = bucket["event_details"][:400]

    save_bad_word_counter(data)

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "rb") as f:
                encrypted = f.read()
            return decrypt_data(encrypted)
        except Exception:
            return []
    return []

def save_history(entry):
    hist = load_history()
    hist.append(entry)
    with open(HISTORY_FILE, "wb") as f:
        f.write(encrypt_data(hist))


def build_whatsapp_history_signature(
    conversation_key,
    direction,
    timestamp_text,
    content,
    has_attachment=False,
    author=""
):
    key = normalize_chat_key(conversation_key)
    if not key:
        return ""

    ts_text = format_user_datetime_text(
        timestamp_text,
        default=str(timestamp_text or "").strip()
    )
    body = str(content or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    author_text = str(author or "").strip().lower()
    direction_text = str(direction or "").strip().lower()

    return "||".join([
        key,
        direction_text,
        ts_text,
        body,
        "1" if has_attachment else "0",
        author_text
    ])


def derive_whatsapp_history_signature_from_log_item(item):
    if not isinstance(item, dict):
        return ""

    send_type = str(item.get("send_type") or "").strip()

    if send_type in {"incoming_reply", "sync_incoming"}:
        direction = "incoming"
        conversation_key = (
            item.get("conversation_key")
            or item.get("from_phone")
            or item.get("chat_label")
            or item.get("from")
        )
        author = item.get("from_display") or item.get("message_author") or ""
    else:
        direction = "outgoing"
        conversation_key = (
            item.get("conversation_key")
            or item.get("to_phone")
            or item.get("chat_label")
            or item.get("to")
        )
        author = item.get("message_author") or ""

    return build_whatsapp_history_signature(
        conversation_key=conversation_key,
        direction=direction,
        timestamp_text=item.get("timestamp"),
        content=item.get("content"),
        has_attachment=bool(item.get("has_attachment")),
        author=author
    )

def load_network_log():
    if os.path.exists(NETWORK_LOG_FILE):
        try:
            with open(NETWORK_LOG_FILE, "rb") as f:
                encrypted = f.read()
            return decrypt_data(encrypted)
        except Exception:
            return []
    return []

def save_network_log(entry):
    log = load_network_log()
    log.append(entry)
    with open(NETWORK_LOG_FILE, "wb") as f:
        f.write(encrypt_data(log))

def normalize_saved_recipient(rec):
    if isinstance(rec, dict):
        send_number = str(rec.get("send_number") or "").strip()
        display_number = str(rec.get("display_number") or send_number).strip()
        name = clean_cell_value(rec.get("name"))
        source_row = rec.get("source_row")
        mobile_raw = str(rec.get("mobile_raw") or "").strip()

        template_vars = rec.get("template_vars") or {}
        safe_vars = {}
        if isinstance(template_vars, dict):
            for k, v in template_vars.items():
                key = str(k).strip()
                if not key:
                    continue
                safe_vars[key] = clean_cell_value(v) or "NULL"

        if not send_number:
            raw = mobile_raw or display_number
            send_number, display_number = normalize_indonesia_mobile(raw)
            if not send_number:
                send_number = normalize_phone_number(raw).lstrip("+")
                display_number = raw or send_number

        if not send_number:
            return None

        safe_vars.setdefault("name", name or "NULL")

        return {
            "source_row": source_row,
            "mobile_raw": mobile_raw,
            "send_number": send_number,
            "display_number": display_number or send_number,
            "name": name,
            "template_vars": safe_vars
        }

    raw = str(rec or "").strip()
    if not raw:
        return None

    send_number, display_number = normalize_indonesia_mobile(raw)
    if not send_number:
        send_number = normalize_phone_number(raw).lstrip("+")
        display_number = raw or send_number

    if not send_number:
        return None

    return {
        "source_row": None,
        "mobile_raw": raw,
        "send_number": send_number,
        "display_number": display_number or send_number,
        "name": None,
        "template_vars": {"name": "NULL"}
    }


def normalize_last_blast_payload(payload):
    result = {
        "recipients": [],
        "numbers": [],
        "message": "",
        "attachment_path": "",
        "updated_at": ""
    }

    if not isinstance(payload, dict):
        return result

    result["message"] = str(payload.get("message") or "")
    result["attachment_path"] = normalize_template_attachment_path(payload.get("attachment_path"))
    result["updated_at"] = str(payload.get("updated_at") or "")

    source_recipients = payload.get("recipients")
    if not isinstance(source_recipients, list) or not source_recipients:
        source_recipients = payload.get("numbers") or []

    normalized = []
    seen = set()

    for rec in source_recipients:
        item = normalize_saved_recipient(rec)
        if not item:
            continue

        key = (item.get("send_number"), item.get("source_row"))
        if key in seen:
            continue
        seen.add(key)
        normalized.append(item)

    result["recipients"] = normalized
    result["numbers"] = [x["send_number"] for x in normalized]
    return result


def load_last_blast():
    if os.path.exists(LAST_BLAST_FILE):
        try:
            with open(LAST_BLAST_FILE, "rb") as f:
                encrypted = f.read()
            payload = decrypt_data(encrypted)
            return normalize_last_blast_payload(payload)
        except Exception:
            return {
                "recipients": [],
                "numbers": [],
                "message": "",
                "attachment_path": "",
                "updated_at": ""
            }

    return {
        "recipients": [],
        "numbers": [],
        "message": "",
        "attachment_path": "",
        "updated_at": ""
    }


def save_last_blast(recipients, message, attachment_path=""):
    normalized = []
    seen = set()

    for rec in (recipients or []):
        item = normalize_saved_recipient(rec)
        if not item:
            continue

        key = (item.get("send_number"), item.get("source_row"))
        if key in seen:
            continue
        seen.add(key)
        normalized.append(item)

    payload = {
        "recipients": normalized,
        "numbers": [x["send_number"] for x in normalized],
        "message": message or "",
        "attachment_path": normalize_template_attachment_path(attachment_path),
        "updated_at": datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    }

    with open(LAST_BLAST_FILE, "wb") as f:
        f.write(encrypt_data(payload))

def load_manual_send_log():
    if os.path.exists(MANUAL_SEND_LOG_FILE):
        try:
            with open(MANUAL_SEND_LOG_FILE, "rb") as f:
                encrypted = f.read()
            return decrypt_data(encrypted)
        except Exception:
            return []
    return []


def write_manual_send_log(log_entries):
    with open(MANUAL_SEND_LOG_FILE, "wb") as f:
        f.write(encrypt_data(list(log_entries or [])))

def is_builtin_template_id(tpl_id):
    tpl_id = str(tpl_id or "").strip()
    if not tpl_id:
        return False
    return any(str(item.get("id")) == tpl_id for item in BUILTIN_TEMPLATE_DEFS)


def get_builtin_template_enabled_map():
    state = load_app_state()
    stored = state.get("builtin_templates_enabled") or {}
    enabled_map = dict(DEFAULT_BUILTIN_TEMPLATE_ENABLED)

    if isinstance(stored, dict):
        for key, value in stored.items():
            enabled_map[str(key)] = bool(value)

    return enabled_map


def set_builtin_template_enabled(template_id, enabled):
    template_id = str(template_id or "").strip()
    if not template_id:
        return

    state = load_app_state()
    enabled_map = dict(DEFAULT_BUILTIN_TEMPLATE_ENABLED)
    stored = state.get("builtin_templates_enabled") or {}
    if isinstance(stored, dict):
        for key, value in stored.items():
            enabled_map[str(key)] = bool(value)

    enabled_map[template_id] = bool(enabled)
    state["builtin_templates_enabled"] = enabled_map
    save_app_state(state)


def get_builtin_templates(include_disabled=False):
    enabled_map = get_builtin_template_enabled_map()
    items = []

    for item in BUILTIN_TEMPLATE_DEFS:
        tpl = {
            "id": str(item.get("id") or ""),
            "name": str(item.get("name") or "").strip(),
            "content": str(item.get("content") or "").rstrip(),
            "attachment_path": normalize_template_attachment_path(item.get("attachment_path")),
            "updated_at": str(item.get("updated_at") or "System Built-in"),
            "builtin": True,
            "enabled": bool(enabled_map.get(str(item.get("id")), True))
        }

        if not tpl["enabled"] and not include_disabled:
            continue
        if not tpl["name"] or not tpl["content"]:
            continue
        items.append(tpl)

    items.sort(key=lambda x: x["name"].lower())
    return items


def load_user_templates():
    if os.path.exists(TEMPLATES_FILE):
        try:
            with open(TEMPLATES_FILE, "rb") as f:
                encrypted = f.read()
            data = decrypt_data(encrypted)
        except Exception:
            return []
    else:
        return []

    if not isinstance(data, list):
        return []

    cleaned = []
    seen = set()

    for item in data:
        if not isinstance(item, dict):
            continue

        tpl_id = str(item.get("id") or uuid.uuid4().hex)
        name = str(item.get("name") or "").strip()
        content = str(item.get("content") or "").rstrip()
        attachment_path = normalize_template_attachment_path(item.get("attachment_path"))
        updated_at = str(item.get("updated_at") or "")

        if not name or not content:
            continue

        key = name.lower()
        if key in seen:
            continue
        seen.add(key)

        cleaned.append({
            "id": tpl_id,
            "name": name,
            "content": content,
            "attachment_path": attachment_path,
            "updated_at": updated_at,
            "builtin": False,
            "enabled": True
        })

    cleaned.sort(key=lambda x: x["name"].lower())
    return cleaned


def load_templates(include_disabled_builtin=False):
    combined = []
    seen = set()

    for tpl in get_builtin_templates(include_disabled=include_disabled_builtin) + load_user_templates():
        key = str(tpl.get("name") or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        combined.append(dict(tpl))

    combined.sort(key=lambda x: x["name"].lower())
    return combined


def save_templates(templates):
    cleaned = []
    seen = set()

    for item in (templates or []):
        if not isinstance(item, dict):
            continue
        if is_builtin_template_id(item.get("id")) or bool(item.get("builtin")):
            continue

        tpl_id = str(item.get("id") or uuid.uuid4().hex)
        name = str(item.get("name") or "").strip()
        content = str(item.get("content") or "").rstrip()
        attachment_path = normalize_template_attachment_path(item.get("attachment_path"))
        updated_at = str(item.get("updated_at") or datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"))

        if not name or not content:
            continue

        key = name.lower()
        if key in seen:
            continue
        seen.add(key)

        cleaned.append({
            "id": tpl_id,
            "name": name,
            "content": content,
            "attachment_path": attachment_path,
            "updated_at": updated_at,
            "builtin": False,
            "enabled": True
        })

    cleaned.sort(key=lambda x: x["name"].lower())

    with open(TEMPLATES_FILE, "wb") as f:
        f.write(encrypt_data(cleaned))

# --------------------------
# Contact management helpers
# --------------------------
def contact_now():
    return datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")


def contact_safe_text(value):
    return str(value or "").strip()


def normalize_contact_phone(raw):
    return normalize_contact_identifier(raw)


def format_contact_display_number(raw):
    send_number, display_number = normalize_indonesia_mobile(raw)
    if display_number:
        return display_number

    digits = normalize_phone_number(raw).lstrip("+")
    return digits or str(raw or "")


def build_contact_search_blob(contact):
    parts = [
        contact.get("name", ""),
        contact.get("send_number", ""),
        contact.get("display_number", ""),
        contact.get("email", ""),
        contact.get("company", ""),
        contact.get("title", ""),
        contact.get("city", ""),
        contact.get("summary", ""),
        contact.get("details", ""),
        contact.get("tags", ""),
        contact.get("last_message_preview", ""),
    ]
    return " ".join(str(x or "") for x in parts).lower()


def normalize_contact_record(item):
    item = dict(item or {})

    send_number = normalize_contact_phone(
        item.get("send_number") or item.get("display_number") or item.get("phone")
    )
    display_number = contact_safe_text(item.get("display_number")) or format_contact_display_number(send_number)

    color_flag = contact_safe_text(item.get("color_flag")).lower()
    if color_flag not in CONTACT_FLAG_META:
        color_flag = "none"

    timeline = item.get("timeline") or []
    if not isinstance(timeline, list):
        timeline = []

    safe_timeline = []
    for row in timeline:
        if not isinstance(row, dict):
            continue
        safe_timeline.append({
            "id": str(row.get("id") or uuid.uuid4().hex[:12]),
            "timestamp": normalize_contact_timestamp_text(row.get("timestamp")),
            "type": str(row.get("type") or "note"),
            "actor": str(row.get("actor") or "user"),
            "text": str(row.get("text") or "").strip()
        })

    latest_import_vars = item.get("latest_import_vars") or {}
    if not isinstance(latest_import_vars, dict):
        latest_import_vars = {}

    safe_import_vars = {}
    for k, v in latest_import_vars.items():
        key = str(k).strip()
        if not key:
            continue
        safe_import_vars[key] = str(v or "").strip()

    return {
        "id": str(item.get("id") or uuid.uuid4().hex),
        "send_number": send_number or "",
        "display_number": display_number or "",
        "name": str(item.get("name") or "").strip(),
        "email": str(item.get("email") or "").strip(),
        "company": str(item.get("company") or "").strip(),
        "title": str(item.get("title") or "").strip(),
        "city": str(item.get("city") or "").strip(),
        "summary": str(item.get("summary") or "").strip(),
        "details": str(item.get("details") or "").strip(),
        "tags": str(item.get("tags") or "").strip(),
        "color_flag": color_flag,
        "source": str(item.get("source") or "").strip(),
        "created_at": str(item.get("created_at") or contact_now()),
        "updated_at": str(item.get("updated_at") or contact_now()),
        "last_import_at": str(item.get("last_import_at") or ""),
        "last_import_source": str(item.get("last_import_source") or ""),
        "latest_import_vars": safe_import_vars,
        "last_chat_at": normalize_optional_contact_timestamp(item.get("last_chat_at")),
        "last_outgoing_at": normalize_optional_contact_timestamp(item.get("last_outgoing_at")),
        "last_incoming_at": normalize_optional_contact_timestamp(item.get("last_incoming_at")),
        "last_message_preview": str(item.get("last_message_preview") or "").strip(),
        "timeline": safe_timeline[-500:]
    }


def load_contacts():
    if os.path.exists(CONTACTS_FILE):
        try:
            with open(CONTACTS_FILE, "rb") as f:
                encrypted = f.read()
            data = decrypt_data(encrypted)
            if isinstance(data, list):
                return [normalize_contact_record(x) for x in data]
        except Exception:
            pass
    return []


def save_contacts(contacts):
    cleaned = []
    seen = set()

    for row in (contacts or []):
        if not isinstance(row, dict):
            continue

        contact = normalize_contact_record(row)
        key = normalize_contact_phone(contact.get("send_number"))

        if not key:
            continue
        if key in seen:
            continue

        seen.add(key)
        contact["send_number"] = key
        contact["display_number"] = contact.get("display_number") or format_contact_display_number(key)
        contact["updated_at"] = contact_safe_text(contact.get("updated_at")) or contact_now()

        cleaned.append(contact)

    cleaned.sort(key=lambda x: ((x.get("name") or "").lower(), x.get("send_number") or ""))

    with open(CONTACTS_FILE, "wb") as f:
        f.write(encrypt_data(cleaned))


def find_contact_index(contacts, send_number):
    key = normalize_contact_phone(send_number)
    if not key:
        return -1, None

    for i, row in enumerate(contacts):
        row_key = normalize_contact_phone(row.get("send_number"))
        if row_key == key:
            return i, row
    return -1, None


def append_contact_timeline_entry(contact, entry_type, text, actor="user", when_text=None):
    text = str(text or "").strip()
    if not text:
        return

    timeline = list(contact.get("timeline") or [])
    timeline.append({
        "id": uuid.uuid4().hex[:12],
        "timestamp": str(when_text or contact_now()),
        "type": str(entry_type or "note"),
        "actor": str(actor or "user"),
        "text": text
    })
    contact["timeline"] = timeline[-500:]


def ensure_contact(send_number, display_number=None, suggested_name=None, source="", imported_vars=None):
    key = normalize_contact_phone(send_number or display_number)
    if not key:
        return None

    contacts = load_contacts()
    idx, existing = find_contact_index(contacts, key)
    now_text = contact_now()
    created = False

    if existing is None:
        contact = normalize_contact_record({
            "send_number": key,
            "display_number": display_number or format_contact_display_number(key),
            "name": suggested_name or "",
            "source": source or "system",
            "created_at": now_text,
            "updated_at": now_text
        })
        append_contact_timeline_entry(
            contact,
            "system",
            f"Contact created from {source or 'system'}.",
            actor="system",
            when_text=now_text
        )
        contacts.append(contact)
        created = True
    else:
        contact = existing

    if suggested_name and not contact.get("name"):
        contact["name"] = str(suggested_name).strip()

    if display_number:
        contact["display_number"] = str(display_number).strip()

    if source:
        contact["source"] = str(source).strip()

    if isinstance(imported_vars, dict) and imported_vars:
        clean_vars = {}
        for k, v in imported_vars.items():
            key_name = str(k).strip()
            if not key_name:
                continue
            clean_vars[key_name] = str(v or "").strip()

        contact["latest_import_vars"] = clean_vars
        contact["last_import_at"] = now_text
        contact["last_import_source"] = str(source or "import").strip()

    contact["updated_at"] = now_text
    save_contacts(contacts)
    return contact


def import_contacts_from_recipients(recipients, source_name="Excel import"):
    contacts = load_contacts()
    changed = False
    now_text = contact_now()

    for rec in (recipients or []):
        if not isinstance(rec, dict):
            continue

        send_number = normalize_contact_phone(rec.get("send_number") or rec.get("display_number") or rec.get("mobile_raw"))
        if not send_number:
            continue

        display_number = rec.get("display_number") or format_contact_display_number(send_number)
        suggested_name = rec.get("name") or ""
        template_vars = dict(rec.get("template_vars") or {})
        source_row = rec.get("source_row")

        idx, contact = find_contact_index(contacts, send_number)

        if contact is None:
            contact = normalize_contact_record({
                "send_number": send_number,
                "display_number": display_number,
                "name": suggested_name,
                "source": "excel_import",
                "created_at": now_text,
                "updated_at": now_text
            })
            append_contact_timeline_entry(
                contact,
                "import",
                f"Imported from {source_name}" + (f" (row {source_row})" if source_row else "") + ".",
                actor="system",
                when_text=now_text
            )
            contacts.append(contact)
            changed = True
        else:
            if suggested_name and not contact.get("name"):
                contact["name"] = str(suggested_name).strip()
                changed = True

            append_contact_timeline_entry(
                contact,
                "import",
                f"Refreshed from {source_name}" + (f" (row {source_row})" if source_row else "") + ".",
                actor="system",
                when_text=now_text
            )
            changed = True

        contact["display_number"] = str(display_number).strip()
        contact["latest_import_vars"] = {str(k): str(v or "").strip() for k, v in template_vars.items()}
        contact["last_import_at"] = now_text
        contact["last_import_source"] = str(source_name)
        contact["updated_at"] = now_text

    if changed:
        save_contacts(contacts)


def append_contact_note(send_number, note_text, entry_type="note", actor="user"):
    key = normalize_contact_phone(send_number)
    if not key:
        return False

    contacts = load_contacts()
    idx, contact = find_contact_index(contacts, key)
    if contact is None:
        contact = normalize_contact_record({
            "send_number": key,
            "display_number": format_contact_display_number(key),
            "created_at": contact_now(),
            "updated_at": contact_now()
        })
        contacts.append(contact)

    append_contact_timeline_entry(contact, entry_type, note_text, actor=actor, when_text=contact_now())
    contact["updated_at"] = contact_now()
    save_contacts(contacts)
    return True


def delete_contact(send_number):
    key = normalize_contact_phone(send_number)
    if not key:
        return

    contacts = load_contacts()
    contacts = [
        x for x in contacts
        if normalize_contact_phone(x.get("send_number")) != key
    ]
    save_contacts(contacts)

def normalize_optional_contact_timestamp(value):
    s = str(value or "").strip()
    if not s:
        return ""
    return normalize_contact_timestamp_text(s)

def save_contact_profile(contact_payload, actor="user", original_send_number=None):
    payload = normalize_contact_record(contact_payload)
    key = normalize_contact_phone(payload.get("send_number"))
    if not key:
        raise ValueError("Phone number is required")

    contacts = load_contacts()
    old_key = normalize_contact_phone(original_send_number)
    now_text = contact_now()

    idx_existing, existing = find_contact_index(contacts, key)

    # NEW contact: reject if phone already exists
    if not old_key:
        if existing is not None:
            raise ValueError(f"A contact already uses this phone number: {key}")

        contact = normalize_contact_record(payload)
        contact["created_at"] = now_text
        contact["updated_at"] = now_text
        append_contact_timeline_entry(
            contact,
            "profile",
            "Contact created from Contact Manager.",
            actor=actor,
            when_text=now_text
        )
        contacts.append(contact)
        save_contacts(contacts)
        return True

    # EDIT existing contact, and phone changed
    if old_key != key:
        _, conflict = find_contact_index(contacts, key)
        if conflict is not None:
            raise ValueError(f"Another contact already uses this phone number: {key}")

        contacts = [
            x for x in contacts
            if normalize_contact_phone(x.get("send_number")) != old_key
        ]
        existing = None

    else:
        # editing same phone: find the current record again from filtered/original list
        _, existing = find_contact_index(contacts, key)

    fields_to_update = [
        "name", "display_number", "email", "company", "title",
        "city", "summary", "details", "tags", "color_flag"
    ]

    if existing is None:
        contact = normalize_contact_record(payload)
        # preserve original created_at when changing phone on an existing contact
        contact["created_at"] = str(payload.get("created_at") or now_text)
        contact["updated_at"] = now_text
        append_contact_timeline_entry(
            contact,
            "profile",
            f"Phone changed from {old_key} to {key}. Profile updated.",
            actor=actor,
            when_text=now_text
        )
        contacts.append(contact)
    else:
        contact = existing
        changed_fields = []

        for field in fields_to_update:
            old_value = str(contact.get(field) or "").strip()
            new_value = str(payload.get(field) or "").strip()

            if field == "color_flag" and new_value not in CONTACT_FLAG_META:
                new_value = "none"

            if old_value != new_value:
                contact[field] = new_value
                changed_fields.append(field)

        if isinstance(payload.get("timeline"), list):
            contact["timeline"] = list(payload.get("timeline"))[-500:]

        contact["display_number"] = (
            payload.get("display_number")
            or contact.get("display_number")
            or format_contact_display_number(key)
        )
        contact["updated_at"] = now_text

        if changed_fields:
            append_contact_timeline_entry(
                contact,
                "profile",
                f"Profile updated: {', '.join(changed_fields)}.",
                actor=actor,
                when_text=now_text
            )

    save_contacts(contacts)
    return True

def update_contact_interaction(
    send_number,
    timestamp_text=None,
    direction="outgoing",
    message="",
    send_type="manual",
    account_label="",
    status="",
    display_number="",
    suggested_name="",
    trigger="",
    auto_create=True
):
    contacts = load_contacts()
    changed = apply_contact_interaction_to_contacts(
        contacts,
        send_number=send_number,
        timestamp_text=timestamp_text,
        direction=direction,
        message=message,
        send_type=send_type,
        account_label=account_label,
        status=status,
        display_number=display_number,
        suggested_name=suggested_name,
        trigger=trigger,
        auto_create=auto_create
    )
    if changed:
        save_contacts(contacts)


def apply_contact_interaction_to_contacts(
    contacts,
    send_number,
    timestamp_text=None,
    direction="outgoing",
    message="",
    send_type="manual",
    account_label="",
    status="",
    display_number="",
    suggested_name="",
    trigger="",
    auto_create=True
):
    key = normalize_contact_phone(send_number or display_number)
    if not key:
        return False

    idx, contact = find_contact_index(contacts, key)
    ts = normalize_contact_timestamp_text(timestamp_text)

    if contact is None:
        if not auto_create:
            return False

        contact = normalize_contact_record({
            "send_number": key,
            "display_number": display_number or format_contact_display_number(key),
            "name": suggested_name or "",
            "created_at": ts,
            "updated_at": ts
        })
        contacts.append(contact)

    if display_number:
        contact["display_number"] = str(display_number).strip()
    if not contact.get("display_number"):
        contact["display_number"] = format_contact_display_number(key)
    if suggested_name and not contact.get("name"):
        contact["name"] = str(suggested_name).strip()

    preview = str(message or "").replace("\n", " ").strip()
    if len(preview) > 120:
        preview = preview[:117] + "..."

    contact["last_message_preview"] = preview
    contact["last_chat_at"] = ts

    if direction == "incoming":
        contact["last_incoming_at"] = ts
        if send_type == "sync_incoming":
            log_text = "Synced incoming message."
        else:
            log_text = "Incoming reply received."
        if preview:
            log_text += f" Preview: {preview}"
        append_contact_timeline_entry(contact, "incoming", log_text, actor="system", when_text=ts)
    else:
        contact["last_outgoing_at"] = ts
        if send_type == "bulk_auto":
            mode_text = "Bulk message sent"
        elif send_type == "sync_outgoing":
            mode_text = "Synced outgoing message"
        else:
            mode_text = "Manual message sent"
        detail_bits = []
        if account_label:
            detail_bits.append(f"via {account_label}")
        if trigger:
            detail_bits.append(f"trigger={trigger}")
        if status:
            detail_bits.append(f"status={status}")

        detail_text = f" ({', '.join(detail_bits)})" if detail_bits else ""
        log_text = f"{mode_text}{detail_text}."
        if preview:
            log_text += f" Preview: {preview}"
        append_contact_timeline_entry(contact, "outgoing", log_text, actor="system", when_text=ts)

    contact["updated_at"] = contact_now()
    return True


def update_contact_interactions_batch(entries):
    entries = list(entries or [])
    if not entries:
        return

    contacts = load_contacts()
    changed = False

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if apply_contact_interaction_to_contacts(
            contacts,
            send_number=entry.get("send_number"),
            timestamp_text=entry.get("timestamp_text"),
            direction=entry.get("direction", "outgoing"),
            message=entry.get("message", ""),
            send_type=entry.get("send_type", "manual"),
            account_label=entry.get("account_label", ""),
            status=entry.get("status", ""),
            display_number=entry.get("display_number", ""),
            suggested_name=entry.get("suggested_name", ""),
            trigger=entry.get("trigger", ""),
            auto_create=bool(entry.get("auto_create", True))
        ):
            changed = True

    if changed:
        save_contacts(contacts)

def parse_ymd_date(value):
    try:
        return datetime.datetime.strptime(str(value).strip(), "%Y-%m-%d").date()
    except Exception:
        return None


def now_user():
    return datetime.datetime.now(USER_TIMEZONE)

def today_key(dt=None):
    if dt is None:
        dt = now_user()
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=USER_TIMEZONE)
    else:
        dt = dt.astimezone(USER_TIMEZONE)
    return dt.strftime("%Y-%m-%d")


def safe_int(value, default=1, minimum=1, maximum=500):
    try:
        n = int(str(value).strip())
    except Exception:
        return default
    n = max(minimum, n)
    n = min(maximum, n)
    return n


def paginate_items(items, page=1, page_size=20):
    page = safe_int(page, 1, 1, 1000000)
    page_size = safe_int(page_size, 20, 1, 500)
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    sliced = items[start:end]
    total_pages = (total + page_size - 1) // page_size if page_size else 1
    return {
        "page": page,
        "pageSize": page_size,
        "total": total,
        "totalPages": total_pages,
        "items": sliced
    }


def format_duration_hms(seconds):
    seconds = int(seconds or 0)
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def normalize_contact_identifier(raw):
    s = str(raw or "").strip()
    if not s:
        return None

    send_number, _ = normalize_indonesia_mobile(s)
    if send_number:
        return send_number

    digits = normalize_phone_number(s).lstrip("+")
    if len(digits) >= 8:
        return digits

    return s


def _default_activity_bucket():
    return {
        "tab_seconds": {},
        "blast_jobs": 0,
        "blast_messages": 0,
        "manual_sends": 0,
        "incoming_replies": 0,
        "touched_contacts": [],
        "clock_in_at": "",
        "last_touch_at": "",
        "attendance_active_seconds": 0,
        "attendance_dormant_seconds": 0,
        "attendance_segments": [],
        "last_updated": ""
    }


def load_activity_stats():
    with ACTIVITY_LOCK:
        if os.path.exists(ACTIVITY_STATS_FILE):
            try:
                with open(ACTIVITY_STATS_FILE, "rb") as f:
                    encrypted = f.read()
                data = decrypt_data(encrypted)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
        return {"days": {}}


def save_activity_stats(data):
    with ACTIVITY_LOCK:
        with open(ACTIVITY_STATS_FILE, "wb") as f:
            f.write(encrypt_data(data))


def clear_activity_stats():
    save_activity_stats({"days": {}})


def _get_activity_bucket(data, day_key_value):
    days = data.setdefault("days", {})
    bucket = days.setdefault(day_key_value, _default_activity_bucket())

    bucket.setdefault("tab_seconds", {})
    bucket.setdefault("blast_jobs", 0)
    bucket.setdefault("blast_messages", 0)
    bucket.setdefault("manual_sends", 0)
    bucket.setdefault("incoming_replies", 0)
    bucket.setdefault("touched_contacts", [])
    bucket.setdefault("clock_in_at", "")
    bucket.setdefault("last_touch_at", "")
    bucket.setdefault("attendance_active_seconds", 0)
    bucket.setdefault("attendance_dormant_seconds", 0)
    bucket.setdefault("attendance_segments", [])
    bucket.setdefault("last_updated", "")

    return bucket


def _merge_touched_contacts(existing, new_values):
    merged = {str(x).strip() for x in (existing or []) if str(x).strip()}
    for value in (new_values or []):
        normalized = normalize_contact_identifier(value)
        if normalized:
            merged.add(normalized)
    return sorted(merged)


def record_tab_seconds(tab_name, seconds, when_dt=None):
    tab_name = str(tab_name or "").strip()
    seconds = int(seconds or 0)

    if not tab_name or seconds <= 0:
        return

    when_dt = when_dt or datetime.datetime.now()
    day_key_value = today_key(when_dt)

    data = load_activity_stats()
    bucket = _get_activity_bucket(data, day_key_value)
    bucket["tab_seconds"][tab_name] = int(bucket["tab_seconds"].get(tab_name, 0)) + seconds
    bucket["last_updated"] = datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    save_activity_stats(data)


def record_blast_activity(recipients, when_dt=None):
    when_dt = when_dt or datetime.datetime.now()
    day_key_value = today_key(when_dt)

    touched = []
    for rec in (recipients or []):
        if isinstance(rec, dict):
            touched.append(rec.get("send_number") or rec.get("display_number") or rec.get("mobile_raw"))
        else:
            touched.append(rec)

    touched = [normalize_contact_identifier(x) for x in touched]
    touched = [x for x in touched if x]

    data = load_activity_stats()
    bucket = _get_activity_bucket(data, day_key_value)
    bucket["blast_jobs"] = int(bucket.get("blast_jobs", 0)) + 1
    bucket["blast_messages"] = int(bucket.get("blast_messages", 0)) + len(touched)
    bucket["touched_contacts"] = _merge_touched_contacts(bucket.get("touched_contacts", []), touched)
    bucket["last_updated"] = datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    save_activity_stats(data)


def record_manual_send_activity(target, when_dt=None):
    when_dt = when_dt or datetime.datetime.now()
    day_key_value = today_key(when_dt)

    data = load_activity_stats()
    bucket = _get_activity_bucket(data, day_key_value)
    bucket["manual_sends"] = int(bucket.get("manual_sends", 0)) + 1
    bucket["touched_contacts"] = _merge_touched_contacts(bucket.get("touched_contacts", []), [target])
    bucket["last_updated"] = datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    save_activity_stats(data)


def record_incoming_reply_activity(source_value, when_dt=None):
    when_dt = when_dt or datetime.datetime.now()
    day_key_value = today_key(when_dt)

    data = load_activity_stats()
    bucket = _get_activity_bucket(data, day_key_value)
    bucket["incoming_replies"] = int(bucket.get("incoming_replies", 0)) + 1
    bucket["touched_contacts"] = _merge_touched_contacts(bucket.get("touched_contacts", []), [source_value])
    bucket["last_updated"] = datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    save_activity_stats(data)


def _append_attendance_segment(bucket, segment_type, start_dt, end_dt):
    if not segment_type:
        return

    start_user = ensure_user_datetime(start_dt)
    end_user = ensure_user_datetime(end_dt)
    if not start_user or not end_user or end_user <= start_user:
        return

    seconds = int(max(0, (end_user - start_user).total_seconds()))
    if seconds <= 0:
        return

    segments = list(bucket.get("attendance_segments") or [])
    segments.append({
        "type": str(segment_type),
        "start": start_user.strftime("%Y-%m-%d %H:%M:%S"),
        "end": end_user.strftime("%Y-%m-%d %H:%M:%S"),
        "seconds": seconds
    })
    bucket["attendance_segments"] = segments[-MAX_ATTENDANCE_SEGMENTS:]


def record_attendance_touch(when_dt=None, source="touch"):
    when_user = ensure_user_datetime(when_dt) or now_user()
    day_key_value = today_key(when_user)
    touch_text = when_user.strftime("%Y-%m-%d %H:%M:%S")

    data = load_activity_stats()
    bucket = _get_activity_bucket(data, day_key_value)

    if not bucket.get("clock_in_at"):
        bucket["clock_in_at"] = touch_text

    prev_touch = ensure_user_datetime(bucket.get("last_touch_at"))
    if prev_touch and prev_touch.date() == when_user.date() and when_user > prev_touch:
        gap_seconds = int((when_user - prev_touch).total_seconds())
        if gap_seconds > 0:
            active_seconds = min(gap_seconds, ATTENDANCE_IDLE_THRESHOLD_SECONDS)
            dormant_seconds = max(0, gap_seconds - ATTENDANCE_IDLE_THRESHOLD_SECONDS)

            if active_seconds > 0:
                active_end = prev_touch + datetime.timedelta(seconds=active_seconds)
                bucket["attendance_active_seconds"] = int(bucket.get("attendance_active_seconds", 0)) + active_seconds
                _append_attendance_segment(bucket, "active", prev_touch, active_end)
            else:
                active_end = prev_touch

            if dormant_seconds > 0:
                bucket["attendance_dormant_seconds"] = int(bucket.get("attendance_dormant_seconds", 0)) + dormant_seconds
                _append_attendance_segment(bucket, "dormant", active_end, when_user)

    bucket["last_touch_at"] = touch_text
    bucket["last_updated"] = touch_text
    save_activity_stats(data)


def get_attendance_bucket_for_day(day_key_value=None, include_live_tail=True):
    day_key_value = day_key_value or today_key()
    data = load_activity_stats()
    bucket = data.get("days", {}).get(day_key_value, _default_activity_bucket())

    clock_in_at = str(bucket.get("clock_in_at") or "")
    last_touch_at = str(bucket.get("last_touch_at") or "")
    active_seconds = int(bucket.get("attendance_active_seconds", 0))
    dormant_seconds = int(bucket.get("attendance_dormant_seconds", 0))
    segments = list(bucket.get("attendance_segments") or [])

    if include_live_tail and day_key_value == today_key():
        last_touch_dt = ensure_user_datetime(last_touch_at)
        now_dt = now_user()
        if last_touch_dt and now_dt > last_touch_dt and last_touch_dt.date() == now_dt.date():
            gap_seconds = int((now_dt - last_touch_dt).total_seconds())
            if gap_seconds > 0:
                active_tail = min(gap_seconds, ATTENDANCE_IDLE_THRESHOLD_SECONDS)
                dormant_tail = max(0, gap_seconds - ATTENDANCE_IDLE_THRESHOLD_SECONDS)

                if active_tail > 0:
                    active_seconds += active_tail
                    segments.append({
                        "type": "active",
                        "start": last_touch_dt.strftime("%Y-%m-%d %H:%M:%S"),
                        "end": (last_touch_dt + datetime.timedelta(seconds=active_tail)).strftime("%Y-%m-%d %H:%M:%S"),
                        "seconds": active_tail
                    })

                if dormant_tail > 0:
                    dormant_start = last_touch_dt + datetime.timedelta(seconds=active_tail)
                    dormant_seconds += dormant_tail
                    segments.append({
                        "type": "dormant",
                        "start": dormant_start.strftime("%Y-%m-%d %H:%M:%S"),
                        "end": now_dt.strftime("%Y-%m-%d %H:%M:%S"),
                        "seconds": dormant_tail
                    })

    return {
        "date": day_key_value,
        "clock_in_at": clock_in_at,
        "last_touch_at": last_touch_at,
        "active_seconds": active_seconds,
        "dormant_seconds": dormant_seconds,
        "segments": segments[-MAX_ATTENDANCE_SEGMENTS:]
    }


def build_last_n_day_attendance_series(n=7, end_day=None):
    rows = []
    for day_key_value in get_last_n_day_keys(n=n, end_day=end_day):
        snap = get_attendance_bucket_for_day(day_key_value, include_live_tail=(day_key_value == today_key()))
        rows.append({
            "date": day_key_value,
            "active_hours": round(int(snap.get("active_seconds", 0)) / 3600.0, 2),
            "dormant_hours": round(int(snap.get("dormant_seconds", 0)) / 3600.0, 2),
            "clock_in_at": str(snap.get("clock_in_at") or ""),
            "last_touch_at": str(snap.get("last_touch_at") or "")
        })
    return rows


def get_activity_bucket_for_day(day_key_value=None):
    day_key_value = day_key_value or today_key()
    data = load_activity_stats()
    bucket = data.get("days", {}).get(day_key_value, _default_activity_bucket())

    tab_seconds = dict(bucket.get("tab_seconds", {}))
    touched_contacts = list(bucket.get("touched_contacts", []))

    return {
        "date": day_key_value,
        "tab_seconds": tab_seconds,
        "screen_time_seconds": sum(int(v or 0) for v in tab_seconds.values()),
        "blast_jobs": int(bucket.get("blast_jobs", 0)),
        "blast_messages": int(bucket.get("blast_messages", 0)),
        "manual_sends": int(bucket.get("manual_sends", 0)),
        "incoming_replies": int(bucket.get("incoming_replies", 0)),
        "touched_contacts": touched_contacts,
        "touched_contacts_count": len(touched_contacts),
        "last_updated": str(bucket.get("last_updated", ""))
    }

def get_message_totals(day_key_value=None):
    target_day = str(day_key_value or "").strip()
    logs = load_manual_send_log()

    totals = {
        "sent_total": 0,
        "received_total": 0,
        "sent_total_at_date": 0,
        "received_total_at_date": 0,
    }

    for item in logs:
        if not isinstance(item, dict):
            continue

        send_type = str(item.get("send_type") or "").strip()
        status = str(item.get("status") or "").strip().lower()
        ts_value = item.get("timestamp")

        day_text = ""
        dt = parse_iso_dt(ts_value)
        if dt:
            day_text = dt.astimezone(USER_TIMEZONE).strftime("%Y-%m-%d")
        else:
            raw = str(ts_value or "").strip()
            if len(raw) >= 10:
                day_text = raw[:10]

        is_sent = (is_whatsapp_outgoing_history_send_type(send_type) and status == "sent")
        is_received = is_whatsapp_incoming_history_send_type(send_type)

        if is_sent:
            totals["sent_total"] += 1
            if target_day and day_text == target_day:
                totals["sent_total_at_date"] += 1

        if is_received:
            totals["received_total"] += 1
            if target_day and day_text == target_day:
                totals["received_total_at_date"] += 1

    return totals

def extract_local_day_from_timestamp(ts_value):
    dt = parse_iso_dt(ts_value)
    if dt:
        return dt.astimezone(USER_TIMEZONE).strftime("%Y-%m-%d")

    raw = str(ts_value or "").strip()
    return raw[:10] if len(raw) >= 10 else ""


def get_last_n_day_keys(n=7, end_day=None):
    end_date = parse_ymd_date(end_day) or datetime.datetime.now(USER_TIMEZONE).date()
    keys = []
    for offset in range(n - 1, -1, -1):
        day = end_date - datetime.timedelta(days=offset)
        keys.append(day.strftime("%Y-%m-%d"))
    return keys


def compute_productivity_score(snapshot):
    sent_total = int(snapshot.get("sent_total", 0))
    received_total = int(snapshot.get("received_total", 0))
    touched_contacts = int(snapshot.get("touched_contacts_count", 0))
    screen_hours = float(snapshot.get("screen_time_seconds", 0)) / 3600.0
    avg_reply_speed = snapshot.get("avg_reply_speed_seconds")

    sent_part = min(sent_total / 40.0, 1.0) * 35.0
    received_part = min(received_total / 10.0, 1.0) * 15.0
    touched_part = min(touched_contacts / 30.0, 1.0) * 20.0
    screen_part = min(screen_hours / 5.0, 1.0) * 10.0

    if avg_reply_speed is None:
        speed_part = 10.0
    elif avg_reply_speed <= 15 * 60:
        speed_part = 20.0
    elif avg_reply_speed >= 2 * 60 * 60:
        speed_part = 0.0
    else:
        span = (2 * 60 * 60) - (15 * 60)
        speed_part = max(0.0, 20.0 * (1.0 - ((avg_reply_speed - 15 * 60) / span)))

    score = int(round(sent_part + received_part + touched_part + screen_part + speed_part))
    return max(0, min(100, score))


def build_productivity_tips(snapshot):
    tips = []

    sent_total = int(snapshot.get("sent_total", 0))
    failed_total = int(snapshot.get("failed_total", 0))
    received_total = int(snapshot.get("received_total", 0))
    touched_contacts = int(snapshot.get("touched_contacts_count", 0))
    screen_time_seconds = int(snapshot.get("screen_time_seconds", 0))
    avg_reply_speed = snapshot.get("avg_reply_speed_seconds")
    reply_rate = float(snapshot.get("reply_rate", 0.0))

    if sent_total < 20:
        tips.append("Increase outreach volume. Try focused sending blocks until you reach at least 20 successful contacts today.")

    if screen_time_seconds >= 2 * 60 * 60 and sent_total < 15:
        tips.append("A lot of active app time is not turning into outreach. Reduce idle browsing and work in tighter batches.")

    if avg_reply_speed is not None and avg_reply_speed > 30 * 60:
        tips.append(f"Reply speed is slow at {format_duration_hms(avg_reply_speed)}. Aim to respond within 15–30 minutes after an incoming reply.")

    if sent_total >= 15 and reply_rate < 15.0:
        tips.append("Reply rate is low. Improve message quality, follow-up sequence, or targeting instead of only increasing volume.")

    if touched_contacts < 10 and sent_total >= 10:
        tips.append("Expand the contact pool. Reaching more unique contacts usually improves daily pipeline coverage.")

    if failed_total > 0:
        tips.append("There are failed sends today. Check recipient validity, WhatsApp page state, or connection stability.")

    if received_total == 0 and sent_total >= 10:
        tips.append("No replies yet today. Review template wording and send timing to improve engagement.")

    if not tips:
        tips.append("Performance looks healthy today. Keep the same pace, maintain fast follow-up, and avoid unnecessary tab switching.")

    return tips[:5]


def build_daily_performance_snapshot(day_key_value=None):
    day_key_value = day_key_value or today_key()
    activity = get_activity_bucket_for_day(day_key_value)
    logs = load_manual_send_log()

    sent_total = 0
    failed_total = 0
    received_total = 0
    reply_speeds = []

    for item in logs:
        if not isinstance(item, dict):
            continue

        item_day = extract_local_day_from_timestamp(item.get("timestamp"))
        if item_day != day_key_value:
            continue

        send_type = str(item.get("send_type") or "").strip()
        status = str(item.get("status") or "").strip().lower()

        if is_whatsapp_outgoing_history_send_type(send_type):
            if status == "sent":
                sent_total += 1

                rs = item.get("reply_speed_seconds")
                if rs is not None:
                    try:
                        rs_int = int(rs)
                        if rs_int >= 0:
                            reply_speeds.append(rs_int)
                    except Exception:
                        pass
            elif status == "failed":
                failed_total += 1

        elif is_whatsapp_incoming_history_send_type(send_type):
            received_total += 1

    avg_reply_speed_seconds = None
    if reply_speeds:
        avg_reply_speed_seconds = int(sum(reply_speeds) / len(reply_speeds))

    reply_rate = (received_total / sent_total * 100.0) if sent_total > 0 else 0.0

    snapshot = {
        "date": day_key_value,
        "screen_time_seconds": int(activity.get("screen_time_seconds", 0)),
        "blast_jobs": int(activity.get("blast_jobs", 0)),
        "blast_messages": int(activity.get("blast_messages", 0)),
        "manual_sends": int(activity.get("manual_sends", 0)),
        "incoming_replies_logged": int(activity.get("incoming_replies", 0)),
        "touched_contacts": list(activity.get("touched_contacts", [])),
        "touched_contacts_count": int(activity.get("touched_contacts_count", 0)),
        "last_updated": str(activity.get("last_updated", "")),

        "sent_total": sent_total,
        "failed_total": failed_total,
        "received_total": received_total,
        "reply_rate": round(reply_rate, 1),
        "avg_reply_speed_seconds": avg_reply_speed_seconds,
        "avg_reply_speed_hms": format_duration_hms(avg_reply_speed_seconds) if avg_reply_speed_seconds is not None else "-",
    }

    snapshot["productivity_score"] = compute_productivity_score(snapshot)
    snapshot["tips"] = build_productivity_tips(snapshot)
    return snapshot


def build_last_n_day_performance_series(n=7, end_day=None):
    rows = []
    for day_key_value in get_last_n_day_keys(n=n, end_day=end_day):
        snap = build_daily_performance_snapshot(day_key_value)
        rows.append({
            "date": day_key_value,
            "sent_total": int(snap.get("sent_total", 0)),
            "received_total": int(snap.get("received_total", 0)),
            "touched_contacts_count": int(snap.get("touched_contacts_count", 0)),
            "screen_time_hours": round(float(snap.get("screen_time_seconds", 0)) / 3600.0, 2),
            "productivity_score": int(snap.get("productivity_score", 0))
        })
    return rows

def save_manual_send_log(entry):
    log = load_manual_send_log()
    log.append(entry)
    write_manual_send_log(log)


def clear_manual_send_log_file():
    write_manual_send_log([])

def normalize_phone_number(raw):
    s = str(raw or "").strip()
    s = s.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if s.startswith("+"):
        return "+" + "".join(ch for ch in s[1:] if ch.isdigit())
    return "".join(ch for ch in s if ch.isdigit())

def normalize_whatsapp_self_number(raw):
    text = str(raw or "").strip()
    if not text:
        return None, None

    m = re.search(r'(\d{8,20})@(?:s\.whatsapp\.net|c\.us|lid)', text, re.IGNORECASE)
    digits = m.group(1) if m else "".join(ch for ch in text if ch.isdigit())

    if len(digits) < 8:
        return None, None

    send_number, display_number = normalize_indonesia_mobile(digits)
    if send_number:
        return send_number, display_number

    return digits, f"+{digits}"

def read_numbers_from_txt(file_path):
    numbers = []
    invalid = []
    seen = set()

    with open(file_path, "r", encoding="utf-8-sig") as f:
        for line_no, line in enumerate(f, start=1):
            raw = line.strip()
            if not raw:
                continue

            num = normalize_phone_number(raw)
            if not num or len(num.replace("+", "")) < 8:
                invalid.append((line_no, raw))
                continue

            if num not in seen:
                seen.add(num)
                numbers.append(num)

    return numbers, invalid

def load_app_state():
    default_state = {
        "wa_account_ids": [1],
        "allow_custom_bulk_message": False,
        "builtin_templates_enabled": dict(DEFAULT_BUILTIN_TEMPLATE_ENABLED),
        "cashier_mode_enabled": False
    }

    if not os.path.exists(APP_STATE_FILE):
        return default_state

    try:
        with open(APP_STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        wa_ids = data.get("wa_account_ids", [1])
        wa_ids = [int(x) for x in wa_ids if str(x).isdigit()]
        wa_ids = sorted(set(wa_ids))

        allow_custom_bulk_message = bool(data.get("allow_custom_bulk_message", False))
        cashier_mode_enabled = bool(data.get("cashier_mode_enabled", False))
        builtin_templates_enabled = dict(DEFAULT_BUILTIN_TEMPLATE_ENABLED)
        stored_builtin = data.get("builtin_templates_enabled") or {}
        if isinstance(stored_builtin, dict):
            for key, value in stored_builtin.items():
                builtin_templates_enabled[str(key)] = bool(value)

        return {
            "wa_account_ids": wa_ids or [1],
            "allow_custom_bulk_message": allow_custom_bulk_message,
            "builtin_templates_enabled": builtin_templates_enabled,
            "cashier_mode_enabled": cashier_mode_enabled
        }
    except Exception:
        return default_state


def save_app_state(state):
    try:
        if not isinstance(state, dict):
            state = {}

        wa_ids = state.get("wa_account_ids", [1])
        wa_ids = [int(x) for x in wa_ids if str(x).isdigit()]
        wa_ids = sorted(set(wa_ids)) or [1]

        safe_state = {
            "wa_account_ids": wa_ids,
            "allow_custom_bulk_message": bool(state.get("allow_custom_bulk_message", False)),
            "builtin_templates_enabled": dict(DEFAULT_BUILTIN_TEMPLATE_ENABLED),
            "cashier_mode_enabled": bool(state.get("cashier_mode_enabled", False))
        }

        stored_builtin = state.get("builtin_templates_enabled") or {}
        if isinstance(stored_builtin, dict):
            for key, value in stored_builtin.items():
                safe_state["builtin_templates_enabled"][str(key)] = bool(value)

        with open(APP_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(safe_state, f, indent=2)
    except Exception as e:
        print("Failed to save app state:", e)

def host_allowed(url_str, allowed_sites):
    try:
        host = (urlparse(url_str).hostname or "").lower()
    except Exception:
        return False

    for site in allowed_sites:
        allowed_host = (urlparse(site).hostname or "").lower()
        if host_matches_rule(host, allowed_host):
            return True
    return False

def is_google_host_allowed(host):
    host = (host or "").lower().strip()
    if not host:
        return False

    # block Gemini
    if host == "gemini.google.com" or host.endswith(".gemini.google.com"):
        return False

    # allow all other google hosts
    return host == "google.com" or host.endswith(".google.com")


def host_matches_rule(host, rule_host):
    host = (host or "").lower().strip()
    rule_host = (rule_host or "").lower().strip()

    if not host or not rule_host:
        return False

    if rule_host == "*.google.com":
        return is_google_host_allowed(host)

    return host == rule_host or host.endswith("." + rule_host)

def flatten_dict(data, parent_key="", sep="."):
    items = {}
    if isinstance(data, dict):
        for k, v in data.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
            if isinstance(v, dict):
                items.update(flatten_dict(v, new_key, sep=sep))
            elif isinstance(v, list):
                if all(isinstance(x, dict) for x in v):
                    items[new_key] = json.dumps(v, ensure_ascii=False)
                else:
                    items[new_key] = json.dumps(v, ensure_ascii=False)
            else:
                items[new_key] = v
    else:
        items[parent_key or "value"] = data
    return items


def normalize_api_rows(payload):
    if isinstance(payload, list):
        if all(isinstance(item, dict) for item in payload):
            return [flatten_dict(item) for item in payload]
        return [{"value": item} for item in payload]

    if isinstance(payload, dict):
        for key in ("data", "items", "results", "rows", "list"):
            value = payload.get(key)
            if isinstance(value, list) and all(isinstance(item, dict) for item in value):
                return [flatten_dict(item) for item in value]
        return [flatten_dict(payload)]

    return [{"value": payload}]


def build_headers(rows):
    headers = []
    seen = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                headers.append(str(key))
    return headers or ["value"]


def cell_to_text(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)

class MultiColumnFilterProxy(QSortFilterProxyModel):
    def filterAcceptsRow(self, source_row, source_parent):
        pattern = self.filterRegularExpression().pattern().lower().strip()
        if not pattern:
            return True

        model = self.sourceModel()
        for col in range(model.columnCount()):
            idx = model.index(source_row, col, source_parent)
            text = str(model.data(idx) or "").lower()
            if pattern in text:
                return True
        return False

def normalize_contact_timestamp_text(value):
    return format_user_datetime_text(value, default=contact_now())

class LockedExcelView(QTableView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.admin_unlocked = False
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setAlternatingRowColors(True)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        self.setSortingEnabled(True)
        self.setWordWrap(False)
        self.setShowGrid(True)
        self.verticalHeader().setDefaultSectionSize(22)
        self.horizontalHeader().setSectionsMovable(True)
        self.horizontalHeader().setSectionsClickable(True)
        self.horizontalHeader().setStretchLastSection(False)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

    def set_admin_unlocked(self, unlocked):
        self.admin_unlocked = unlocked
        self.setContextMenuPolicy(
            Qt.ContextMenuPolicy.DefaultContextMenu
            if unlocked else Qt.ContextMenuPolicy.NoContextMenu
        )

    def contextMenuEvent(self, event):
        if not self.admin_unlocked:
            event.ignore()
            return
        super().contextMenuEvent(event)

    def keyPressEvent(self, event):
        if not self.admin_unlocked:
            if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
                event.accept()
                return
            if event.matches(QKeySequence.StandardKey.Copy):
                event.accept()
                return
        super().keyPressEvent(event)


class ApiSheetTab(QWidget):
    def __init__(self, api_url, admin_password, refresh_callback, close_callback, parent=None):
        super().__init__(parent)
        self.child_views = []
        self.api_url = api_url
        self.admin_password = admin_password
        self.refresh_callback = refresh_callback
        self.close_callback = close_callback
        self.admin_unlocked = False
        self._row_payloads = []

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)

        root = QVBoxLayout(self)

        top = QHBoxLayout()
        self.info_label = QLabel("Locked view. Right-click and Ctrl shortcuts are disabled.")
        self.row_info_label = QLabel("0 rows × 0 cols")
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Filter rows...")

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(lambda: self.refresh_callback(self))

        self.unlock_btn = QPushButton("Admin Unlock")
        self.unlock_btn.clicked.connect(self.toggle_admin_unlock)

        self.close_btn = QPushButton("Close Tab")
        self.close_btn.clicked.connect(lambda: self.close_callback(self))

        top.addWidget(self.info_label, 1)
        top.addWidget(self.row_info_label)
        top.addWidget(self.refresh_btn)
        top.addWidget(self.unlock_btn)
        top.addWidget(self.close_btn)

        root.addLayout(top)

        self.url_label = QLabel(api_url)
        self.url_label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        root.addWidget(self.url_label)
        root.addWidget(self.search_edit)

        self.splitter = QSplitter(Qt.Orientation.Vertical, self)
        root.addWidget(self.splitter, 1)

        # Main excel-like grid
        self.main_view = LockedExcelView(self)
        self.main_model = QStandardItemModel(self)
        self.proxy = MultiColumnFilterProxy(self)
        self.proxy.setSourceModel(self.main_model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.main_view.setModel(self.proxy)
        self.search_edit.textChanged.connect(
            lambda text: self.proxy.setFilterRegularExpression(text)
        )

        # Detail area
        detail_widget = QWidget(self)
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)

        self.detail_tree = QTreeWidget(self)
        self.detail_tree.setHeaderLabels(["Path", "Value"])
        self.detail_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)

        self.child_tabs = QTabWidget(self)
        self.child_tabs.setTabsClosable(False)

        detail_layout.addWidget(QLabel("Nested details"))
        detail_layout.addWidget(self.detail_tree, 1)
        detail_layout.addWidget(self.child_tabs, 2)

        self.splitter.addWidget(self.main_view)
        self.splitter.addWidget(detail_widget)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 2)

        try:
            self.main_view.selectionModel().currentRowChanged.disconnect()
        except Exception:
            pass
        self.main_view.selectionModel().currentRowChanged.connect(self.on_row_changed)

    def _smart_resize_columns(self, view, model, sample_rows=120, max_width=420):
        fm = view.fontMetrics()
        for col in range(model.columnCount()):
            header_text = str(model.headerData(col, Qt.Orientation.Horizontal) or "")
            width = fm.horizontalAdvance(header_text) + 28

            rows = min(model.rowCount(), sample_rows)
            for row in range(rows):
                idx = model.index(row, col)
                text = str(model.data(idx) or "")
                width = max(width, min(max_width, fm.horizontalAdvance(text[:80]) + 28))

            view.setColumnWidth(col, min(width, max_width))

    def toggle_admin_unlock(self):
        if self.admin_unlocked:
            self.admin_unlocked = False
            self.main_view.set_admin_unlocked(False)
            for view in self.child_views:
                view.set_admin_unlocked(False)
            self.url_label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
            self.info_label.setText("Locked view. Right-click and Ctrl shortcuts are disabled.")
            self.unlock_btn.setText("Admin Unlock")
            return

        pwd, ok = QInputDialog.getText(
            self, "Admin Login", "Enter Password:", QLineEdit.EchoMode.Password
        )
        if ok and pwd == self.admin_password:
            self.admin_unlocked = True
            self.main_view.set_admin_unlocked(True)
            for view in self.child_views:
                view.set_admin_unlocked(True)
            self.url_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.info_label.setText("Admin unlocked. Copy/right-click enabled for this sheet.")
            self.unlock_btn.setText("Lock Again")
        elif ok:
            QMessageBox.warning(self, "Error", "Incorrect password.")

    def set_payload(self, payload, status_text=""):
        self.main_model.clear()
        self.detail_tree.clear()
        self.child_tabs.clear()
        self._row_payloads = []

        table_path, rows = choose_primary_table(payload)
        normalized_rows = []
        source_rows = []

        if isinstance(rows, list) and all(isinstance(r, dict) for r in rows):
            for r in rows:
                normalized_rows.append(flatten_scalars(r))
                source_rows.append(r)
        else:
            normalized_rows = normalize_api_rows(rows)
            source_rows = rows if isinstance(rows, list) else [rows]

        headers = build_headers(normalized_rows)
        self.main_model.setColumnCount(len(headers))
        self.main_model.setHorizontalHeaderLabels(headers)

        for row in normalized_rows:
            items = []
            for header in headers:
                item = QStandardItem(cell_to_text(row.get(header, "")))
                item.setEditable(False)
                items.append(item)
            self.main_model.appendRow(items)

        self._row_payloads = source_rows
        self._smart_resize_columns(self.main_view, self.main_model)
        self.row_info_label.setText(f"{len(normalized_rows)} rows × {len(headers)} cols")

        if status_text:
            self.info_label.setText(f"{status_text} | primary table: {table_path}")

        if self.proxy.rowCount() > 0:
            self.main_view.selectRow(0)
            self.on_row_changed(self.proxy.index(0, 0), QModelIndex())

    def on_row_changed(self, current, previous):
        if not current.isValid():
            return

        source_index = self.proxy.mapToSource(current)
        row = source_index.row()
        if row < 0 or row >= len(self._row_payloads):
            return

        payload = self._row_payloads[row]
        self.populate_detail_tree(payload)
        self.populate_child_tables(payload)

    def populate_detail_tree(self, payload):
        self.detail_tree.clear()

        def add_item(parent, key, value):
            if isinstance(value, dict):
                node = QTreeWidgetItem([str(key), "{object}"])
                parent.addChild(node) if parent else self.detail_tree.addTopLevelItem(node)
                for k, v in value.items():
                    add_item(node, k, v)
            elif isinstance(value, list):
                label = f"[{len(value)} items]"
                node = QTreeWidgetItem([str(key), label])
                parent.addChild(node) if parent else self.detail_tree.addTopLevelItem(node)
                for i, item in enumerate(value):
                    add_item(node, f"[{i}]", item)
            else:
                node = QTreeWidgetItem([str(key), cell_to_text(value)])
                parent.addChild(node) if parent else self.detail_tree.addTopLevelItem(node)

        if isinstance(payload, dict):
            for k, v in payload.items():
                add_item(None, k, v)
        else:
            add_item(None, "value", payload)

        self.detail_tree.expandToDepth(1)

    def populate_child_tables(self, payload):
        self.child_tabs.clear()
        self.child_views = []
        objects, tables = extract_nested_parts(payload)

        for path, value in tables.items():
            tab = QWidget()
            layout = QVBoxLayout(tab)
            layout.setContentsMargins(4, 4, 4, 4)

            if isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
                model = QStandardItemModel(tab)
                normalized = [flatten_scalars(x) for x in value]
                headers = build_headers(normalized)
                model.setColumnCount(len(headers))
                model.setHorizontalHeaderLabels(headers)

                view = LockedExcelView(tab)
                view.set_admin_unlocked(self.admin_unlocked)

                for row in normalized:
                    items = [QStandardItem(cell_to_text(row.get(h, ""))) for h in headers]
                    for item in items:
                        item.setEditable(False)
                    model.appendRow(items)

                view.setModel(model)
                self._smart_resize_columns(view, model)
                layout.addWidget(view)
                self.child_tabs.addTab(tab, f"{path} ({len(value)})")
                self.child_views.append(view)

            elif isinstance(value, list):
                model = QStandardItemModel(tab)
                model.setColumnCount(1)
                model.setHorizontalHeaderLabels(["value"])

                view = LockedExcelView(tab)
                view.set_admin_unlocked(self.admin_unlocked)

                for item_value in value:
                    item = QStandardItem(cell_to_text(item_value))
                    item.setEditable(False)
                    model.appendRow([item])

                view.setModel(model)
                self._smart_resize_columns(view, model)
                layout.addWidget(view)
                self.child_tabs.addTab(tab, f"{path} ({len(value)})")
                self.child_views.append(view)

# --------------------------
# Custom WebEnginePage
# --------------------------
class CustomWebEnginePage(QWebEnginePage):
    def __init__(self, profile, tab_name, parent=None):
        super().__init__(profile, parent)
        self.tab_name = tab_name
        self.main_window = parent
        self.browser_view = None
        self.auto_file_chooser_path = ""
        self.featurePermissionRequested.connect(self.on_feature_permission_requested)
        if hasattr(self, "webAuthUxRequested"):
            self.webAuthUxRequested.connect(self.on_web_auth_requested)

    def on_web_auth_requested(self, request):
        try:
            request.cancel()
            if self.main_window:
                self.main_window.status_bar.showMessage("Passkey prompt blocked.", 3000)
        except Exception:
            pass

    def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
        print(f"JS [{level}] {sourceID}:{lineNumber}: {message}")
        noisy_patterns = [
            "[DOM] Password field is not contained in a form",
            "Self-XSS",
            "WARNING!",
            "CSP Violation",
            "[Global] report:",
            "allContact undefined",
            "monitor function",
            "Request failed with status code 401",
        ]

        if any(p in message for p in noisy_patterns):
            return

        if level == QWebEnginePage.JavaScriptConsoleMessageLevel.ErrorMessageLevel:
            print(f"js[{level}] {sourceID}:{lineNumber}: {message}")

    def on_feature_permission_requested(self, securityOrigin, feature):
        url = securityOrigin.host()
        if feature == QWebEnginePage.Feature.Geolocation:
            self.setFeaturePermission(
                securityOrigin,
                feature,
                QWebEnginePage.PermissionPolicy.PermissionDeniedByUser
            )
        elif feature == QWebEnginePage.Feature.Notifications:
            reply = QMessageBox.question(
                None,
                "Notification Permission",
                f"Allow {url} to show notifications?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            self.setFeaturePermission(
                securityOrigin,
                feature,
                QWebEnginePage.PermissionPolicy.PermissionGrantedByUser
                if reply == QMessageBox.StandardButton.Yes
                else QWebEnginePage.PermissionPolicy.PermissionDeniedByUser
            )
        else:
            self.setFeaturePermission(
                securityOrigin,
                feature,
                QWebEnginePage.PermissionPolicy.PermissionDeniedByUser
            )

    def contextMenuEvent(self, event):
        super().contextMenuEvent(event)

    def chooseFiles(self, mode, oldFiles, acceptedMimeTypes):
        auto_path = normalize_template_attachment_path(getattr(self, "auto_file_chooser_path", ""))
        if auto_path and os.path.exists(auto_path):
            self.auto_file_chooser_path = ""
            return [auto_path]

        return super().chooseFiles(mode, oldFiles, acceptedMimeTypes)

    def createWindow(self, windowType):
        if not self.main_window:
            return super().createWindow(windowType)

        current_meta = self.main_window.find_tab_meta_by_view(self.browser_view)
        if current_meta:
            return self.main_window.create_dynamic_tab_from_meta(current_meta)

        current_config = self.main_window.get_config_by_name(self.tab_name)
        if not current_config:
            return super().createWindow(windowType)

        return self.main_window.create_dynamic_tab_for_config(current_config)

    def acceptNavigationRequest(self, url, nav_type, isMainFrame):
        if not isMainFrame or not self.main_window:
            return super().acceptNavigationRequest(url, nav_type, isMainFrame)

        current_view = self.browser_view
        if current_view is None:
            return super().acceptNavigationRequest(url, nav_type, isMainFrame)

        current_meta = self.main_window.find_tab_meta_by_view(current_view)
        if not current_meta:
            return super().acceptNavigationRequest(url, nav_type, isMainFrame)

        target_url = url.toString()

        # Lark: allow only Lark/Feishu hosts, but keep popup/login flow working
        if self.tab_name == "Lark":
            if host_allowed(target_url, current_meta["allowed_sites"]):
                return True

            self.main_window.status_bar.showMessage(
                "Navigation blocked – only Lark/Feishu sites allowed.",
                3000
            )
            return False

        target_config = self.main_window.find_config_for_url(target_url)

        if target_config and target_config["name"] == current_meta["name"]:
            return True

        if target_config and target_config["name"] != current_meta["name"]:
            self.main_window.focus_or_open_fixed_tab(target_config, target_url)

            if not current_meta.get("is_fixed"):
                QTimer.singleShot(
                    0,
                    lambda v=current_view: self.main_window.close_web_view_tab(v)
                )
            return False

        self.main_window.status_bar.showMessage(
            f"Navigation blocked – only {current_meta['name']} sites allowed.",
            3000
        )
        return False

# --------------------------
# Request interceptor
# --------------------------
class HeaderInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, country, fake_ip, enable_spoof=False):
        super().__init__()
        self.country = country
        self.fake_ip = fake_ip
        self.enable_spoof = enable_spoof

    def interceptRequest(self, info):
        try:
            url = info.requestUrl()
            if url.scheme() not in ("http", "https"):
                return

            host = (url.host() or "").lower()

            info.setHttpHeader(b"Accept-Language", FORCED_LANGUAGE.encode())

            if not self.enable_spoof:
                return

            # For Lark/Feishu, do not inject fake IP / geo headers.
            if is_lark_host(host):
                return

            if self.fake_ip:
                info.setHttpHeader(b"X-Forwarded-For", self.fake_ip.encode())
            if self.country:
                info.setHttpHeader(b"CF-IPCountry", self.country.encode())
                info.setHttpHeader(b"Geo-Location", self.country.encode())
        except Exception as e:
            print(f"Error in interceptRequest: {e}")


class MessageInputDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enter Message")
        layout = QVBoxLayout(self)
        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText("Type your message here...")
        configure_scrollable_text_edit(self.text_edit, min_height=220, always_show_scroll=True)
        layout.addWidget(self.text_edit)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_message(self):
        return self.text_edit.toPlainText()

class BulkWhatsAppDialog(QDialog):
    PREVIEW_MAX = 96

    def __init__(self, last_blast=None, templates=None, allow_custom_message=False, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Bulk WhatsApp Blast")
        self.setSizeGripEnabled(True)

        self.last_blast = last_blast or {"numbers": [], "message": "", "attachment_path": "", "updated_at": ""}
        self.templates = list(templates or [])
        self.allow_custom_message = bool(allow_custom_message)
        self.file_records = []
        self.file_path = ""
        self.selected_attachment_path = ""

        self._apply_screen_friendly_size()

        outer_root = QVBoxLayout(self)
        outer_root.setContentsMargins(10, 10, 10, 10)
        outer_root.setSpacing(10)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer_root.addWidget(scroll, 1)

        content = QWidget(self)
        content.setMinimumWidth(960)
        root = QVBoxLayout(content)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(12)

        card_style = (
            "QFrame {"
            "background:#ffffff;"
            "border:1px solid #d4e2f7;"
            "border-radius:22px;"
            "}"
        )

        title = QLabel("Bulk WhatsApp Sender")
        title.setStyleSheet("font-size:18px;font-weight:800;color:#0d2d63;")
        root.addWidget(title)

        guide = QLabel(
            "Spreadsheet guide:\n"
            "- Supported files: .xlsx, .xls, .csv\n"
            "- Row 1 must be header\n"
            "- Data starts from row 2\n"
            "- Column 1 = phone number (mandatory)\n"
            "- Column 2 = name (optional)\n"
            "- Column 3 = data1, Column 4 = data2, and so on\n"
            "- Accepted phone format examples:\n"
            "  87850303779\n"
            "  087850303779\n"
            "  6287850303779\n"
            f"- Maximum {MAX_BULK_RECIPIENTS} unique number(s) per blast\n"
            "- Duplicate numbers are removed automatically before send"
        )
        guide.setWordWrap(True)
        guide.setStyleSheet(
            "padding:12px;"
            "background:#ffffff;"
            "border:1px solid #d4e2f7;"
            "border-radius:18px;"
            "color:#24466d;"
            "font-weight:600;"
        )
        root.addWidget(guide)

        # --------------------------
        # TOP: recipient sources
        # --------------------------
        sources_box = QFrame(self)
        sources_box.setStyleSheet(card_style)
        sources_layout = QVBoxLayout(sources_box)
        sources_layout.setContentsMargins(14, 14, 14, 14)
        sources_layout.setSpacing(8)

        sources_title = QLabel("Recipients")
        sources_title.setStyleSheet("font-size:15px;font-weight:800;color:#0d2d63;")
        sources_layout.addWidget(sources_title)

        sources_hint = QLabel(
            "Pick from the previous blast or import a file. The app will auto-deduplicate by number before sending."
        )
        sources_hint.setWordWrap(True)
        sources_hint.setStyleSheet("color:#4c678e;font-weight:600;")
        sources_layout.addWidget(sources_hint)

        source_tabs = QTabWidget(self)
        source_tabs.setDocumentMode(True)
        source_tabs.setMinimumHeight(390)

        # Previous blast tab
        prev_tab = QWidget(self)
        prev_layout = QVBoxLayout(prev_tab)

        prev_meta = format_user_datetime_text(self.last_blast.get("updated_at", ""), default="")
        prev_info = QLabel(
            f"Last saved: {prev_meta}" if prev_meta else "No previous blast saved yet."
        )
        prev_info.setWordWrap(True)
        prev_layout.addWidget(prev_info)

        self.prev_list = self._make_stable_list_widget()
        for rec in self.last_blast.get("recipients", []):
            full_text = self._recipient_preview_text(rec)
            item = QListWidgetItem(self._shorten(full_text))
            item.setToolTip(full_text)
            item.setData(Qt.ItemDataRole.UserRole, rec)
            self.prev_list.addItem(item)
        prev_layout.addWidget(self.prev_list, 1)

        prev_btns = QHBoxLayout()
        self.prev_select_all_btn = QPushButton("Select All Previous")
        self.prev_clear_btn = QPushButton("Clear Previous Selection")
        self.prev_select_all_btn.clicked.connect(self.prev_list.selectAll)
        self.prev_clear_btn.clicked.connect(self.prev_list.clearSelection)
        prev_btns.addWidget(self.prev_select_all_btn)
        prev_btns.addWidget(self.prev_clear_btn)
        prev_layout.addLayout(prev_btns)

        self.reuse_last_msg_chk = QCheckBox("Reuse previous message")
        if self.last_blast.get("message"):
            self.reuse_last_msg_chk.setChecked(True)
        else:
            self.reuse_last_msg_chk.setEnabled(False)
        prev_layout.addWidget(self.reuse_last_msg_chk)

        source_tabs.addTab(prev_tab, "Previous Blast")

        # Import file tab
        file_tab = QWidget(self)
        file_layout = QVBoxLayout(file_tab)

        self.file_path_label = QLabel("No file selected.")
        self.file_path_label.setWordWrap(True)
        self.file_path_label.setStyleSheet("color:#444;")
        file_layout.addWidget(self.file_path_label)

        file_btns = QHBoxLayout()
        self.import_file_btn = QPushButton("Import File")
        self.file_select_all_btn = QPushButton("Select All Imported")
        self.file_clear_btn = QPushButton("Clear Imported Selection")
        self.import_file_btn.clicked.connect(self.import_data_file)
        self.file_select_all_btn.clicked.connect(self.select_all_file)
        self.file_clear_btn.clicked.connect(self.clear_file_selection)
        file_btns.addWidget(self.import_file_btn)
        file_btns.addWidget(self.file_select_all_btn)
        file_btns.addWidget(self.file_clear_btn)
        file_layout.addLayout(file_btns)

        self.file_list = self._make_stable_list_widget()
        file_layout.addWidget(self.file_list, 1)

        self.file_result_label = QLabel("")
        self.file_result_label.setWordWrap(True)
        file_layout.addWidget(self.file_result_label)

        source_tabs.addTab(file_tab, "Import XLSX / CSV")

        sources_layout.addWidget(source_tabs)
        root.addWidget(sources_box)

        # --------------------------
        # BOTTOM: message/template area
        # --------------------------
        compose_box = QFrame(self)
        compose_box.setStyleSheet(card_style)
        compose_layout = QVBoxLayout(compose_box)
        compose_layout.setContentsMargins(14, 14, 14, 14)
        compose_layout.setSpacing(8)

        msg_title = QLabel("Message Template")
        msg_title.setStyleSheet("font-size:15px;font-weight:800;color:#0d2d63;")
        compose_layout.addWidget(msg_title)

        placeholder_info = QLabel(
            "Supported placeholders: ${name}, ${data1}, ${data2}, ${data3}, ...\n"
            "If some recipients are missing placeholder data, the app will ask for one temporary global value before send."
        )
        placeholder_info.setWordWrap(True)
        placeholder_info.setStyleSheet(
            "padding:10px;"
            "background:#f7faff;"
            "border:1px solid #d9e5f8;"
            "border-radius:16px;"
            "color:#39587f;"
            "font-weight:600;"
        )
        compose_layout.addWidget(placeholder_info)

        template_row = QHBoxLayout()
        template_row.addWidget(QLabel("Saved Template"))

        self.template_combo = QComboBox()
        self.template_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._rebuild_template_combo()
        self.template_combo.currentIndexChanged.connect(self._handle_template_combo_changed)

        self.template_load_btn = QPushButton("Load Template")
        self.template_load_btn.clicked.connect(self.apply_selected_template)

        template_row.addWidget(self.template_combo, 1)
        template_row.addWidget(self.template_load_btn)
        compose_layout.addLayout(template_row)

        self.attachment_info_label = QLabel("Image attachment: No image attachment")
        self.attachment_info_label.setWordWrap(True)
        self.attachment_info_label.setStyleSheet(
            "padding:10px;"
            "background:#f7faff;"
            "border:1px solid #d9e5f8;"
            "border-radius:16px;"
            "color:#39587f;"
            "font-weight:600;"
        )
        compose_layout.addWidget(self.attachment_info_label)

        self.message_edit = QTextEdit()
        self.message_edit.setPlaceholderText(
            "Example:\n"
            "Hi ${name}, you have unpaid bill of Rp. ${data1}"
        )
        configure_scrollable_text_edit(self.message_edit, min_height=250, always_show_scroll=True)
        if self.allow_custom_message and self.last_blast.get("message"):
            self.message_edit.setPlainText(self.last_blast.get("message", ""))
        compose_layout.addWidget(self.message_edit, 1)
        root.addWidget(compose_box)

        self.reuse_last_msg_chk.toggled.connect(self._handle_reuse_message)

        warning = QLabel(
            "Compliance warning: Use respectful and lawful language only. "
            "Harassment, threats, hate speech, fraud, deception, intimidation, or abusive wording "
            "may lead to internal disciplinary action, account review, and possible legal consequences."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(
            "color:#8a4b00;background:#fff8e4;border:1px solid #ffe0a3;padding:12px;border-radius:18px;font-weight:700;"
        )
        root.addWidget(warning)

        self.summary_label = QLabel(f"Unique recipients selected: 0 / {MAX_BULK_RECIPIENTS}")
        self.summary_label.setWordWrap(True)
        self.summary_label.setStyleSheet(
            "padding:12px;"
            "background:#ffffff;"
            "border:1px solid #d4e2f7;"
            "border-radius:18px;"
            "color:#24466d;"
            "font-weight:800;"
        )
        root.addWidget(self.summary_label)

        scroll.setWidget(content)

        self.prev_list.itemSelectionChanged.connect(self.update_summary)
        self.file_list.itemSelectionChanged.connect(self.update_summary)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.validate_and_accept)
        buttons.rejected.connect(self.reject)
        outer_root.addWidget(buttons)

        self._apply_message_policy()
        self.update_summary()

    def _apply_screen_friendly_size(self):
        screen = self.screen() or QApplication.primaryScreen()
        if not screen:
            self.resize(1100, 820)
            self.setMinimumSize(960, 700)
            return

        g = screen.availableGeometry()
        width = max(960, min(1220, int(g.width() * 0.88)))
        height = max(700, min(900, int(g.height() * 0.88)))
        self.resize(width, height)
        self.setMinimumSize(920, 680)

    def _make_stable_list_widget(self):
        w = QListWidget()
        w.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        w.setUniformItemSizes(True)
        w.setAlternatingRowColors(True)
        w.setWordWrap(False)
        w.setTextElideMode(Qt.TextElideMode.ElideRight)
        w.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        w.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        w.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        w.setSizeAdjustPolicy(QAbstractScrollArea.SizeAdjustPolicy.AdjustIgnored)

        # key fix: stop the list from visually taking over the dialog
        w.setMinimumHeight(220)
        w.setMaximumHeight(340)
        w.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        return w

    def _shorten(self, text, max_len=None):
        max_len = max_len or self.PREVIEW_MAX
        text = str(text or "").replace("\n", " ").strip()
        if len(text) <= max_len:
            return text
        return text[: max_len - 1] + "…"

    def _recipient_preview_text(self, rec):
        vars_map = dict(rec.get("template_vars") or {})
        name = vars_map.get("name") or rec.get("name") or "NULL"

        data_keys = sorted(
            [k for k in vars_map.keys() if k.startswith("data")],
            key=lambda x: int(x[4:]) if x[4:].isdigit() else 999999
        )

        data_preview = []
        for key in data_keys[:3]:
            value = self._shorten(vars_map.get(key), 24)
            data_preview.append(f"{key}={value}")

        preview_text = " | ".join(data_preview) if data_preview else "no extra data"
        prefix = f"row {rec.get('source_row')} | " if rec.get("source_row") else ""
        return f"{prefix}{rec.get('display_number')} | name={self._shorten(name, 24)} | {preview_text}"

    def _rebuild_template_combo(self):
        current_id = None
        if hasattr(self, "template_combo"):
            current_id = self.template_combo.currentData()

        self.template_combo.blockSignals(True)
        self.template_combo.clear()

        if self.allow_custom_message:
            self.template_combo.addItem("Custom message", None)

        for tpl in self.templates:
            self.template_combo.addItem(str(tpl.get("name") or ""), tpl.get("id"))

        if current_id is not None:
            idx = self.template_combo.findData(current_id)
            if idx >= 0:
                self.template_combo.setCurrentIndex(idx)
        elif not self.allow_custom_message and self.template_combo.count() > 0:
            self.template_combo.setCurrentIndex(0)

        self.template_combo.blockSignals(False)

    def _apply_message_policy(self):
        if self.allow_custom_message:
            self.message_edit.setReadOnly(False)
            self.message_edit.setPlaceholderText(
                "Example:\nHi ${name}, you have unpaid bill of Rp. ${data1}"
            )
            self.reuse_last_msg_chk.setEnabled(bool(self.last_blast.get("message")))
            current_tpl = self._find_template_by_id(self.template_combo.currentData())
            self._set_locked_attachment(current_tpl.get("attachment_path") if current_tpl else "")
            return

        self.reuse_last_msg_chk.setChecked(False)
        self.reuse_last_msg_chk.setEnabled(False)
        self.message_edit.clear()
        self.message_edit.setReadOnly(True)
        self._set_locked_attachment("")
        self.message_edit.setPlaceholderText(
            "Custom bulk message is disabled by admin. Please pick a saved template."
        )

        if self.template_combo.count() > 0:
            if self.template_combo.currentData() is None:
                self.template_combo.setCurrentIndex(0)
            self.apply_selected_template()

    def _handle_template_combo_changed(self):
        tpl_id = self.template_combo.currentData()
        if tpl_id is None:
            return
        self.apply_selected_template()

    def _find_template_by_id(self, tpl_id):
        for tpl in self.templates:
            if str(tpl.get("id")) == str(tpl_id):
                return tpl
        return None

    def apply_selected_template(self):
        tpl_id = self.template_combo.currentData()
        tpl = self._find_template_by_id(tpl_id)
        if not tpl:
            if not self.allow_custom_message:
                self.message_edit.clear()
            self._set_locked_attachment("")
            return
        self.message_edit.setPlainText(str(tpl.get("content") or ""))
        self._set_locked_attachment(tpl.get("attachment_path"))

    def _handle_reuse_message(self, checked):
        if self.allow_custom_message and checked and self.last_blast.get("message"):
            self.message_edit.setPlainText(self.last_blast.get("message", ""))

    def _set_locked_attachment(self, path):
        self.selected_attachment_path = normalize_template_attachment_path(path)
        label = format_template_attachment_label(self.selected_attachment_path)
        self.attachment_info_label.setText(f"Image attachment: {label}")

    def get_attachment_path(self):
        return self.selected_attachment_path

    def import_data_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Recipients File",
            "",
            "Spreadsheet Files (*.xlsx *.xls *.csv)"
        )
        if not file_path:
            return

        try:
            records, invalid = read_recipients_from_file(file_path)
        except Exception as e:
            QMessageBox.warning(self, "Import Error", f"Failed to import file:\n{e}")
            return

        self.file_records = records
        self.file_path = file_path
        self.file_list.clear()

        for rec in records:
            full_text = self._recipient_preview_text(rec)
            item = QListWidgetItem(self._shorten(full_text))
            item.setToolTip(full_text)
            item.setData(Qt.ItemDataRole.UserRole, rec)
            self.file_list.addItem(item)

        self.file_path_label.setText(file_path)

        msg = f"Loaded {len(records)} valid recipient row(s)."
        if invalid:
            preview = ", ".join(f"row {row_no}" for row_no, _ in invalid[:5])
            extra = "" if len(invalid) <= 5 else f" and {len(invalid)-5} more"
            msg += f" Invalid phone rows skipped: {preview}{extra}."

        self.file_result_label.setText(msg)
        self.file_list.selectAll()
        self.update_summary()

    def select_all_file(self):
        self.file_list.selectAll()
        self.update_summary()

    def clear_file_selection(self):
        self.file_list.clearSelection()
        self.update_summary()

    def _get_selection_snapshot(self):
        raw = []

        for item in self.prev_list.selectedItems():
            rec = item.data(Qt.ItemDataRole.UserRole)
            if rec:
                raw.append(dict(rec))
                continue

            n = item.text().strip()
            if not n:
                continue

            raw.append({
                "send_number": n,
                "display_number": n,
                "name": None,
                "template_vars": {"name": "NULL"}
            })

        for item in self.file_list.selectedItems():
            rec = item.data(Qt.ItemDataRole.UserRole)
            if not rec:
                continue

            raw.append(dict(rec))

        unique_items, duplicate_count = dedupe_bulk_recipients(raw)
        return {
            "raw_count": len(raw),
            "unique_count": len(unique_items),
            "duplicate_count": duplicate_count,
            "recipients": unique_items
        }

    def get_selected_recipients(self):
        return list(self._get_selection_snapshot().get("recipients") or [])

    def get_message(self):
        if self.allow_custom_message:
            return self.message_edit.toPlainText().strip()

        tpl = self._find_template_by_id(self.template_combo.currentData())
        if not tpl:
            return ""
        return str(tpl.get("content") or "").rstrip()

    def update_summary(self):
        snapshot = self._get_selection_snapshot()
        text = (
            f"Unique recipients selected: {snapshot['unique_count']} / {MAX_BULK_RECIPIENTS}"
        )
        if snapshot["duplicate_count"] > 0:
            text += f"    |    Duplicates auto-removed: {snapshot['duplicate_count']}"
        self.summary_label.setText(text)

    def validate_and_accept(self):
        snapshot = self._get_selection_snapshot()
        recipients = list(snapshot.get("recipients") or [])
        message = self.get_message()
        attachment_path = self.get_attachment_path()

        if not recipients:
            QMessageBox.warning(self, "No Recipients", "Please select at least one recipient.")
            return

        if len(recipients) > MAX_BULK_RECIPIENTS:
            QMessageBox.warning(
                self,
                "Too Many Numbers",
                f"Maximum {MAX_BULK_RECIPIENTS} unique numbers are allowed per blast.\n\n"
                f"You currently selected {len(recipients)} unique numbers."
            )
            return

        if not self.allow_custom_message and not self._find_template_by_id(self.template_combo.currentData()):
            QMessageBox.warning(
                self,
                "Template Required",
                "Custom bulk message is disabled by admin. Please select a saved template."
            )
            return

        if not message:
            QMessageBox.warning(self, "No Message", "Message cannot be empty.")
            return

        if attachment_path and not is_supported_template_image_path(attachment_path, require_exists=True):
            QMessageBox.warning(
                self,
                "Attachment Missing",
                "The selected template image attachment is missing or not a supported image file."
            )
            return

        self.accept()

class TemplateManagerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Manage WhatsApp Templates")
        self.setMinimumSize(950, 620)

        self.templates = load_user_templates()
        self.current_template_id = None
        self.builtin_checkboxes = {}

        root = QVBoxLayout(self)

        title = QLabel("Admin Template Manager")
        title.setStyleSheet("font-size:16px;font-weight:700;")
        root.addWidget(title)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        root.addWidget(splitter, 1)

        # Left panel
        left = QWidget(self)
        left_layout = QVBoxLayout(left)

        left_layout.addWidget(QLabel("User Templates"))
        self.template_list = QListWidget()
        left_layout.addWidget(self.template_list, 1)

        left_btns = QHBoxLayout()
        self.new_btn = QPushButton("New")
        self.delete_btn = QPushButton("Delete")
        left_btns.addWidget(self.new_btn)
        left_btns.addWidget(self.delete_btn)
        left_layout.addLayout(left_btns)

        self.builtin_group = QGroupBox("Built-in Templates")
        builtin_layout = QVBoxLayout(self.builtin_group)
        builtin_info = QLabel(
            "System templates are ready to use. Admin can enable or disable them for users here."
        )
        builtin_info.setWordWrap(True)
        builtin_layout.addWidget(builtin_info)

        for tpl in get_builtin_templates(include_disabled=True):
            checkbox = QCheckBox(str(tpl.get("name") or ""))
            checkbox.setChecked(bool(tpl.get("enabled", True)))
            checkbox.setToolTip(str(tpl.get("content") or ""))
            checkbox.toggled.connect(
                lambda checked, tpl_id=tpl.get("id"): self.on_builtin_template_toggled(tpl_id, checked)
            )
            builtin_layout.addWidget(checkbox)
            self.builtin_checkboxes[str(tpl.get("id"))] = checkbox

        left_layout.addWidget(self.builtin_group)

        splitter.addWidget(left)

        # Right panel
        right = QWidget(self)
        right_layout = QVBoxLayout(right)

        form = QFormLayout()
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Template name")
        form.addRow("Name", self.name_edit)
        right_layout.addLayout(form)

        right_layout.addWidget(QLabel("Template Content"))
        self.content_edit = QTextEdit()
        self.content_edit.setPlaceholderText(
            "Example:\nHi ${name}, you have unpaid bill of Rp. ${data1}"
        )
        configure_scrollable_text_edit(self.content_edit, min_height=260, always_show_scroll=True)
        right_layout.addWidget(self.content_edit, 1)

        attachment_group = QGroupBox("Optional Single Image Attachment")
        attachment_layout = QVBoxLayout(attachment_group)
        attachment_help = QLabel(
            "Admin may lock one JPG / JPEG / PNG image to this template. Users can use the image during bulk send, but cannot replace it."
        )
        attachment_help.setWordWrap(True)
        attachment_layout.addWidget(attachment_help)

        self.attachment_path_label = QLabel("No image attachment")
        self.attachment_path_label.setWordWrap(True)
        self.attachment_path_label.setStyleSheet("padding:6px;border:1px solid #ddd;border-radius:6px;")
        attachment_layout.addWidget(self.attachment_path_label)

        attachment_btns = QHBoxLayout()
        self.attachment_pick_btn = QPushButton("Choose Image")
        self.attachment_clear_btn = QPushButton("Clear Image")
        attachment_btns.addWidget(self.attachment_pick_btn)
        attachment_btns.addWidget(self.attachment_clear_btn)
        attachment_layout.addLayout(attachment_btns)

        right_layout.addWidget(attachment_group)

        help_label = QLabel(
            "Supported placeholders: ${name}, ${data1}, ${data2}, ${data3}, ...\n"
            "Missing values will become NULL.\n"
            "Only user-created templates can be edited here. Built-in templates can be enabled/disabled from the left panel."
        )
        help_label.setWordWrap(True)
        help_label.setStyleSheet("padding:6px;border:1px solid #ddd;border-radius:6px;")
        right_layout.addWidget(help_label)

        action_row = QHBoxLayout()
        self.save_btn = QPushButton("Save")
        self.close_btn = QPushButton("Close")
        action_row.addStretch()
        action_row.addWidget(self.save_btn)
        action_row.addWidget(self.close_btn)
        right_layout.addLayout(action_row)

        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        self.template_list.itemSelectionChanged.connect(self.on_template_selected)
        self.new_btn.clicked.connect(self.new_template)
        self.delete_btn.clicked.connect(self.delete_template)
        self.save_btn.clicked.connect(self.save_template)
        self.attachment_pick_btn.clicked.connect(self.choose_attachment)
        self.attachment_clear_btn.clicked.connect(self.clear_attachment)
        self.close_btn.clicked.connect(self.accept)

        self.refresh_list()

    def refresh_list(self):
        self.templates = load_user_templates()
        self.template_list.clear()

        for tpl in self.templates:
            text = tpl["name"]
            if tpl.get("updated_at"):
                text += f"  |  {format_user_datetime_text(tpl['updated_at'], default=str(tpl['updated_at']))}"
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, tpl["id"])
            self.template_list.addItem(item)

    def get_template_by_id(self, tpl_id):
        for tpl in self.templates:
            if str(tpl.get("id")) == str(tpl_id):
                return tpl
        return None

    def on_template_selected(self):
        item = self.template_list.currentItem()
        if not item:
            return

        tpl_id = item.data(Qt.ItemDataRole.UserRole)
        tpl = self.get_template_by_id(tpl_id)
        if not tpl:
            return

        self.current_template_id = tpl["id"]
        self.name_edit.setText(str(tpl.get("name") or ""))
        self.content_edit.setPlainText(str(tpl.get("content") or ""))
        self._set_attachment_path(tpl.get("attachment_path"))

    def new_template(self):
        self.current_template_id = None
        self.template_list.clearSelection()
        self.name_edit.clear()
        self.content_edit.clear()
        self._set_attachment_path("")
        self.name_edit.setFocus()

    def _set_attachment_path(self, path):
        normalized = normalize_template_attachment_path(path)
        self.attachment_path_label.setProperty("attachment_path", normalized)
        self.attachment_path_label.setText(format_template_attachment_label(normalized))

    def _get_attachment_path(self):
        return normalize_template_attachment_path(self.attachment_path_label.property("attachment_path"))

    def choose_attachment(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Template Image",
            "",
            "Image Files (*.jpg *.jpeg *.png)"
        )
        if not file_path:
            return

        if not is_supported_template_image_path(file_path, require_exists=True):
            QMessageBox.warning(self, "Invalid Image", "Please choose a JPG, JPEG, or PNG image.")
            return

        self._set_attachment_path(file_path)

    def clear_attachment(self):
        self._set_attachment_path("")

    def save_template(self):
        name = self.name_edit.text().strip()
        content = self.content_edit.toPlainText().rstrip()
        attachment_path = self._get_attachment_path()

        if not name:
            QMessageBox.warning(self, "Missing Name", "Template name cannot be empty.")
            return

        if not content:
            QMessageBox.warning(self, "Missing Content", "Template content cannot be empty.")
            return

        if attachment_path and not is_supported_template_image_path(attachment_path, require_exists=True):
            QMessageBox.warning(self, "Invalid Image", "Attachment must be an existing JPG, JPEG, or PNG image.")
            return

        templates = load_user_templates()
        existing_catalog = load_templates(include_disabled_builtin=True)

        for tpl in existing_catalog:
            if tpl["name"].strip().lower() == name.lower() and str(tpl["id"]) != str(self.current_template_id):
                QMessageBox.warning(self, "Duplicate Name", "Another template already uses this name.")
                return

        if self.current_template_id:
            updated = False
            for tpl in templates:
                if str(tpl["id"]) == str(self.current_template_id):
                    tpl["name"] = name
                    tpl["content"] = content
                    tpl["attachment_path"] = attachment_path
                    tpl["updated_at"] = datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
                    updated = True
                    break

            if not updated:
                templates.append({
                    "id": self.current_template_id,
                    "name": name,
                    "content": content,
                    "attachment_path": attachment_path,
                    "updated_at": datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
                })
        else:
            self.current_template_id = uuid.uuid4().hex
            templates.append({
                "id": self.current_template_id,
                "name": name,
                "content": content,
                "attachment_path": attachment_path,
                "updated_at": datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
            })

        save_templates(templates)
        self.refresh_list()

        for i in range(self.template_list.count()):
            item = self.template_list.item(i)
            if str(item.data(Qt.ItemDataRole.UserRole)) == str(self.current_template_id):
                self.template_list.setCurrentRow(i)
                break

        QMessageBox.information(self, "Saved", "Template saved successfully.")

    def delete_template(self):
        item = self.template_list.currentItem()
        if not item:
            QMessageBox.warning(self, "No Selection", "Please select a template first.")
            return

        tpl_id = item.data(Qt.ItemDataRole.UserRole)
        tpl = self.get_template_by_id(tpl_id)
        if not tpl:
            return

        reply = QMessageBox.question(
            self,
            "Delete Template",
            f"Delete template '{tpl['name']}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        templates = [x for x in load_user_templates() if str(x.get("id")) != str(tpl_id)]
        save_templates(templates)

        self.current_template_id = None
        self.name_edit.clear()
        self.content_edit.clear()
        self._set_attachment_path("")
        self.refresh_list()
        QMessageBox.information(self, "Deleted", "Template deleted.")

    def on_builtin_template_toggled(self, template_id, checked):
        set_builtin_template_enabled(template_id, checked)

        parent = self.parent()
        if parent and hasattr(parent, "apply_bulk_message_policy_ui"):
            parent.apply_bulk_message_policy_ui()


class TemplateReplyDialog(QDialog):
    def __init__(self, chat_context=None, reply_recipient=None, matched_recipient=None, templates=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Reply With Template")
        self.setMinimumSize(760, 560)

        self.chat_context = dict(chat_context or {})
        self.reply_recipient = dict(reply_recipient or {})
        self.matched_recipient = dict(matched_recipient or {})
        self.templates = list(templates or [])

        root = QVBoxLayout(self)

        title = QLabel("WhatsApp Reply Template")
        title.setStyleSheet("font-size:16px;font-weight:700;")
        root.addWidget(title)

        contact_label = self.chat_context.get("title") or self.chat_context.get("phone") or "Current conversation"
        phone_label = self.chat_context.get("phone") or "-"

        match_text = "Matched from last blast data."
        if not self.matched_recipient:
            match_text = "No last blast match found. Template stays editable so user can adjust values manually."

        info = QLabel(
            f"Current chat: {contact_label}\n"
            f"Phone: {phone_label}\n"
            f"{match_text}"
        )
        info.setWordWrap(True)
        info.setStyleSheet("padding:8px;border:1px solid #9ab2d8;background:#f4f7ff;")
        root.addWidget(info)

        row = QHBoxLayout()
        row.addWidget(QLabel("Template"))
        self.template_combo = QComboBox()
        for tpl in self.templates:
            self.template_combo.addItem(str(tpl.get("name") or ""), tpl.get("id"))
        self.load_btn = QPushButton("Load Template")
        row.addWidget(self.template_combo, 1)
        row.addWidget(self.load_btn)
        root.addLayout(row)

        helper = QLabel(
            "Placeholders such as ${name}, ${data1}, ${data2}, and so on will be filled from the current chat "
            "and the last blast match when available. If some fields are still missing, the app will ask for temporary values. "
            "You can edit the final message before inserting it into the chat."
        )
        helper.setWordWrap(True)
        helper.setStyleSheet("padding:6px;border:1px solid #ddd;border-radius:6px;")
        root.addWidget(helper)

        self.message_edit = QTextEdit()
        configure_scrollable_text_edit(self.message_edit, min_height=240, always_show_scroll=True)
        root.addWidget(self.message_edit, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.insert_btn = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.insert_btn.setText("Insert To Chat")
        buttons.accepted.connect(self.accept_with_validation)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

        self.template_combo.currentIndexChanged.connect(self.apply_selected_template)
        self.load_btn.clicked.connect(self.apply_selected_template)

        if self.template_combo.count() > 0:
            self.template_combo.setCurrentIndex(0)
            self.apply_selected_template()

    def _find_template_by_id(self, tpl_id):
        for tpl in self.templates:
            if str(tpl.get("id")) == str(tpl_id):
                return tpl
        return None

    def apply_selected_template(self):
        tpl = self._find_template_by_id(self.template_combo.currentData())
        if not tpl:
            self.message_edit.clear()
            return

        template_text = str(tpl.get("content") or "")
        global_values = prompt_template_global_values(
            self,
            template_text,
            [self.reply_recipient],
            action_label="this reply"
        )
        if global_values is None:
            return

        rendered = render_message_template(
            template_text,
            self.reply_recipient,
            global_values=global_values
        )
        self.message_edit.setPlainText(rendered)

    def get_message(self):
        return self.message_edit.toPlainText().rstrip()

    def accept_with_validation(self):
        if not self.get_message().strip():
            QMessageBox.warning(self, "Empty Message", "Message cannot be empty.")
            return
        self.accept()

class CollectionBlastDock(QDockWidget):
    def __init__(self, parent=None):
        super().__init__("Collection WhatsApp Blast", parent)
        self.records = []
        self.templates = []
        self.allow_custom_message = False
        self.selected_attachment_path = ""

        self.setMinimumWidth(420)
        self.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable |
            QDockWidget.DockWidgetFeature.DockWidgetFloatable
        )

        root_widget = QWidget(self)
        root = QVBoxLayout(root_widget)

        self.info_label = QLabel(
            "Open My Collections page and wait for /api/staff/collections response."
        )
        self.info_label.setWordWrap(True)
        root.addWidget(self.info_label)

        self.count_label = QLabel("Found: 0 numbers")
        root.addWidget(self.count_label)

        btn_row = QHBoxLayout()
        self.select_all_btn = QPushButton("Select All")
        self.clear_btn = QPushButton("Clear")
        btn_row.addWidget(self.select_all_btn)
        btn_row.addWidget(self.clear_btn)
        root.addLayout(btn_row)

        self.list_widget = QListWidget()
        self.list_widget.setMinimumHeight(220)
        self.list_widget.setUniformItemSizes(True)
        self.list_widget.setAlternatingRowColors(True)
        root.addWidget(self.list_widget, 1)

        root.addWidget(QLabel("Use WhatsApp account:"))
        self.wa_combo = QComboBox()
        root.addWidget(self.wa_combo)

        root.addWidget(QLabel("Saved Template:"))
        tpl_row = QHBoxLayout()
        self.template_combo = QComboBox()
        self.template_combo.currentIndexChanged.connect(self._handle_template_combo_changed)
        self.template_load_btn = QPushButton("Load Template")
        tpl_row.addWidget(self.template_combo, 1)
        tpl_row.addWidget(self.template_load_btn)
        root.addLayout(tpl_row)

        self.template_load_btn.clicked.connect(self.apply_selected_template)

        self.attachment_info_label = QLabel("Image attachment: No image attachment")
        self.attachment_info_label.setWordWrap(True)
        self.attachment_info_label.setStyleSheet("padding:6px;border:1px solid #ddd;border-radius:6px;")
        root.addWidget(self.attachment_info_label)

        root.addWidget(QLabel("Message:"))
        self.message_edit = QTextEdit()
        self.message_edit.setPlaceholderText("Type WhatsApp message here...")
        configure_scrollable_text_edit(self.message_edit, min_height=140, always_show_scroll=True)
        root.addWidget(self.message_edit, 1)

        self.queue_btn = QPushButton("Queue / Start Blast")
        root.addWidget(self.queue_btn)

        self.setWidget(root_widget)
        self._rebuild_template_combo()
        self._apply_custom_message_policy()

    def _rebuild_template_combo(self):
        current_id = self.template_combo.currentData()

        self.template_combo.blockSignals(True)
        self.template_combo.clear()

        if self.allow_custom_message:
            self.template_combo.addItem("Custom message", None)

        for tpl in self.templates:
            self.template_combo.addItem(str(tpl.get("name") or ""), tpl.get("id"))

        if current_id is not None:
            idx = self.template_combo.findData(current_id)
            if idx >= 0:
                self.template_combo.setCurrentIndex(idx)
        elif not self.allow_custom_message and self.template_combo.count() > 0:
            self.template_combo.setCurrentIndex(0)

        self.template_combo.blockSignals(False)

    def _apply_custom_message_policy(self):
        if self.allow_custom_message:
            self.message_edit.setReadOnly(False)
            self.message_edit.setPlaceholderText("Type WhatsApp message here...")
            current_tpl = None
            for tpl in self.templates:
                if str(tpl.get("id")) == str(self.template_combo.currentData()):
                    current_tpl = tpl
                    break
            self._set_locked_attachment(current_tpl.get("attachment_path") if current_tpl else "")
            return

        self.message_edit.clear()
        self.message_edit.setReadOnly(True)
        self._set_locked_attachment("")
        self.message_edit.setPlaceholderText(
            "Custom bulk message is disabled by admin. Please pick a saved template."
        )

        if self.template_combo.count() > 0:
            if self.template_combo.currentData() is None:
                self.template_combo.setCurrentIndex(0)
            self.apply_selected_template()

    def _handle_template_combo_changed(self):
        tpl_id = self.template_combo.currentData()
        if tpl_id is None:
            return
        self.apply_selected_template()

    def set_custom_message_enabled(self, enabled):
        self.allow_custom_message = bool(enabled)
        self._rebuild_template_combo()
        self._apply_custom_message_policy()

    def set_templates(self, templates):
        self.templates = list(templates or [])
        self._rebuild_template_combo()
        self._apply_custom_message_policy()

    def apply_selected_template(self):
        tpl_id = self.template_combo.currentData()
        if tpl_id is None:
            if not self.allow_custom_message:
                self.message_edit.clear()
            self._set_locked_attachment("")
            return

        for tpl in self.templates:
            if str(tpl.get("id")) == str(tpl_id):
                self.message_edit.setPlainText(str(tpl.get("content") or ""))
                self._set_locked_attachment(tpl.get("attachment_path"))
                return

        if not self.allow_custom_message:
            self.message_edit.clear()
        self._set_locked_attachment("")

    def get_effective_message(self):
        if self.allow_custom_message:
            return self.message_edit.toPlainText().strip()

        tpl_id = self.template_combo.currentData()
        for tpl in self.templates:
            if str(tpl.get("id")) == str(tpl_id):
                return str(tpl.get("content") or "").rstrip()
        return ""

    def _set_locked_attachment(self, path):
        self.selected_attachment_path = normalize_template_attachment_path(path)
        self.attachment_info_label.setText(
            f"Image attachment: {format_template_attachment_label(self.selected_attachment_path)}"
        )

    def get_effective_attachment_path(self):
        return self.selected_attachment_path

    def set_waiting(self, text):
        self.info_label.setText(text)

    def set_records(self, records):
        self.records = list(records or [])
        self.list_widget.clear()

        for rec in self.records:
            text = f"{rec['uid']}  |  {rec['display_number']}"
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, rec)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            self.list_widget.addItem(item)

        self.count_label.setText(f"Found: {len(self.records)} numbers")

    def selected_records(self):
        out = []
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                rec = item.data(Qt.ItemDataRole.UserRole)
                if rec:
                    out.append(rec)
        return out

    def select_all(self):
        for i in range(self.list_widget.count()):
            self.list_widget.item(i).setCheckState(Qt.CheckState.Checked)

    def clear_all(self):
        for i in range(self.list_widget.count()):
            self.list_widget.item(i).setCheckState(Qt.CheckState.Unchecked)

    def set_whatsapp_accounts(self, accounts, selected_account_id=None):
        current_id = self.selected_account_id()
        self.wa_combo.clear()

        for account_id, label in accounts:
            self.wa_combo.addItem(label, account_id)

        target_id = selected_account_id if selected_account_id is not None else current_id
        if target_id is not None:
            idx = self.wa_combo.findData(target_id)
            if idx >= 0:
                self.wa_combo.setCurrentIndex(idx)

    def selected_account_id(self):
        return self.wa_combo.currentData()

class LockedBrowserApiHandler(BaseHTTPRequestHandler):
    server_version = "LockedBrowserAPI/1.0"

    def log_message(self, format, *args):
        return

    def _send_json(self, status_code, payload):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _is_authorized(self):
        token = str(self.headers.get(API_HEADER_NAME, "") or "").strip()
        auth = str(self.headers.get("Authorization", "") or "").strip()

        if not token and auth.lower().startswith("bearer "):
            token = auth[7:].strip()

        return token == API_TOKEN

    def _require_auth(self):
        if self._is_authorized():
            return True

        self._send_json(401, {
            "ok": False,
            "message": "Unauthorized"
        })
        return False

    def _read_json_body(self):
        try:
            content_length = int(self.headers.get("Content-Length", "0") or 0)
        except Exception:
            content_length = 0

        raw = self.rfile.read(content_length) if content_length > 0 else b""
        if not raw:
            return {}

        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _get_payload_value(self, data, *keys):
        for key in keys:
            if key in data:
                return data.get(key)
        return None

    def do_GET(self):
        if not self._require_auth():
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/api/v1/get/bad-word-stats":
            start_date = parse_ymd_date(query.get("from", [today_key()])[0]) or parse_ymd_date(today_key())
            end_date = parse_ymd_date(query.get("to", [today_key()])[0]) or parse_ymd_date(today_key())

            if start_date > end_date:
                start_date, end_date = end_date, start_date

            raw_days = load_bad_word_counter().get("days", {})
            items = []

            total_events = 0
            total_hits = 0

            for day in sorted(raw_days.keys()):
                day_obj = parse_ymd_date(day)
                if not day_obj:
                    continue
                if day_obj < start_date or day_obj > end_date:
                    continue

                bucket = raw_days.get(day, {})
                items.append({
                    "date": day,
                    "events": int(bucket.get("events", 0)),
                    "total_hits": int(bucket.get("total_hits", 0)),
                    "by_source": dict(bucket.get("by_source", {})),
                    "by_word": dict(bucket.get("by_word", {}))
                })

                total_events += int(bucket.get("events", 0))
                total_hits += int(bucket.get("total_hits", 0))

            self._send_json(200, {
                "ok": True,
                "from": start_date.isoformat(),
                "to": end_date.isoformat(),
                "total_events": total_events,
                "total_hits": total_hits,
                "items": items
            })
            return

        if path == "/api/v1/get/templates":
            page = safe_int(query.get("page", ["1"])[0], 1, 1, 1000000)
            page_size = safe_int(query.get("pageSize", ["20"])[0], 20, 1, 500)
            data = paginate_items(load_templates(), page, page_size)
            self._send_json(200, {
                "ok": True,
                **data
            })
            return

        if path == "/api/v1/get/send-receive-messages":
            page = safe_int(query.get("page", ["1"])[0], 1, 1, 1000000)
            page_size = safe_int(query.get("pageSize", ["20"])[0], 20, 1, 500)
            logs = list(reversed(load_manual_send_log()))
            data = paginate_items(logs, page, page_size)
            self._send_json(200, {
                "ok": True,
                **data
            })
            return

        if path == "/api/v1/live-view":
            main_window = getattr(self.server, "main_window", None)
            if not main_window:
                self._send_json(500, {
                    "ok": False,
                    "message": "Main window is not available"
                })
                return

            fps = safe_int(query.get("fps", ["2"])[0], 2, 1, 10)
            quality = safe_int(query.get("quality", ["70"])[0], 70, 20, 95)
            max_width = safe_int(query.get("maxWidth", ["1280"])[0], 1280, 320, 2560)
            scope = str(query.get("scope", ["window"])[0] or "window").strip().lower()
            if scope not in {"window", "tab"}:
                scope = "window"

            boundary = "frame"

            self.send_response(200)
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Connection", "close")
            self.send_header("Content-Type", f"multipart/x-mixed-replace; boundary={boundary}")
            self.end_headers()

            frame_delay = 1.0 / max(1, fps)

            try:
                while True:
                    done = threading.Event()
                    result = {}

                    main_window.live_view_request_signal.emit({
                        "done": done,
                        "result": result,
                        "quality": quality,
                        "max_width": max_width,
                        "scope": scope
                    })

                    if not done.wait(5):
                        break

                    if not result.get("ok"):
                        break

                    frame = result.get("frame") or b""
                    meta = result.get("meta") or {}

                    header = (
                        f"--{boundary}\r\n"
                        f"Content-Type: image/jpeg\r\n"
                        f"Content-Length: {len(frame)}\r\n"
                        f"X-Captured-At: {meta.get('captured_at', '')}\r\n"
                        f"X-Current-Tab: {meta.get('current_tab', '')}\r\n"
                        f"X-Current-Url: {meta.get('current_url', '')}\r\n"
                        f"X-Scope: {meta.get('scope', '')}\r\n"
                        f"X-Width: {meta.get('width', '')}\r\n"
                        f"X-Height: {meta.get('height', '')}\r\n"
                        f"\r\n"
                    ).encode("utf-8", errors="ignore")

                    self.wfile.write(header)
                    self.wfile.write(frame)
                    self.wfile.write(b"\r\n")
                    self.wfile.flush()

                    time.sleep(frame_delay)

            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:
                pass

            return        

        self._send_json(404, {
            "ok": False,
            "message": "Not found"
        })

    def do_POST(self):
        if not self._require_auth():
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        payload = self._read_json_body()

        if path == "/api/v1/create/template":
            name = str(self._get_payload_value(payload, "template name", "template_name", "name") or "").strip()
            content = str(self._get_payload_value(payload, "content") or "").rstrip()
            attachment_path = normalize_template_attachment_path(
                self._get_payload_value(payload, "attachment_path", "attachment", "image_path")
            )

            if not name or not content:
                self._send_json(400, {
                    "ok": False,
                    "message": "template name and content are required"
                })
                return

            if attachment_path and not is_supported_template_image_path(attachment_path, require_exists=True):
                self._send_json(400, {
                    "ok": False,
                    "message": "attachment_path must be an existing JPG, JPEG, or PNG file"
                })
                return

            templates = load_templates()
            for tpl in templates:
                if str(tpl.get("name", "")).strip().lower() == name.lower():
                    self._send_json(409, {
                        "ok": False,
                        "message": "Template already exists"
                    })
                    return

            templates.append({
                "id": uuid.uuid4().hex,
                "name": name,
                "content": content,
                "attachment_path": attachment_path,
                "updated_at": datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
            })
            save_templates(templates)

            self._send_json(200, {
                "ok": True,
                "message": "Template created"
            })
            return

        if path == "/api/v1/edit/template":
            name = str(self._get_payload_value(payload, "template name", "template_name", "name") or "").strip()
            content = str(self._get_payload_value(payload, "content") or "").rstrip()
            attachment_keys = {"attachment_path", "attachment", "image_path"}
            has_attachment_field = isinstance(payload, dict) and any(key in payload for key in attachment_keys)
            attachment_path = normalize_template_attachment_path(
                self._get_payload_value(payload, "attachment_path", "attachment", "image_path")
            )

            if not name or not content:
                self._send_json(400, {
                    "ok": False,
                    "message": "template name and content are required"
                })
                return

            if has_attachment_field and attachment_path and not is_supported_template_image_path(attachment_path, require_exists=True):
                self._send_json(400, {
                    "ok": False,
                    "message": "attachment_path must be an existing JPG, JPEG, or PNG file"
                })
                return

            templates = load_templates()
            updated = False

            for tpl in templates:
                if str(tpl.get("name", "")).strip().lower() == name.lower():
                    tpl["content"] = content
                    if has_attachment_field:
                        tpl["attachment_path"] = attachment_path
                    tpl["updated_at"] = datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
                    updated = True
                    break

            if not updated:
                self._send_json(404, {
                    "ok": False,
                    "message": "Template not found"
                })
                return

            save_templates(templates)
            self._send_json(200, {
                "ok": True,
                "message": "Template updated"
            })
            return

        if path == "/api/v1/delete/template":
            name = str(self._get_payload_value(payload, "template name", "template_name", "name") or "").strip()

            if not name:
                self._send_json(400, {
                    "ok": False,
                    "message": "template name is required"
                })
                return

            templates = load_templates()
            kept = [tpl for tpl in templates if str(tpl.get("name", "")).strip().lower() != name.lower()]

            if len(kept) == len(templates):
                self._send_json(404, {
                    "ok": False,
                    "message": "Template not found"
                })
                return

            save_templates(kept)
            self._send_json(200, {
                "ok": True,
                "message": "Template deleted"
            })
            return

        if path == "/api/v1/update/bad-words":
            bw_text = self._get_payload_value(payload, "bw.txt", "bw_txt", "content")
            bw_text = str(bw_text or "")

            with open(BAD_WORDS_FILE, "w", encoding="utf-8") as f:
                f.write(bw_text.replace("\r\n", "\n"))

            self._send_json(200, {
                "ok": True,
                "message": "Bad words file replaced",
                "note": "Live WhatsApp censor list will fully refresh after WhatsApp pages reload."
            })
            return

        self._send_json(404, {
            "ok": False,
            "message": "Not found"
        })

class UserStatsDialog(QDialog):
    def __init__(self, day_key_value=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("User Daily Stats")
        self.setMinimumSize(980, 700)

        day_key_value = day_key_value or today_key()
        stats = get_activity_bucket_for_day(day_key_value)
        msg_totals = get_message_totals(day_key_value)

        root = QVBoxLayout(self)

        title = QLabel(f"User Stats - {day_key_value}")
        title.setStyleSheet("font-size:16px;font-weight:700;")
        root.addWidget(title)

        summary = QLabel(
            f"Screen time in app: {format_duration_hms(stats['screen_time_seconds'])}\n"
            f"Blast jobs today: {stats['blast_jobs']}\n"
            f"Blast recipient count today: {stats['blast_messages']}\n"
            f"Manual sends today: {stats['manual_sends']}\n"
            f"Replies received today: {stats['incoming_replies']}\n"
            f"Unique touched contacts today: {stats['touched_contacts_count']}\n"
            f"\n"
            f"Sent total: {msg_totals['sent_total']}\n"
            f"Received total: {msg_totals['received_total']}\n"
            f"Sent total at {day_key_value}: {msg_totals['sent_total_at_date']}\n"
            f"Receive total at {day_key_value}: {msg_totals['received_total_at_date']}\n"
            f"\n"
            f"Last updated: {format_user_datetime_text(stats['last_updated'], default='-')}"
        )
        summary.setWordWrap(True)
        summary.setStyleSheet("padding:8px;border:1px solid #9ab2d8;background:#f4f7ff;")
        root.addWidget(summary)

        splitter = QSplitter(Qt.Orientation.Vertical, self)
        root.addWidget(splitter, 1)

        self.tab_table = QTableWidget(0, 3, self)
        prepare_plain_table_widget(self.tab_table, ["Tab", "Duration", "Seconds"], stretch_last=False)
        self.tab_table.setColumnWidth(0, 260)
        self.tab_table.setColumnWidth(1, 180)
        self.tab_table.setColumnWidth(2, 120)
        splitter.addWidget(self.tab_table)

        tab_items = sorted(
            stats["tab_seconds"].items(),
            key=lambda x: int(x[1] or 0),
            reverse=True
        )
        self.tab_table.setRowCount(len(tab_items))
        for row_index, (tab_name, sec) in enumerate(tab_items):
            sec = int(sec or 0)
            self.tab_table.setItem(row_index, 0, make_table_item(str(tab_name)))
            self.tab_table.setItem(row_index, 1, make_table_item(format_duration_hms(sec)))
            self.tab_table.setItem(
                row_index,
                2,
                make_table_item(str(sec), align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            )

        if self.tab_table.rowCount() > 0:
            select_first_table_row(self.tab_table)

        touched_box = QTextEdit(self)
        touched_box.setReadOnly(True)
        touched_box.setPlainText("\n".join(stats["touched_contacts"]) if stats["touched_contacts"] else "-")
        splitter.addWidget(touched_box)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        root.addWidget(close_btn)

class ContactLogDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Contact Timeline Note")
        self.setMinimumSize(520, 320)

        root = QVBoxLayout(self)

        info = QLabel(
            "Suggested usage:\n"
            "- note important responses\n"
            "- objections / reluctance\n"
            "- promised follow-up date\n"
            "- customer tone / risk / preference\n"
            "- any detail useful for future conversation"
        )
        info.setWordWrap(True)
        info.setStyleSheet("padding:8px;border:1px solid #ddd;border-radius:6px;")
        root.addWidget(info)

        form = QFormLayout()
        self.type_combo = QComboBox()
        self.type_combo.addItems(["note", "follow_up", "response", "promise", "risk", "other"])
        form.addRow("Log Type", self.type_combo)
        root.addLayout(form)

        root.addWidget(QLabel("Detail"))
        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText(
            "Example: Contact was reached, but showed reluctant response and asked to be contacted again tomorrow afternoon."
        )
        root.addWidget(self.text_edit, 1)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def get_entry(self):
        return {
            "type": self.type_combo.currentText().strip(),
            "text": self.text_edit.toPlainText().strip()
        }

    def accept(self):
        entry = self.get_entry()
        if not entry["text"]:
            QMessageBox.warning(self, "Missing Note", "Please write a note first.")
            return
        super().accept()

class ContactEditorDialog(QDialog):
    def __init__(self, contact=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Contact Profile")
        self.setMinimumSize(1180, 820)
        self.resize(1240, 860)

        self.contact = normalize_contact_record(contact or {})
        self.is_new = not bool(self.contact.get("send_number"))
        self.original_send_number = self.contact.get("send_number", "")

        root = QVBoxLayout(self)

        guide = QLabel(
            "Contact Management Guide\n"
            "- Keep as much useful detail as possible.\n"
            "- Use the color flag only as a personal management aid; the app does not assign meaning to the colors.\n"
            "- Use summary for quick overview, and details for richer background/context.\n"
            "- Timeline notes should record important updates with date and detail."
        )
        guide.setWordWrap(True)
        guide.setStyleSheet("padding:10px;border:1px solid #9ab2d8;background:#f4f7ff;")
        root.addWidget(guide)

        self.tabs = QTabWidget(self)
        self.tabs.setDocumentMode(True)
        root.addWidget(self.tabs, 1)

        # --------------------------
        # PROFILE TAB
        # --------------------------
        profile_tab = QWidget(self)
        profile_root = QVBoxLayout(profile_tab)

        profile_scroll = QScrollArea(self)
        profile_scroll.setWidgetResizable(True)

        profile_container = QWidget()
        profile_layout = QVBoxLayout(profile_container)
        profile_layout.setContentsMargins(12, 12, 12, 12)
        profile_layout.setSpacing(10)

        self.stats_label = QLabel("")
        self.stats_label.setStyleSheet("padding:8px;background:#f4f7ff;border:1px solid #9ab2d8;")
        profile_layout.addWidget(self.stats_label)

        fields_grid = QGridLayout()
        fields_grid.setHorizontalSpacing(14)
        fields_grid.setVerticalSpacing(8)

        # widgets
        self.phone_edit = QLineEdit(self.contact.get("send_number", ""))
        self.display_phone_edit = QLineEdit(self.contact.get("display_number", ""))
        self.name_edit = QLineEdit(self.contact.get("name", ""))
        self.email_edit = QLineEdit(self.contact.get("email", ""))
        self.company_edit = QLineEdit(self.contact.get("company", ""))
        self.title_edit = QLineEdit(self.contact.get("title", ""))
        self.city_edit = QLineEdit(self.contact.get("city", ""))
        self.tags_edit = QLineEdit(self.contact.get("tags", ""))

        self.flag_combo = QComboBox()
        for key, meta in CONTACT_FLAG_META.items():
            self.flag_combo.addItem(meta["label"], key)
        idx = self.flag_combo.findData(self.contact.get("color_flag", "none"))
        if idx >= 0:
            self.flag_combo.setCurrentIndex(idx)

        def add_field(row, col, label_text, widget):
            box = QWidget()
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(0, 0, 0, 0)
            box_layout.setSpacing(4)

            lbl = QLabel(label_text)
            lbl.setStyleSheet("font-weight:600;")
            box_layout.addWidget(lbl)
            box_layout.addWidget(widget)

            fields_grid.addWidget(box, row, col)

        add_field(0, 0, "Phone", self.phone_edit)
        add_field(0, 1, "Display Phone", self.display_phone_edit)

        add_field(1, 0, "Name", self.name_edit)
        add_field(1, 1, "Email", self.email_edit)

        add_field(2, 0, "Company", self.company_edit)
        add_field(2, 1, "Title", self.title_edit)

        add_field(3, 0, "City", self.city_edit)
        add_field(3, 1, "Tags", self.tags_edit)

        add_field(4, 0, "Flag", self.flag_combo)

        profile_layout.addLayout(fields_grid)

        profile_layout.addWidget(QLabel("Summary"))
        self.summary_edit = QTextEdit()
        self.summary_edit.setMinimumHeight(120)
        self.summary_edit.setPlainText(self.contact.get("summary", ""))
        profile_layout.addWidget(self.summary_edit)

        profile_layout.addWidget(QLabel("Detailed Background / Notes"))
        self.details_edit = QTextEdit()
        self.details_edit.setMinimumHeight(220)
        self.details_edit.setPlainText(self.contact.get("details", ""))
        profile_layout.addWidget(self.details_edit)

        import_info = self.contact.get("latest_import_vars") or {}
        self.import_preview = QTextEdit()
        self.import_preview.setReadOnly(True)
        self.import_preview.setMinimumHeight(150)
        self.import_preview.setPlainText(
            json.dumps(import_info, indent=2, ensure_ascii=False) if import_info else "-"
        )
        profile_layout.addWidget(QLabel("Latest Imported Fields"))
        profile_layout.addWidget(self.import_preview)

        profile_layout.addStretch()

        profile_scroll.setWidget(profile_container)
        profile_root.addWidget(profile_scroll)

        self.tabs.addTab(profile_tab, "Profile")

        # --------------------------
        # TIMELINE TAB
        # --------------------------
        timeline_tab = QWidget(self)
        timeline_layout = QVBoxLayout(timeline_tab)
        timeline_layout.setContentsMargins(12, 12, 12, 12)
        timeline_layout.setSpacing(8)

        timeline_title = QLabel("Timeline / Update Log")
        timeline_title.setStyleSheet("font-size:14px;font-weight:700;")
        timeline_layout.addWidget(timeline_title)

        helper = QLabel(
            "Use timeline entries for follow-up promises, objections, risk notes, contact preferences, and important dated updates."
        )
        helper.setWordWrap(True)
        helper.setStyleSheet("padding:8px;border:1px solid #9ab2d8;background:#f4f7ff;")
        timeline_layout.addWidget(helper)

        self.timeline_table = QTableWidget(0, 3, self)
        prepare_plain_table_widget(self.timeline_table, ["Timestamp", "Type", "Timeline Note"], stretch_last=True)
        self.timeline_table.setMinimumHeight(260)
        self.timeline_table.setColumnWidth(0, 180)
        self.timeline_table.setColumnWidth(1, 120)
        timeline_layout.addWidget(self.timeline_table, 1)

        tl_btns = QHBoxLayout()
        self.add_log_btn = QPushButton("Add Timeline Note")
        self.delete_log_btn = QPushButton("Delete Selected Log")
        tl_btns.addWidget(self.add_log_btn)
        tl_btns.addWidget(self.delete_log_btn)
        tl_btns.addStretch()
        timeline_layout.addLayout(tl_btns)

        self.tabs.addTab(timeline_tab, "Timeline")

        # --------------------------
        # BUTTONS
        # --------------------------
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

        self.add_log_btn.clicked.connect(self.add_timeline_note)
        self.delete_log_btn.clicked.connect(self.delete_selected_timeline)

        self.refresh_stats()
        self.refresh_timeline()

    def refresh_stats(self):
        self.stats_label.setText(
            f"Last chat: {self.contact.get('last_chat_at') or '-'}    |    "
            f"Last outgoing: {self.contact.get('last_outgoing_at') or '-'}    |    "
            f"Last incoming: {self.contact.get('last_incoming_at') or '-'}"
        )

    def refresh_timeline(self):
        rows = list(self.contact.get("timeline") or [])
        rows = sorted(rows, key=lambda x: str(x.get("timestamp") or ""), reverse=True)
        self.timeline_table.setRowCount(0)

        if not rows:
            return

        self.timeline_table.setRowCount(len(rows))
        for row_index, entry in enumerate(rows):
            entry_type = str(entry.get("type") or "note").strip() or "note"
            timestamp_item = make_table_item(
                format_user_datetime_text(entry.get("timestamp"), default="-"),
                user_data=str(entry.get("id") or "")
            )
            type_item = make_table_item(entry_type.replace("_", " ").title())
            text_item = make_table_item(str(entry.get("text") or "").strip())
            self.timeline_table.setItem(row_index, 0, timestamp_item)
            self.timeline_table.setItem(row_index, 1, type_item)
            self.timeline_table.setItem(row_index, 2, text_item)

        select_first_table_row(self.timeline_table)

    def add_timeline_note(self):
        dlg = ContactLogDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        entry = dlg.get_entry()
        append_contact_timeline_entry(
            self.contact,
            entry["type"],
            entry["text"],
            actor="user",
            when_text=contact_now()
        )
        self.contact["updated_at"] = contact_now()
        self.refresh_timeline()

    def delete_selected_timeline(self):
        row = self.timeline_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Please select one log entry first.")
            return

        if not require_admin_password_from_widget(self):
            QMessageBox.warning(self, "Error", "Incorrect password.")
            return

        entry_item = self.timeline_table.item(row, 0)
        entry_id = entry_item.data(Qt.ItemDataRole.UserRole) if entry_item else ""
        timeline = list(self.contact.get("timeline") or [])
        timeline = [x for x in timeline if str(x.get("id") or "") != str(entry_id)]
        self.contact["timeline"] = timeline
        self.refresh_timeline()

    def get_contact_payload(self):
        send_number = normalize_contact_phone(self.phone_edit.text())
        display_number = contact_safe_text(self.display_phone_edit.text()) or format_contact_display_number(send_number)

        payload = normalize_contact_record(self.contact)
        payload.update({
            "send_number": send_number,
            "display_number": display_number,
            "name": contact_safe_text(self.name_edit.text()),
            "email": contact_safe_text(self.email_edit.text()),
            "company": contact_safe_text(self.company_edit.text()),
            "title": contact_safe_text(self.title_edit.text()),
            "city": contact_safe_text(self.city_edit.text()),
            "tags": contact_safe_text(self.tags_edit.text()),
            "color_flag": str(self.flag_combo.currentData() or "none"),
            "summary": self.summary_edit.toPlainText().strip(),
            "details": self.details_edit.toPlainText().strip(),
            "timeline": list(self.contact.get("timeline") or [])
        })
        return payload

    def accept(self):
        payload = self.get_contact_payload()
        if not payload.get("send_number"):
            QMessageBox.warning(self, "Missing Phone", "Phone number is required.")
            return

        try:
            save_contact_profile(
                payload,
                actor="user",
                original_send_number=self.original_send_number
            )
        except Exception as e:
            QMessageBox.warning(self, "Save Failed", f"Failed to save contact:\n{e}")
            return

        super().accept()

class ContactCardWidget(QFrame):
    def __init__(self, contact=None, parent=None):
        super().__init__(parent)
        self.contact = {}
        self.setFrameShape(QFrame.Shape.NoFrame)

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(8)

        header = QHBoxLayout()
        header.setSpacing(8)

        self.flag_badge = QLabel("")
        self.flag_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.flag_badge.setMinimumWidth(82)
        header.addWidget(self.flag_badge, 0)

        self.name_label = QLabel("")
        self.name_label.setWordWrap(True)
        self.name_label.setStyleSheet("font-size:15px;font-weight:800;color:#0d2d63;")
        header.addWidget(self.name_label, 1)

        self.company_label = QLabel("")
        self.company_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        self.company_label.setWordWrap(True)
        self.company_label.setStyleSheet("font-size:12px;font-weight:700;color:#42638e;")
        header.addWidget(self.company_label, 1)

        root.addLayout(header)

        self.phone_label = QLabel("")
        self.phone_label.setWordWrap(True)
        self.phone_label.setStyleSheet("font-size:13px;font-weight:700;color:#23466f;")
        root.addWidget(self.phone_label)

        self.summary_label = QLabel("")
        self.summary_label.setWordWrap(True)
        self.summary_label.setStyleSheet("font-size:12px;color:#516a8c;")
        root.addWidget(self.summary_label)

        self.meta_label = QLabel("")
        self.meta_label.setWordWrap(True)
        self.meta_label.setStyleSheet("font-size:12px;color:#5d7697;font-weight:600;")
        root.addWidget(self.meta_label)

        self.set_contact(contact or {})
        self.set_selected(False)

    def set_contact(self, contact):
        self.contact = normalize_contact_record(contact or {})
        flag = str(self.contact.get("color_flag") or "none")
        meta = CONTACT_FLAG_META.get(flag, CONTACT_FLAG_META["none"])

        self.flag_badge.setText(meta["label"])
        self.flag_badge.setStyleSheet(
            f"background:{meta['bg']};color:{meta['fg']};"
            "border-radius:12px;padding:6px 10px;font-weight:800;"
        )

        self.name_label.setText(self.contact.get("name") or "Unnamed Contact")
        self.company_label.setText(self.contact.get("company") or "")

        phone_text = self.contact.get("display_number") or self.contact.get("send_number") or "-"
        title_text = self.contact.get("title") or ""
        if title_text:
            phone_text = f"{phone_text}    |    {title_text}"
        self.phone_label.setText(phone_text)

        summary = (self.contact.get("summary") or "").strip()
        self.summary_label.setText(summary or "No summary yet.")

        last_chat = format_user_datetime_text(self.contact.get("last_chat_at"), default="-")
        last_out = format_user_datetime_text(self.contact.get("last_outgoing_at"), default="-")
        last_in = format_user_datetime_text(self.contact.get("last_incoming_at"), default="-")
        self.meta_label.setText(
            f"Last chat: {last_chat}    |    "
            f"Last outgoing: {last_out}    |    "
            f"Last incoming: {last_in}"
        )

    def set_selected(self, selected):
        if selected:
            self.setStyleSheet(
                "QFrame {"
                "background:#eef5ff;"
                "border:2px solid #7ea8e6;"
                "border-radius:22px;"
                "}"
            )
        else:
            self.setStyleSheet(
                "QFrame {"
                "background:#ffffff;"
                "border:1px solid #d4e2f7;"
                "border-radius:22px;"
                "}"
            )

class ContactManagerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Local Contact Manager")
        self.setMinimumSize(1280, 760)

        root = QVBoxLayout(self)

        guide = QLabel(
            "Suggested best practice:\n"
            "- Save all useful details learned from each contact.\n"
            "- Use Summary for quick context.\n"
            "- Use Detailed Background for richer notes.\n"
            "- Use Timeline Notes for dated updates such as reluctance, promise-to-pay, follow-up date, tone, risk, and special handling.\n"
            "- The green / yellow / red flags are only personal visual labels for contact management."
        )
        guide.setWordWrap(True)
        guide.setStyleSheet("padding:10px;border:1px solid #9ab2d8;background:#f4f7ff;")
        root.addWidget(guide)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Search"))

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search by name, phone, company, note, tag, summary...")
        filter_row.addWidget(self.search_edit, 1)

        filter_row.addWidget(QLabel("Flag"))
        self.flag_filter = QComboBox()
        self.flag_filter.addItem("All", "all")
        for key, meta in CONTACT_FLAG_META.items():
            self.flag_filter.addItem(meta["label"], key)
        filter_row.addWidget(self.flag_filter)

        self.count_label = QLabel("0 contacts")
        filter_row.addWidget(self.count_label)

        root.addLayout(filter_row)

        splitter = QSplitter(Qt.Orientation.Vertical, self)
        root.addWidget(splitter, 1)

        self.contact_table = QTableWidget(0, 9, self)
        prepare_plain_table_widget(
            self.contact_table,
            ["Flag", "Name", "Phone", "Company", "Tags", "Summary", "Last Chat", "Last Outgoing", "Last Incoming"],
            stretch_last=False
        )
        self.contact_table.setColumnWidth(0, 90)
        self.contact_table.setColumnWidth(1, 190)
        self.contact_table.setColumnWidth(2, 150)
        self.contact_table.setColumnWidth(3, 150)
        self.contact_table.setColumnWidth(4, 130)
        self.contact_table.setColumnWidth(5, 260)
        self.contact_table.setColumnWidth(6, 150)
        self.contact_table.setColumnWidth(7, 150)
        self.contact_table.setColumnWidth(8, 150)
        splitter.addWidget(self.contact_table)

        detail_wrap = QWidget(self)
        detail_layout = QVBoxLayout(detail_wrap)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(6)
        detail_layout.addWidget(QLabel("Selected Contact Details"))
        self.contact_detail = QTextEdit(self)
        self.contact_detail.setReadOnly(True)
        self.contact_detail.setMinimumHeight(170)
        detail_layout.addWidget(self.contact_detail)
        splitter.addWidget(detail_wrap)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 2)

        btn_row = QHBoxLayout()
        self.new_btn = QPushButton("New Contact")
        self.edit_btn = QPushButton("Edit Contact")
        self.add_log_btn = QPushButton("Add Timeline Note")
        self.delete_btn = QPushButton("Delete Contact")
        self.refresh_btn = QPushButton("Refresh")
        self.close_btn = QPushButton("Close")

        btn_row.addWidget(self.new_btn)
        btn_row.addWidget(self.edit_btn)
        btn_row.addWidget(self.add_log_btn)
        btn_row.addWidget(self.delete_btn)
        btn_row.addStretch()
        btn_row.addWidget(self.refresh_btn)
        btn_row.addWidget(self.close_btn)
        root.addLayout(btn_row)

        self.search_edit.textChanged.connect(self.render_contacts)
        self.flag_filter.currentIndexChanged.connect(self.render_contacts)
        self.new_btn.clicked.connect(self.create_contact)
        self.edit_btn.clicked.connect(self.edit_selected_contact)
        self.add_log_btn.clicked.connect(self.add_note_selected_contact)
        self.delete_btn.clicked.connect(self.delete_selected_contact)
        self.refresh_btn.clicked.connect(self.render_contacts)
        self.close_btn.clicked.connect(self.accept)
        self.contact_table.itemSelectionChanged.connect(self.update_contact_detail)
        self.contact_table.itemDoubleClicked.connect(lambda *_: self.edit_selected_contact())

        self.render_contacts()

    def _selected_send_number(self):
        row = self.contact_table.currentRow()
        if row < 0:
            return ""
        item = self.contact_table.item(row, 0)
        if not item:
            return ""
        return str(item.data(Qt.ItemDataRole.UserRole) or "")

    def _get_contact_by_number(self, send_number):
        contacts = load_contacts()
        _, contact = find_contact_index(contacts, send_number)
        return contact

    def update_contact_detail(self):
        send_number = self._selected_send_number()
        if not send_number:
            self.contact_detail.clear()
            return

        contact = self._get_contact_by_number(send_number)
        if not contact:
            self.contact_detail.clear()
            return

        contact = normalize_contact_record(contact)
        timeline_count = len(list(contact.get("timeline") or []))
        self.contact_detail.setPlainText(
            "\n".join([
                f"Name: {contact.get('name') or '-'}",
                f"Phone: {contact.get('display_number') or contact.get('send_number') or '-'}",
                f"Company: {contact.get('company') or '-'}",
                f"Title: {contact.get('title') or '-'}",
                f"Email: {contact.get('email') or '-'}",
                f"City: {contact.get('city') or '-'}",
                f"Tags: {contact.get('tags') or '-'}",
                f"Flag: {CONTACT_FLAG_META.get(str(contact.get('color_flag') or 'none'), CONTACT_FLAG_META['none'])['label']}",
                f"Last chat: {format_user_datetime_text(contact.get('last_chat_at'), default='-')}",
                f"Last outgoing: {format_user_datetime_text(contact.get('last_outgoing_at'), default='-')}",
                f"Last incoming: {format_user_datetime_text(contact.get('last_incoming_at'), default='-')}",
                f"Timeline notes: {timeline_count}",
                "",
                "Summary:",
                str(contact.get("summary") or "-"),
                "",
                "Detailed Background / Notes:",
                str(contact.get("details") or "-")
            ])
        )

    def render_contacts(self):
        contacts = load_contacts()
        query = self.search_edit.text().strip().lower()
        flag_value = str(self.flag_filter.currentData() or "all")

        rows = []
        for contact in contacts:
            if flag_value != "all" and str(contact.get("color_flag") or "none") != flag_value:
                continue

            blob = build_contact_search_blob(contact)
            if query and query not in blob:
                continue

            rows.append(contact)

        def _sort_key(contact):
            ts = str(contact.get("last_chat_at") or "").strip()
            parsed = None
            try:
                parsed = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except Exception:
                parsed = None

            return (
                1 if not parsed else 0,
                -(int(parsed.timestamp()) if parsed else 0),
                (contact.get("name") or "").lower()
            )

        rows.sort(key=_sort_key)

        self.contact_table.setRowCount(0)
        self.count_label.setText(f"{len(rows)} contacts")

        self.contact_table.setRowCount(len(rows))
        for row_index, contact in enumerate(rows):
            contact = normalize_contact_record(contact)
            flag = str(contact.get("color_flag") or "none")
            flag_label = CONTACT_FLAG_META.get(flag, CONTACT_FLAG_META["none"])["label"]
            phone_text = contact.get("display_number") or contact.get("send_number") or "-"
            row_values = [
                flag_label,
                contact.get("name") or "Unnamed Contact",
                phone_text,
                contact.get("company") or "",
                contact.get("tags") or "",
                make_text_preview(contact.get("summary") or "", 120),
                format_user_datetime_text(contact.get("last_chat_at"), default="-"),
                format_user_datetime_text(contact.get("last_outgoing_at"), default="-"),
                format_user_datetime_text(contact.get("last_incoming_at"), default="-")
            ]
            for col, value in enumerate(row_values):
                user_data = contact.get("send_number") if col == 0 else None
                self.contact_table.setItem(row_index, col, make_table_item(value, user_data=user_data))

        if self.contact_table.rowCount() > 0:
            select_first_table_row(self.contact_table)
            self.update_contact_detail()
        else:
            self.contact_detail.clear()

    def create_contact(self):
        dlg = ContactEditorDialog(parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.render_contacts()

    def edit_selected_contact(self):
        send_number = self._selected_send_number()
        if not send_number:
            QMessageBox.warning(self, "No Selection", "Please select a contact first.")
            return

        contact = self._get_contact_by_number(send_number)
        if not contact:
            QMessageBox.warning(self, "Not Found", "Contact not found.")
            return

        dlg = ContactEditorDialog(contact=contact, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.render_contacts()

    def add_note_selected_contact(self):
        send_number = self._selected_send_number()
        if not send_number:
            QMessageBox.warning(self, "No Selection", "Please select a contact first.")
            return

        dlg = ContactLogDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        entry = dlg.get_entry()
        append_contact_note(send_number, entry["text"], entry_type=entry["type"], actor="user")
        self.render_contacts()

    def delete_selected_contact(self):
        send_number = self._selected_send_number()
        if not send_number:
            QMessageBox.warning(self, "No Selection", "Please select a contact first.")
            return

        owner = self.parent()
        if owner and hasattr(owner, "require_admin_password"):
            if not owner.require_admin_password():
                QMessageBox.warning(self, "Error", "Incorrect password.")
                return

        reply = QMessageBox.question(
            self,
            "Delete Contact",
            "Delete this local contact and its timeline?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        delete_contact(send_number)
        self.render_contacts()

class StatCard(QFrame):
    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setMinimumHeight(120)
        self.setStyleSheet("""
            QFrame {
                background: #ffffff;
                border: 1px solid #d4e2f7;
                border-radius: 22px;
            }
            QLabel {
                border: none;
                background: transparent;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet(
            "font-size:13px;"
            "color:#35507c;"
            "font-weight:700;"
        )

        self.value_label = QLabel("-")
        self.value_label.setStyleSheet("font-size:28px;font-weight:800;color:#0d2d63;")

        self.sub_label = QLabel("")
        self.sub_label.setWordWrap(True)
        self.sub_label.setStyleSheet(
            "font-size:12px;"
            "color:#4e6487;"
            "font-weight:600;"
        )

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.sub_label)
        layout.addStretch()

    def set_data(self, title, value, subtext=""):
        self.title_label.setText(str(title))
        self.value_label.setText(str(value))
        self.sub_label.setText(str(subtext or ""))


class MiniBarChart(QWidget):
    def __init__(self, title="", suffix="", parent=None, bar_color="#2563eb"):
        super().__init__(parent)
        self.title = title
        self.suffix = suffix
        self.bar_color = QColor(bar_color)
        self.labels = []
        self.values = []
        self.setMinimumHeight(260)
        self.setStyleSheet(
            "background:#ffffff;"
            "border:1px solid #d4e2f7;"
            "border-radius:22px;"
        )

    def set_data(self, labels, values, title=None, suffix=None):
        self.labels = list(labels or [])
        self.values = list(values or [])
        if title is not None:
            self.title = str(title)
        if suffix is not None:
            self.suffix = str(suffix)
        self.update()

    def set_bar_color(self, value):
        self.bar_color = QColor(str(value or "#2563eb"))
        self.update()

    def _format_value(self, value):
        try:
            f = float(value)
            if abs(f - int(f)) < 0.001:
                return f"{int(f)}{self.suffix}"
            return f"{f:.1f}{self.suffix}"
        except Exception:
            return f"{value}{self.suffix}"

    def paintEvent(self, event):
        super().paintEvent(event)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        rect = self.rect().adjusted(14, 14, -14, -14)

        painter.setPen(QPen(QColor("#0d2d63")))
        title_font = QFont()
        title_font.setPointSize(11)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.drawText(
            rect.adjusted(0, 0, 0, -rect.height() + 22),
            Qt.AlignmentFlag.AlignLeft,
            self.title
        )

        chart_rect = rect.adjusted(48, 34, -16, -42)
        if chart_rect.width() <= 0 or chart_rect.height() <= 0:
            return

        painter.setPen(QPen(QColor("#bfd0ea"), 1))
        painter.drawLine(chart_rect.bottomLeft(), chart_rect.bottomRight())
        painter.drawLine(chart_rect.bottomLeft(), chart_rect.topLeft())

        if not self.values:
            painter.setPen(QPen(QColor("#50688f")))
            painter.drawText(chart_rect, Qt.AlignmentFlag.AlignCenter, "No data")
            return

        max_val = max(max(self.values), 1)
        count = max(len(self.values), 1)
        slot_w = chart_rect.width() / count
        bar_w = max(18, int(slot_w * 0.55))

        label_font = QFont()
        label_font.setPointSize(9)
        painter.setFont(label_font)

        for i, value in enumerate(self.values):
            try:
                v = float(value)
            except Exception:
                v = 0.0

            bar_h = int((v / max_val) * max(1, chart_rect.height() - 34))
            x_center = chart_rect.left() + int((i + 0.5) * slot_w)
            x = x_center - int(bar_w / 2)
            y = chart_rect.bottom() - bar_h

            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(self.bar_color))
            painter.drawRoundedRect(QRect(x, y, bar_w, bar_h), 5, 5)

            painter.setPen(QPen(QColor("#16335f")))
            value_text = self._format_value(v)
            painter.drawText(
                QRect(x - 18, y - 20, bar_w + 36, 18),
                Qt.AlignmentFlag.AlignCenter,
                value_text
            )

            lbl = str(self.labels[i]) if i < len(self.labels) else ""
            painter.setPen(QPen(QColor("#476384")))
            painter.drawText(
                QRect(x - 18, chart_rect.bottom() + 8, bar_w + 36, 18),
                Qt.AlignmentFlag.AlignCenter,
                lbl
            )


class AttendanceTimelineChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.day_key_value = today_key()
        self.segments = []
        self.setMinimumHeight(260)
        self.setStyleSheet(
            "background:#ffffff;"
            "border:1px solid #d4e2f7;"
            "border-radius:22px;"
        )

    def set_data(self, day_key_value, segments):
        self.day_key_value = str(day_key_value or today_key())
        self.segments = list(segments or [])
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        rect = self.rect().adjusted(16, 16, -16, -16)

        painter.setPen(QPen(QColor("#0d2d63")))
        title_font = QFont()
        title_font.setPointSize(11)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.drawText(
            rect.adjusted(0, 0, 0, -rect.height() + 22),
            Qt.AlignmentFlag.AlignLeft,
            f"Attendance Timeline - {self.day_key_value}"
        )

        legend_y = rect.top() + 28
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#16a34a"))
        painter.drawRoundedRect(QRect(rect.left(), legend_y, 14, 14), 4, 4)
        painter.setPen(QPen(QColor("#36506f")))
        painter.drawText(QRect(rect.left() + 20, legend_y - 2, 80, 18), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "Active")

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#dc2626"))
        painter.drawRoundedRect(QRect(rect.left() + 90, legend_y, 14, 14), 4, 4)
        painter.setPen(QPen(QColor("#36506f")))
        painter.drawText(QRect(rect.left() + 110, legend_y - 2, 90, 18), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "Dormant")

        chart_rect = rect.adjusted(0, 58, 0, -34)
        if chart_rect.width() <= 0 or chart_rect.height() <= 0:
            return

        painter.setPen(QPen(QColor("#bfd0ea"), 1))
        painter.drawRoundedRect(chart_rect, 12, 12)

        if not self.segments:
            painter.setPen(QPen(QColor("#50688f")))
            painter.drawText(chart_rect, Qt.AlignmentFlag.AlignCenter, "No attendance activity yet")
            return

        day_start = ensure_user_datetime(f"{self.day_key_value} 00:00:00")
        day_end = day_start + datetime.timedelta(days=1)
        total_seconds = max(1, int((day_end - day_start).total_seconds()))

        for hour in range(1, 24):
            x = chart_rect.left() + int((hour / 24.0) * chart_rect.width())
            painter.setPen(QPen(QColor("#e2e8f5"), 1))
            painter.drawLine(x, chart_rect.top() + 8, x, chart_rect.bottom() - 18)

        bar_rect = QRect(
            chart_rect.left() + 10,
            chart_rect.top() + 20,
            chart_rect.width() - 20,
            max(28, chart_rect.height() - 58)
        )
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(223, 232, 245, 150))
        painter.drawRoundedRect(bar_rect, 14, 14)

        for seg in self.segments:
            seg_type = str(seg.get("type") or "").strip().lower()
            start_dt = ensure_user_datetime(seg.get("start"))
            end_dt = ensure_user_datetime(seg.get("end"))
            if not start_dt or not end_dt or end_dt <= start_dt:
                continue

            start_offset = int((start_dt - day_start).total_seconds())
            end_offset = int((end_dt - day_start).total_seconds())
            start_offset = max(0, min(total_seconds, start_offset))
            end_offset = max(0, min(total_seconds, end_offset))
            if end_offset <= start_offset:
                continue

            x1 = bar_rect.left() + int((start_offset / total_seconds) * bar_rect.width())
            x2 = bar_rect.left() + int((end_offset / total_seconds) * bar_rect.width())
            width = max(3, x2 - x1)
            color = QColor("#16a34a" if seg_type == "active" else "#dc2626")

            painter.setBrush(QBrush(color))
            painter.drawRoundedRect(QRect(x1, bar_rect.top(), width, bar_rect.height()), 10, 10)

        painter.setPen(QPen(QColor("#476384")))
        label_font = QFont()
        label_font.setPointSize(9)
        painter.setFont(label_font)
        for hour in range(0, 25, 3):
            x = chart_rect.left() + int((hour / 24.0) * chart_rect.width())
            label = f"{hour:02d}:00" if hour < 24 else "24:00"
            painter.drawText(QRect(x - 20, chart_rect.bottom() - 14, 44, 16), Qt.AlignmentFlag.AlignCenter, label)


class AttendanceDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Attendance")
        self.setMinimumSize(1080, 820)

        outer_root = QVBoxLayout(self)
        outer_root.setContentsMargins(8, 8, 8, 8)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer_root.addWidget(scroll)

        content = QWidget(self)
        content.setMinimumWidth(1020)
        root = QVBoxLayout(content)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        title = QLabel("Attendance")
        title.setStyleSheet("font-size:18px;font-weight:800;color:#0d2d63;")
        root.addWidget(title)

        subtitle = QLabel(
            "Attendance is recorded automatically from app open time and ongoing interaction. "
            "Green means active time. Red means dormant time between touches."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(
            "color:#325179;"
            "background:#f4f7ff;"
            "border:1px solid #9ab2d8;"
            "padding:12px;"
            "font-weight:600;"
        )
        root.addWidget(subtitle)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Date"))
        self.date_edit = QDateEdit(self)
        self.date_edit.setCalendarPopup(True)
        self.date_edit.setDisplayFormat("yyyy-MM-dd")
        self.date_edit.setDate(QDate.currentDate())
        self.refresh_btn = QPushButton("Refresh")
        self.export_btn = QPushButton("Export Excel")
        self.refresh_btn.clicked.connect(self.refresh_dashboard)
        self.export_btn.clicked.connect(self.export_excel)
        controls.addWidget(self.date_edit)
        controls.addWidget(self.refresh_btn)
        controls.addWidget(self.export_btn)
        controls.addStretch()
        root.addLayout(controls)
        configure_rounded_combo_popup(self.date_edit)

        self.summary_table = QTableWidget(4, 3, self)
        prepare_plain_table_widget(self.summary_table, ["Metric", "Value", "Notes"], stretch_last=True)
        self.summary_table.setMinimumHeight(180)
        self.summary_table.setColumnWidth(0, 150)
        self.summary_table.setColumnWidth(1, 220)
        root.addWidget(self.summary_table)

        self.summary_label = QLabel("")
        self.summary_label.setWordWrap(True)
        self.summary_label.setStyleSheet(
            "padding:12px;"
            "background:#f4f7ff;"
            "border:1px solid #9ab2d8;"
            "color:#24466d;"
            "font-weight:700;"
        )
        root.addWidget(self.summary_label)

        self.timeline_chart = AttendanceTimelineChart(self)
        self.timeline_chart.setMinimumHeight(300)
        self.timeline_chart.setMinimumWidth(960)
        root.addWidget(self.timeline_chart)

        self.active_chart = MiniBarChart("Active time - last 7 days", suffix="h", bar_color="#16a34a")
        self.dormant_chart = MiniBarChart("Dormant time - last 7 days", suffix="h", bar_color="#dc2626")
        self.active_chart.setMinimumHeight(250)
        self.dormant_chart.setMinimumHeight(250)
        self.active_chart.setMinimumWidth(960)
        self.dormant_chart.setMinimumWidth(960)
        root.addWidget(self.active_chart)
        root.addWidget(self.dormant_chart)

        segment_title = QLabel("Segments")
        segment_title.setStyleSheet("font-size:14px;font-weight:800;color:#153764;")
        root.addWidget(segment_title)

        self.segment_table = QTableWidget(0, 4, self)
        prepare_plain_table_widget(self.segment_table, ["Type", "Start", "End", "Duration"], stretch_last=False)
        self.segment_table.setMinimumHeight(280)
        self.segment_table.setMinimumWidth(960)
        self.segment_table.setColumnWidth(0, 110)
        self.segment_table.setColumnWidth(1, 220)
        self.segment_table.setColumnWidth(2, 220)
        self.segment_table.setColumnWidth(3, 140)
        root.addWidget(self.segment_table, 1)

        scroll.setWidget(content)

        self.date_edit.dateChanged.connect(self.refresh_dashboard)
        self.refresh_dashboard()

    def selected_day_key(self):
        return self.date_edit.date().toString("yyyy-MM-dd")

    def refresh_dashboard(self):
        day_key_value = self.selected_day_key()
        snapshot = get_attendance_bucket_for_day(day_key_value)
        series = build_last_n_day_attendance_series(7, day_key_value)

        clock_in_text = format_user_datetime_text(snapshot.get("clock_in_at"), default="-")
        last_touch_text = format_user_datetime_text(snapshot.get("last_touch_at"), default="-")
        active_seconds = int(snapshot.get("active_seconds", 0))
        dormant_seconds = int(snapshot.get("dormant_seconds", 0))
        total_seconds = active_seconds + dormant_seconds

        summary_rows = [
            ("Clock In", clock_in_text, "First app open / touch"),
            ("Last Touch", last_touch_text, "Last recorded interaction"),
            ("Active", format_duration_hms(active_seconds), "Tracked as green"),
            ("Dormant", format_duration_hms(dormant_seconds), "Tracked as red")
        ]
        self.summary_table.setRowCount(len(summary_rows))
        for row_index, (metric, value, note) in enumerate(summary_rows):
            self.summary_table.setItem(row_index, 0, make_table_item(metric))
            self.summary_table.setItem(row_index, 1, make_table_item(value))
            self.summary_table.setItem(row_index, 2, make_table_item(note))

        active_ratio = 0.0 if total_seconds <= 0 else round((active_seconds / total_seconds) * 100.0, 1)
        dormant_ratio = 0.0 if total_seconds <= 0 else round((dormant_seconds / total_seconds) * 100.0, 1)
        self.summary_label.setText(
            f"Date: {day_key_value}    |    "
            f"Clock in: {clock_in_text}    |    "
            f"Last touch: {last_touch_text}\n"
            f"Active: {format_duration_hms(active_seconds)} ({active_ratio}%)    |    "
            f"Dormant: {format_duration_hms(dormant_seconds)} ({dormant_ratio}%)"
        )

        self.timeline_chart.set_data(day_key_value, snapshot.get("segments") or [])

        labels = [row["date"][5:] for row in series]
        self.active_chart.set_data(labels, [row["active_hours"] for row in series], "Active time - last 7 days", "h")
        self.dormant_chart.set_data(labels, [row["dormant_hours"] for row in series], "Dormant time - last 7 days", "h")

        rows = list(snapshot.get("segments") or [])
        rows = sorted(rows, key=lambda x: str(x.get("start") or ""))
        self.segment_table.setRowCount(len(rows))

        for row_index, seg in enumerate(rows):
            seg_type = str(seg.get("type") or "").strip().lower()
            start_text = format_user_datetime_text(seg.get("start"), default="-")
            end_text = format_user_datetime_text(seg.get("end"), default="-")
            duration_text = format_duration_hms(seg.get("seconds"))
            type_text = "Active" if seg_type == "active" else "Dormant"

            self.segment_table.setItem(row_index, 0, make_table_item(type_text))
            self.segment_table.setItem(row_index, 1, make_table_item(start_text))
            self.segment_table.setItem(row_index, 2, make_table_item(end_text))
            self.segment_table.setItem(row_index, 3, make_table_item(duration_text))

        if self.segment_table.rowCount() > 0:
            select_first_table_row(self.segment_table)

    def export_excel(self):
        parent = self.parent()
        checker = getattr(parent, "require_admin_password", None)
        if callable(checker):
            if not checker():
                QMessageBox.warning(self, "Error", "Incorrect password.")
                return

        selected_day = self.selected_day_key()
        snapshot = get_attendance_bucket_for_day(selected_day)
        series = build_last_n_day_attendance_series(30, selected_day)

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Attendance Report",
            f"attendance_{selected_day}.xlsx",
            "Excel Files (*.xlsx)"
        )
        if not save_path:
            return

        try:
            if not save_path.lower().endswith(".xlsx"):
                save_path += ".xlsx"

            summary_rows = [{
                "date": selected_day,
                "clock_in_at": format_user_datetime_text(snapshot.get("clock_in_at"), default="-"),
                "last_touch_at": format_user_datetime_text(snapshot.get("last_touch_at"), default="-"),
                "active_seconds": int(snapshot.get("active_seconds", 0)),
                "active_hms": format_duration_hms(snapshot.get("active_seconds", 0)),
                "dormant_seconds": int(snapshot.get("dormant_seconds", 0)),
                "dormant_hms": format_duration_hms(snapshot.get("dormant_seconds", 0))
            }]

            segment_rows = []
            for item in snapshot.get("segments") or []:
                segment_rows.append({
                    "type": str(item.get("type") or ""),
                    "start": format_user_datetime_text(item.get("start"), default="-"),
                    "end": format_user_datetime_text(item.get("end"), default="-"),
                    "seconds": int(item.get("seconds", 0)),
                    "duration_hms": format_duration_hms(item.get("seconds", 0))
                })

            with pd.ExcelWriter(save_path, engine="openpyxl") as writer:
                pd.DataFrame(summary_rows).to_excel(writer, index=False, sheet_name="Summary")
                pd.DataFrame(series).to_excel(writer, index=False, sheet_name="Last 30 Days")
                pd.DataFrame(segment_rows).to_excel(writer, index=False, sheet_name="Segments")

            QMessageBox.information(self, "Exported", f"Attendance report saved to:\n{save_path}")
        except Exception as e:
            QMessageBox.warning(self, "Export Failed", f"Failed to export attendance report:\n{e}")

class PerformanceDock(QDockWidget):
    def __init__(self, parent=None):
        super().__init__("User Performance", parent)
        self.setObjectName("PerformanceDock")
        self.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable |
            QDockWidget.DockWidgetFeature.DockWidgetFloatable |
            QDockWidget.DockWidgetFeature.DockWidgetClosable
        )
        self.setMinimumWidth(620)

        self.setStyleSheet("""
            QDockWidget {
                font-size: 13px;
            }
            QDockWidget::title {
                background: #edf4ff;
                color: #0d2d63;
                padding: 10px 14px;
                font-weight: 700;
                border-bottom: 1px solid #d7e4f7;
            }
            QLabel {
                color: #10315e;
            }
            QDateEdit, QPushButton, QTextEdit, QTableWidget {
                font-size: 13px;
            }
            QPushButton {
                background: #f6f9ff;
                color: #0d2d63;
                border: 1px solid #8fa9d4;
                padding: 7px 12px;
                font-weight: 700;
            }
            QPushButton:hover {
                background: #edf4ff;
            }
            QDateEdit {
                background: #ffffff;
                color: #10315e;
                border: 1px solid #8fa9d4;
                padding: 6px 10px;
            }
            QTextEdit {
                background: #ffffff;
                color: #10315e;
                border: 1px solid #8fa9d4;
                padding: 8px;
            }
            QTableWidget {
                background: #ffffff;
                color: #10315e;
                border: 1px solid #8fa9d4;
            }
        """)

        content_widget = QWidget(self)
        root = QVBoxLayout(content_widget)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(12)

        title = QLabel("User Performance Dashboard")
        title.setStyleSheet("font-size:18px;font-weight:800;color:#0d2d63;")
        root.addWidget(title)

        subtitle = QLabel(
            "Heuristic dashboard based on local app logs only. "
            "Useful for trend monitoring, not a full productivity truth source."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(
            "color:#325179;"
            "background:#f4f7ff;"
            "border:1px solid #9ab2d8;"
            "padding:12px;"
            "font-size:13px;"
            "font-weight:600;"
        )
        root.addWidget(subtitle)

        control_row = QHBoxLayout()
        control_row.setSpacing(8)
        control_row.addWidget(QLabel("Date"))

        self.date_edit = QDateEdit(self)
        self.date_edit.setCalendarPopup(True)
        self.date_edit.setDisplayFormat("yyyy-MM-dd")
        self.date_edit.setDate(QDate.currentDate())

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_dashboard)

        control_row.addWidget(self.date_edit)
        control_row.addWidget(self.refresh_btn)
        control_row.addStretch()
        root.addLayout(control_row)

        self.summary_table = QTableWidget(6, 3, self)
        prepare_plain_table_widget(self.summary_table, ["Metric", "Value", "Notes"], stretch_last=True)
        self.summary_table.setMinimumHeight(220)
        self.summary_table.setColumnWidth(0, 200)
        self.summary_table.setColumnWidth(1, 180)
        root.addWidget(self.summary_table)

        self.meta_label = QLabel("")
        self.meta_label.setWordWrap(True)
        self.meta_label.setStyleSheet(
            "padding:12px;"
            "background:#f4f7ff;"
            "border:1px solid #9ab2d8;"
            "color:#24466d;"
            "font-weight:700;"
        )
        root.addWidget(self.meta_label)

        self.sent_chart = MiniBarChart("Successful outreach - last 7 days", bar_color="#2b5fd9")
        self.screen_chart = MiniBarChart("Screen time - last 7 days", suffix="h", bar_color="#0f766e")
        self.score_chart = MiniBarChart("Heuristic score - last 7 days", bar_color="#7c3aed")

        root.addWidget(self.sent_chart)
        root.addWidget(self.screen_chart)
        root.addWidget(self.score_chart)

        tips_title = QLabel("System Suggestions")
        tips_title.setStyleSheet("font-size:15px;font-weight:800;color:#0d2d63;")
        root.addWidget(tips_title)

        self.tips_box = QTextEdit(self)
        self.tips_box.setReadOnly(True)
        self.tips_box.setMinimumHeight(180)
        self.tips_box.setStyleSheet("""
            QTextEdit {
                background: #ffffff;
                color: #24466d;
                border: 1px solid #8fa9d4;
                padding: 8px;
                font-size: 13px;
                font-weight: 600;
            }
        """)
        root.addWidget(self.tips_box, 1)

        root.addStretch()

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(content_widget)

        self.setWidget(scroll)

        self.auto_timer = QTimer(self)
        self.auto_timer.setInterval(30000)
        self.auto_timer.timeout.connect(self.refresh_dashboard)
        self.auto_timer.start()

        self.date_edit.dateChanged.connect(self.refresh_dashboard)
        self.refresh_dashboard()

    def selected_day_key(self):
        return self.date_edit.date().toString("yyyy-MM-dd")

    def refresh_dashboard(self):
        day_key_value = self.selected_day_key()
        snapshot = build_daily_performance_snapshot(day_key_value)
        series = build_last_n_day_performance_series(7, day_key_value)

        summary_rows = [
            ("Heuristic Score", f"{snapshot['productivity_score']}/100", "Local log based"),
            ("Successful Reached Out", snapshot["sent_total"], f"Failed: {snapshot['failed_total']}"),
            ("Replies Received", snapshot["received_total"], f"Reply rate: {snapshot['reply_rate']}%"),
            ("Unique Contacts", snapshot["touched_contacts_count"], f"Blast jobs: {snapshot['blast_jobs']}"),
            ("Avg Reply Speed", snapshot["avg_reply_speed_hms"], "Only when measurable"),
            ("Screen Time", format_duration_hms(snapshot["screen_time_seconds"]), "Active app time")
        ]
        self.summary_table.setRowCount(len(summary_rows))
        for row_index, (metric, value, note) in enumerate(summary_rows):
            self.summary_table.setItem(row_index, 0, make_table_item(metric))
            self.summary_table.setItem(row_index, 1, make_table_item(value))
            self.summary_table.setItem(row_index, 2, make_table_item(note))

        self.meta_label.setText(
            f"Date: {snapshot['date']}    |    "
            f"Manual sends: {snapshot['manual_sends']}    |    "
            f"Blast messages: {snapshot['blast_messages']}    |    "
            f"Incoming replies logged: {snapshot['incoming_replies_logged']}    |    "
            f"Last updated: {format_user_datetime_text(snapshot['last_updated'], default='-')}"
        )

        labels = [row["date"][5:] for row in series]
        sent_values = [row["sent_total"] for row in series]
        screen_values = [row["screen_time_hours"] for row in series]
        score_values = [row["productivity_score"] for row in series]

        self.sent_chart.set_data(labels, sent_values, "Successful outreach - last 7 days", "")
        self.screen_chart.set_data(labels, screen_values, "Screen time - last 7 days", "h")
        self.score_chart.set_data(labels, score_values, "Heuristic score - last 7 days", "")

        tips = snapshot.get("tips") or []
        tips_text = "\n".join(f"{idx+1}. {tip}" for idx, tip in enumerate(tips))
        self.tips_box.setPlainText(tips_text or "No suggestions.")

# --------------------------
# Main Browser Window
# --------------------------
class LockedBrowser(QMainWindow):
    live_view_request_signal = pyqtSignal(object)
    def __init__(self):
        super().__init__()
        self.apply_light_ui_theme()
        self.setWindowTitle("Locked Browser - Multi‑Service")
        self.setGeometry(100, 100, 1200, 800)
        self.live_view_request_signal.connect(
            self._handle_live_view_request,
            Qt.ConnectionType.QueuedConnection
        )

        # Random country & fake IP
        self.country = random.choice(list(SPOOF_COUNTRIES.keys()))
        self.coords = SPOOF_COUNTRIES[self.country]
        ip_ranges = {
            "Singapore": "103.2.12.",
            "Malaysia": "110.159.2.",
            "Vietnam": "14.136.96.",
            "Thailand": "110.171.2.",
            "Australia": "1.1.1."
        }
        self.fake_ip = ip_ranges[self.country] + str(random.randint(10, 99))

        # Proxy state
        self.proxy_enabled = False
        self.proxy_info = {
            "enabled": False,
            "type": "DIRECT",
            "host": "",
            "port": 0,
            "username": "",
            "password": ""
        }

        # Apply DIRECT first, before creating QWebEngine profiles/pages
        self.apply_proxy_config(self.proxy_info, rebuild=False)

        # Profiles
        self.profile_interceptors = []
        self.whatsapp_profiles = {}
        self.profile = self.create_shared_profile()

        self.bad_words = load_bad_words()
        self._bulk_target_view = None
        self._bulk_target_account_id = None
        self._bulk_bad_word_hits = []
        self._bulk_bad_words = []

        self.runtime_poll_timer = QTimer(self)
        self.runtime_poll_timer.setInterval(5000)
        self.runtime_poll_timer.setTimerType(Qt.TimerType.CoarseTimer)
        self.runtime_poll_timer.timeout.connect(self.poll_runtime_data)
        self.runtime_poll_timer.start()

        self.collection_watch_timer = QTimer(self)
        self.collection_watch_timer.setInterval(4000)
        self.collection_watch_timer.setTimerType(Qt.TimerType.CoarseTimer)
        self.collection_watch_timer.timeout.connect(self.update_collection_blast_dock)
        self.collection_watch_timer.start()

        self._bulk_poll_timer = QTimer(self)
        self._bulk_poll_timer.setInterval(1000)
        self._bulk_poll_timer.setTimerType(Qt.TimerType.CoarseTimer)
        self._bulk_poll_timer.timeout.connect(self._poll_bulk_whatsapp_status)

        self._wa_sync_poll_timer = QTimer(self)
        self._wa_sync_poll_timer.setInterval(1200)
        self._wa_sync_poll_timer.setTimerType(Qt.TimerType.CoarseTimer)
        self._wa_sync_poll_timer.timeout.connect(self._poll_whatsapp_history_sync_status)

        # Create tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(False)
        self.tab_widget.setMovable(False)
        self.setCentralWidget(self.tab_widget)

        # Store references to tab views
        self.tab_views = []
        self._app_is_active = True
        self._activity_current_tab_label = None
        self._activity_started_monotonic = None
        self._attendance_last_record_monotonic = 0.0

        self._bulk_recipients = []
        self._bulk_statuses = []
        self._bulk_template = ""
        self._bulk_attachment_path = ""
        self._bulk_encoded = ""
        self._bulk_index = 0
        self._bulk_processing = False
        self._bulk_send_started_at = 0.0
        self._bulk_send_timeout_sec = 180

        self._bulk_queue = []

        self._wa_sync_tabs = []
        self._wa_sync_tab_index = -1
        self._wa_sync_target_view = None
        self._wa_sync_target_account_id = None
        self._wa_sync_processing = False
        self._wa_sync_started_at = 0.0
        self._wa_sync_timeout_sec = 1800
        self._wa_sync_current_state = {}
        self._wa_sync_total_saved = 0
        self._wa_sync_total_duplicates = 0
        self._wa_sync_total_chats = 0
        self._wa_sync_log_cache = []
        self._wa_sync_existing_signatures = set()

        self._collection_staff_signature = ""
        self._collection_staff_records = []

        self.create_collection_blast_dock()
        self.create_performance_dock()
        self.tabifyDockWidget(self.collection_blast_dock, self.performance_dock)
        self.resizeDocks(
            [self.performance_dock],
            [680],
            Qt.Orientation.Horizontal
        )
        self.performance_dock.show()

        self.tab_widget.currentChanged.connect(self.on_current_tab_changed)

        self._collection_target_active = False
        self._collection_page_entered_at = ""

        state = load_app_state()
        wa_ids = state.get("wa_account_ids", [1]) or [1]

        # Restore WhatsApp account tabs
        for wa_id in wa_ids:
            self.add_whatsapp_account_tab(
                account_id=int(wa_id),
                switch_to=False,
                save_state_after=False
            )

        # Add other fixed tabs using shared profile
        for config in TAB_CONFIG:
            if config["name"] == "WhatsApp":
                continue

            self.add_browser_tab(
                config=config,
                title=config["name"],
                is_fixed=True,
                switch_to=False,
                profile=self.profile
            )

        self.save_whatsapp_tabs_state()

        # Create UI
        self.create_top_bar()
        self.apply_bulk_message_policy_ui()
        self.apply_cashier_mode_ui()
        self.create_status_bar()
        app = QApplication.instance()
        if app is not None:
            app.applicationStateChanged.connect(self.on_application_state_changed)
            app.installEventFilter(self)
        self.start_local_api_server()
        self.setup_tray_icon()
        self._record_attendance_touch(force=True, source="startup")

        # Show disclaimer and load tabs
        self.show_startup_disclaimer()
        self._activity_current_tab_label = self._current_activity_tab_name()
        self._activity_started_monotonic = time.monotonic()

    def default_proxy_info(self):
        return {
            "enabled": False,
            "type": "DIRECT",
            "host": "",
            "port": 0,
            "username": "",
            "password": ""
        }


    def apply_proxy_config(self, proxy_info, rebuild=True):
        info = dict(self.default_proxy_info())
        info.update(proxy_info or {})

        enabled = bool(info.get("enabled"))
        host = str(info.get("host") or "").strip()
        username = str(info.get("username") or "").strip()
        password = str(info.get("password") or "")

        if not enabled or not host:
            proxy = QNetworkProxy(QNetworkProxy.ProxyType.NoProxy)
            QNetworkProxy.setApplicationProxy(proxy)

            self.proxy_enabled = False
            self.proxy_info = self.default_proxy_info()
        else:
            proxy_type_text = str(info.get("type") or "HTTP").strip().upper()

            proxy = QNetworkProxy()
            if proxy_type_text == "SOCKS5":
                proxy.setType(QNetworkProxy.ProxyType.Socks5Proxy)
            else:
                proxy_type_text = "HTTP"
                proxy.setType(QNetworkProxy.ProxyType.HttpProxy)

            proxy.setHostName(host)
            proxy.setPort(int(info.get("port") or 0))

            if username:
                proxy.setUser(username)
                proxy.setPassword(password)

            QNetworkProxy.setApplicationProxy(proxy)

            self.proxy_enabled = True
            self.proxy_info = {
                "enabled": True,
                "type": proxy_type_text,
                "host": host,
                "port": int(info.get("port") or 0),
                "username": username,
                "password": password
            }

        self.update_proxy_label()

        if rebuild:
            self.rebuild_webengine_after_proxy_change()


    def rebuild_webengine_after_proxy_change(self):
        if self._bulk_processing or self._wa_sync_processing:
            QMessageBox.warning(
                self,
                "Proxy Change Blocked",
                "Cannot change proxy while a WhatsApp automation job is running."
            )
            return

        current_widget = self.tab_widget.currentWidget()
        current_key = None
        snapshot = []

        # Save only web tabs; API sheet tabs can stay open
        for idx, tab in enumerate(list(self.tab_views)):
            view = tab["view"]
            current_url = view.url().toString().strip() or tab.get("home") or ""

            snap = {
                "name": tab["name"],
                "allowed_sites": list(tab["allowed_sites"]),
                "home": tab["home"],
                "is_fixed": bool(tab.get("is_fixed")),
                "account_id": tab.get("account_id"),
                "title": self.tab_widget.tabText(self.tab_widget.indexOf(view)),
                "url": current_url
            }
            snapshot.append(snap)

            if view == current_widget:
                current_key = (snap["name"], snap["account_id"], snap["url"], idx)

        # Remove old web tabs
        for tab in list(self.tab_views):
            view = tab["view"]
            page = view.page()

            try:
                page.proxyAuthenticationRequired.disconnect(self.on_proxy_auth_required)
            except Exception:
                pass

            try:
                idx = self.tab_widget.indexOf(view)
                if idx != -1:
                    self.tab_widget.removeTab(idx)
            except Exception:
                pass

            view.deleteLater()

        self.tab_views.clear()

        # Rebuild profiles after proxy change
        try:
            if hasattr(self, "profile") and self.profile is not None:
                self.profile.deleteLater()
        except Exception:
            pass

        for profile in list(self.whatsapp_profiles.values()):
            try:
                profile.deleteLater()
            except Exception:
                pass

        self.profile_interceptors = []
        self.whatsapp_profiles = {}
        self.profile = self.create_shared_profile()

        # Recreate tabs in the same order
        for snap in snapshot:
            if snap["name"] == "WhatsApp":
                profile = self.get_or_create_whatsapp_profile(snap["account_id"])
            else:
                profile = self.profile

            self.add_browser_tab(
                config={
                    "name": snap["name"],
                    "allowed_sites": snap["allowed_sites"],
                    "home": snap["home"]
                },
                title=snap["title"],
                is_fixed=snap["is_fixed"],
                switch_to=False,
                initial_url=snap["url"],
                profile=profile,
                account_id=snap["account_id"]
            )

        self.save_whatsapp_tabs_state()
        self.refresh_collection_whatsapp_accounts()
        self.apply_bulk_message_policy_ui()

        # Restore focus roughly to the same tab
        if current_key is not None:
            target_name, target_account_id, target_url, _ = current_key
            for tab in self.tab_views:
                view = tab["view"]
                same_name = tab["name"] == target_name
                same_acc = tab.get("account_id") == target_account_id
                if same_name and same_acc:
                    self.tab_widget.setCurrentWidget(view)
                    break

        self.status_bar.showMessage("Proxy applied and browser tabs rebuilt.", 5000)
    
    def apply_light_ui_theme(self):
        app = QApplication.instance()
        if not app:
            return

        app.setStyle("Fusion")

        pal = QPalette()
        pal.setColor(QPalette.ColorRole.Window, QColor("#eef4ff"))
        pal.setColor(QPalette.ColorRole.WindowText, QColor("#0d2d63"))
        pal.setColor(QPalette.ColorRole.Base, QColor("#fbfdff"))
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor("#edf3ff"))
        pal.setColor(QPalette.ColorRole.ToolTipBase, QColor("#ffffff"))
        pal.setColor(QPalette.ColorRole.ToolTipText, QColor("#0d2d63"))
        pal.setColor(QPalette.ColorRole.Text, QColor("#10315e"))
        pal.setColor(QPalette.ColorRole.Button, QColor("#e8f0ff"))
        pal.setColor(QPalette.ColorRole.ButtonText, QColor("#0d2d63"))
        pal.setColor(QPalette.ColorRole.BrightText, QColor("#ffffff"))
        pal.setColor(QPalette.ColorRole.Highlight, QColor("#2b5fd9"))
        pal.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
        app.setPalette(pal)

        app.setStyleSheet("""
            QMainWindow, QDialog {
                background: #f1f5ff;
                color: #0d2d63;
            }

            QWidget {
                color: #10315e;
                selection-background-color: #2b5fd9;
                selection-color: white;
            }

            QLabel {
                color: #10315e;
            }

            QToolBar {
                spacing: 8px;
                padding: 6px;
                background: #dbe7ff;
                border: 1px solid #9ab2d8;
            }

            QStatusBar {
                background: #18355f;
                color: #f8fbff;
                border-top: 1px solid #284a7d;
            }

            QMenu, QDockWidget {
                background: #ffffff;
                color: #10315e;
            }

            QMenu {
                border: 1px solid #8fa9d4;
                padding: 2px;
            }

            QMenu::separator {
                height: 1px;
                background: #e2ebfa;
                margin: 6px 10px;
            }

            QMenu::item {
                padding: 6px 12px;
                background: transparent;
                color: #123563;
            }

            QMenu::item:selected {
                background: #2b5fd9;
                color: #ffffff;
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

            QLineEdit, QTextEdit, QPlainTextEdit, QComboBox,
            QListWidget, QTableWidget, QTreeWidget, QDateEdit, QTabWidget::pane, QScrollArea, QAbstractItemView {
                background: #ffffff;
                color: #10315e;
                border: 1px solid #8fa9d4;
                padding: 4px;
            }

            QComboBox, QDateEdit {
                padding: 4px 8px;
            }

            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 26px;
                border-left: 1px solid #8fa9d4;
                background: #dbe7ff;
            }

            QComboBox QAbstractItemView {
                background: #ffffff;
                color: #10315e;
                border: 1px solid #8fa9d4;
                padding: 2px;
                selection-background-color: #2b5fd9;
                selection-color: #ffffff;
                outline: 0;
            }

            QListView, QMenu, QListWidget {
                outline: 0;
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

            QTabBar::close-button {
                background: #f7faff;
                border: 1px solid #8fa9d4;
                width: 18px;
                height: 18px;
                subcontrol-position: right;
                margin-left: 6px;
            }

            QHeaderView::section {
                background: #d8e6ff;
                color: #17386a;
                border: 1px solid #8fa9d4;
                padding: 6px;
                font-weight: 700;
            }

            QScrollBar:vertical {
                background: #eef4ff;
                width: 12px;
                margin: 0px;
                border: 1px solid #8fa9d4;
            }

            QScrollBar::handle:vertical {
                background: #9fbce8;
                min-height: 32px;
                border: 1px solid #6f8fbd;
            }

            QScrollBar::handle:vertical:hover {
                background: #7fa6dd;
            }

            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical,
            QScrollBar:horizontal, QScrollBar::add-line:horizontal,
            QScrollBar::sub-line:horizontal, QScrollBar::add-page:horizontal,
            QScrollBar::sub-page:horizontal {
                background: transparent;
                border: none;
                height: 0px;
                width: 0px;
            }

            QToolTip {
                background: #ffffff;
                color: #10315e;
                border: 1px solid #8fa9d4;
                padding: 4px 6px;
            }

            QDockWidget::title {
                background: #edf4ff;
                color: #0d2d63;
                padding: 8px 10px;
                border-bottom: 1px solid #8fa9d4;
                font-weight: 800;
            }
        """)
    
    def _handle_live_view_request(self, req):
        result_box = {}
        done_event = None

        if isinstance(req, dict):
            result_box = req.get("result") or {}
            done_event = req.get("done")

        try:
            quality = int(req.get("quality", 70)) if isinstance(req, dict) else 70
            max_width = int(req.get("max_width", 1280)) if isinstance(req, dict) else 1280
            scope = str(req.get("scope", "window")).strip().lower() if isinstance(req, dict) else "window"

            frame_bytes, meta = self.capture_live_view_jpeg(
                quality=quality,
                max_width=max_width,
                scope=scope
            )

            result_box["ok"] = True
            result_box["frame"] = frame_bytes
            result_box["meta"] = meta
        except Exception as e:
            result_box["ok"] = False
            result_box["error"] = str(e)
        finally:
            if done_event:
                done_event.set()


    def capture_live_view_jpeg(self, quality=70, max_width=1280, scope="window"):
        quality = max(20, min(95, int(quality)))
        max_width = max(320, min(2560, int(max_width)))
        scope = str(scope or "window").strip().lower()

        current_widget = self.tab_widget.currentWidget()
        current_tab_text = ""
        current_url = ""

        if current_widget is not None:
            idx = self.tab_widget.indexOf(current_widget)
            if idx >= 0:
                current_tab_text = self.tab_widget.tabText(idx)

        if isinstance(current_widget, QWebEngineView):
            current_url = current_widget.url().toString()

        if scope == "tab" and current_widget is not None:
            pixmap = current_widget.grab()
        else:
            pixmap = self.grab()

        if pixmap.isNull():
            raise RuntimeError("Failed to capture live view.")

        if pixmap.width() > max_width:
            pixmap = pixmap.scaledToWidth(
                max_width,
                Qt.TransformationMode.SmoothTransformation
            )

        byte_array = QByteArray()
        buffer = QBuffer(byte_array)
        if not buffer.open(QIODevice.OpenModeFlag.WriteOnly):
            raise RuntimeError("Failed to open JPEG buffer.")

        ok = pixmap.save(buffer, "JPG", quality)
        buffer.close()

        if not ok:
            raise RuntimeError("Failed to encode JPEG frame.")

        meta = {
            "captured_at": datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
            "window_title": self.windowTitle(),
            "current_tab": current_tab_text,
            "current_url": current_url,
            "scope": scope,
            "width": pixmap.width(),
            "height": pixmap.height(),
            "quality": quality
        }

        return bytes(byte_array), meta

    def is_custom_bulk_message_enabled(self):
        return bool(load_app_state().get("allow_custom_bulk_message", False))


    def set_custom_bulk_message_enabled(self, enabled):
        state = load_app_state()
        state["allow_custom_bulk_message"] = bool(enabled)
        save_app_state(state)

    def is_cashier_mode_enabled(self):
        return bool(load_app_state().get("cashier_mode_enabled", False))


    def set_cashier_mode_enabled(self, enabled):
        state = load_app_state()
        state["cashier_mode_enabled"] = bool(enabled)
        save_app_state(state)


    def update_bulk_message_policy_label(self):
        if hasattr(self, "bulk_policy_label"):
            text = "CUSTOM ON" if self.is_custom_bulk_message_enabled() else "TEMPLATES ONLY"
            self.bulk_policy_label.setText(f"  Bulk Msg: {text}  ")


    def update_cashier_mode_label(self):
        if hasattr(self, "cashier_mode_label"):
            text = "ON" if self.is_cashier_mode_enabled() else "OFF"
            self.cashier_mode_label.setText(f"  Cashier: {text}  ")


    def apply_bulk_message_policy_ui(self):
        self.update_bulk_message_policy_label()

        if hasattr(self, "collection_blast_dock"):
            self.collection_blast_dock.set_templates(load_templates())
            self.collection_blast_dock.set_custom_message_enabled(
                self.is_custom_bulk_message_enabled()
            )


    def push_cashier_mode_to_whatsapp_view(self, view):
        if not isinstance(view, QWebEngineView):
            return

        enabled_js = "true" if self.is_cashier_mode_enabled() else "false"
        try:
            view.page().runJavaScript(
                f"""
                (function() {{
                    window.__waCashierModeEnabled = {enabled_js};
                    window.dispatchEvent(new Event("__ptn_cashier_mode_changed"));
                }})();
                """
            )
        except Exception:
            pass


    def apply_cashier_mode_ui(self):
        self.update_cashier_mode_label()

        for tab in self.tab_views:
            if tab.get("name") == "WhatsApp":
                self.push_cashier_mode_to_whatsapp_view(tab.get("view"))


    def configure_cashier_mode(self):
        if not self.require_admin_password():
            QMessageBox.warning(self, "Error", "Incorrect password.")
            return

        current_enabled = self.is_cashier_mode_enabled()
        options = [
            "Disable cashier mode",
            "Enable cashier mode"
        ]

        choice, ok = QInputDialog.getItem(
            self,
            "Cashier Mode",
            f"Current mode: {'Enabled' if current_enabled else 'Disabled'}\n\n"
            "When enabled, users cannot type manual WhatsApp replies and must use Reply Template.",
            options,
            1 if current_enabled else 0,
            False
        )
        if not ok:
            return

        enabled = (choice == options[1])
        self.set_cashier_mode_enabled(enabled)
        self.apply_cashier_mode_ui()

        msg = (
            "Cashier mode enabled. Manual WhatsApp typing is blocked; users must reply via template."
            if enabled else
            "Cashier mode disabled. Manual WhatsApp typing is allowed again."
        )
        self.status_bar.showMessage(msg, 5000)
        QMessageBox.information(self, "Cashier Mode", msg)


    def configure_custom_bulk_message_policy(self):
        if not self.require_admin_password():
            QMessageBox.warning(self, "Error", "Incorrect password.")
            return

        current_enabled = self.is_custom_bulk_message_enabled()

        options = [
            "Disable custom bulk message (templates only)",
            "Enable custom bulk message"
        ]

        choice, ok = QInputDialog.getItem(
            self,
            "Bulk Message Policy",
            f"Current mode: {'Enable custom message' if current_enabled else 'Templates only'}\n\nSelect new mode:",
            options,
            1 if current_enabled else 0,
            False
        )
        if not ok:
            return

        enabled = (choice == options[1])
        self.set_custom_bulk_message_enabled(enabled)
        self.apply_bulk_message_policy_ui()

        msg = "Custom bulk message enabled." if enabled else "Custom bulk message disabled. Users can only use saved templates."
        self.status_bar.showMessage(msg, 5000)
        QMessageBox.information(self, "Bulk Message Policy", msg)

        if not enabled and not load_templates():
            QMessageBox.information(
                self,
                "No Templates Yet",
                "Custom bulk message is now disabled, but there are no saved templates yet.\n\nPlease create at least one template first."
            )
    
    def poll_runtime_data(self):
        if not self._app_is_active:
            return

        self.fetch_network_logs_current_tab()

        # Stagger the heavier jobs so they do not all hit at once.
        QTimer.singleShot(180, self.fetch_manual_send_logs)
        QTimer.singleShot(420, self.fetch_incoming_reply_logs)


    def fetch_network_logs_current_tab(self):
        current = self.tab_widget.currentWidget()
        if not isinstance(current, QWebEngineView):
            return

        current.page().runJavaScript(
            """
            (function() {
                const logs = window.__networkLogs || [];
                window.__networkLogs = [];
                return JSON.stringify(logs);
            })();
            """,
            self.handle_network_logs
        )
    
    def verify_proxy_connectivity(self):
        if not self.proxy_info.get("enabled"):
            return

        self._proxy_test_manager = QNetworkAccessManager(self)
        request = QNetworkRequest(QUrl("https://api.ipify.org?format=json"))
        reply = self._proxy_test_manager.get(request)

        done = {"value": False}
        timeout = QTimer(self)
        timeout.setSingleShot(True)

        def finish_ok():
            if done["value"]:
                return
            done["value"] = True
            timeout.stop()

            if reply.error():
                msg = f"Proxy test failed: {reply.errorString()}"
                self.status_bar.showMessage(msg, 8000)
                QMessageBox.warning(self, "Proxy Test Failed", msg)
                save_network_log({
                    "type": "proxy_test",
                    "result": "failed",
                    "error": reply.errorString(),
                    "proxy": dict(self.proxy_info),
                    "ts": datetime.datetime.now().isoformat()
                })
                reply.deleteLater()
                return

            raw = bytes(reply.readAll()).decode("utf-8", errors="ignore")
            public_ip = ""
            try:
                data = json.loads(raw)
                public_ip = str(data.get("ip") or "").strip()
            except Exception:
                pass

            msg = f"Proxy test OK. Public IP: {public_ip or 'unknown'}"
            self.status_bar.showMessage(msg, 8000)
            QMessageBox.information(self, "Proxy Test", msg)

            save_network_log({
                "type": "proxy_test",
                "result": "ok",
                "public_ip": public_ip,
                "proxy": dict(self.proxy_info),
                "ts": datetime.datetime.now().isoformat()
            })
            reply.deleteLater()

        def finish_timeout():
            if done["value"]:
                return
            done["value"] = True
            try:
                reply.abort()
            except Exception:
                pass

            msg = "Proxy test timed out."
            self.status_bar.showMessage(msg, 8000)
            QMessageBox.warning(self, "Proxy Test Failed", msg)

            save_network_log({
                "type": "proxy_test",
                "result": "timeout",
                "proxy": dict(self.proxy_info),
                "ts": datetime.datetime.now().isoformat()
            })

        reply.finished.connect(finish_ok)
        timeout.timeout.connect(finish_timeout)
        timeout.start(10000)
    
    def _current_activity_tab_name(self):
        current = self.tab_widget.currentWidget()

        if isinstance(current, QWebEngineView):
            meta = self.find_tab_meta_by_view(current)
            if not meta:
                return "Unknown"

            if meta["name"] == "WhatsApp":
                return self._format_whatsapp_label(meta.get("account_id"))

            return str(meta["name"])

        if isinstance(current, ApiSheetTab):
            return "API Sheet"

        return "Unknown"


    def _flush_active_tab_time(self, stop=False):
        if self._activity_started_monotonic is not None and self._activity_current_tab_label:
            elapsed = int(max(0, time.monotonic() - self._activity_started_monotonic))
            if elapsed > 0:
                record_tab_seconds(self._activity_current_tab_label, elapsed)

        if stop or not self._app_is_active:
            self._activity_current_tab_label = None
            self._activity_started_monotonic = None
            return

        self._activity_current_tab_label = self._current_activity_tab_name()
        self._activity_started_monotonic = time.monotonic()


    def _record_attendance_touch(self, force=False, source="touch"):
        try:
            now_mono = time.monotonic()
            if (
                not force and
                self._attendance_last_record_monotonic and
                (now_mono - self._attendance_last_record_monotonic) < ATTENDANCE_TOUCH_DEBOUNCE_SECONDS
            ):
                return

            self._attendance_last_record_monotonic = now_mono
            record_attendance_touch(source=source)
        except Exception:
            pass


    def eventFilter(self, obj, event):
        try:
            if event is not None:
                event_type = event.type()

                if event_type in (QEvent.Type.Show, QEvent.Type.Polish):
                    apply_ios_button_shadow(obj)
                    configure_rounded_combo_popup(obj)
                    configure_data_table_widget(obj)

                if not self._app_is_active:
                    return super().eventFilter(obj, event)

                tracked_sources = {
                    QEvent.Type.MouseButtonPress: "mouse",
                    QEvent.Type.MouseButtonDblClick: "mouse",
                    QEvent.Type.Wheel: "wheel",
                    QEvent.Type.KeyPress: "keyboard",
                    QEvent.Type.FocusIn: "focus",
                    QEvent.Type.TouchBegin: "touch",
                    QEvent.Type.TabletPress: "tablet",
                    QEvent.Type.ShortcutOverride: "shortcut"
                }
                source = tracked_sources.get(event_type)
                if source:
                    self._record_attendance_touch(source=source)
        except Exception:
            pass

        return super().eventFilter(obj, event)


    def on_current_tab_changed(self, _index):
        current = self.tab_widget.currentWidget()
        if isinstance(current, QWebEngineView):
            meta = self.find_tab_meta_by_view(current)
            if meta and meta.get("name") == "WhatsApp":
                QTimer.singleShot(500, lambda v=current: self.refresh_whatsapp_identity_for_view(v))

        self._record_attendance_touch(source="tab_change")
        self._flush_active_tab_time(stop=False)
        self.update_collection_blast_dock()


    def on_application_state_changed(self, state):
        active_now = state == Qt.ApplicationState.ApplicationActive
        if active_now == self._app_is_active:
            return

        if not active_now:
            self._app_is_active = False
            self._flush_active_tab_time(stop=True)
            return

        self._app_is_active = True
        self._activity_current_tab_label = self._current_activity_tab_name()
        self._activity_started_monotonic = time.monotonic()
        self._record_attendance_touch(force=True, source="app_active")


    def start_local_api_server(self):
        try:
            self.api_server = ThreadingHTTPServer((API_HOST, API_PORT), LockedBrowserApiHandler)
            self.api_server.main_window = self
            self.api_server_thread = threading.Thread(
                target=self.api_server.serve_forever,
                daemon=True
            )
            self.api_server_thread.start()
            print(f"LockedBrowser API listening on {API_HOST}:{API_PORT}")
        except Exception as e:
            print("Failed to start local API server:", e)


    def show_user_stats(self):
        if not self.require_admin_password():
            QMessageBox.warning(self, "Error", "Incorrect password.")
            return

        dlg = UserStatsDialog(day_key_value=today_key(), parent=self)
        dlg.exec()

    def show_attendance(self):
        dlg = AttendanceDialog(parent=self)
        dlg.exec()
    
    def open_template_manager(self):
        if not self.require_admin_password():
            QMessageBox.warning(self, "Error", "Incorrect password.")
            return

        dlg = TemplateManagerDialog(self)
        dlg.exec()
        self.apply_bulk_message_policy_ui()
        self.apply_cashier_mode_ui()

    def get_current_whatsapp_tab_or_warn(self):
        current = self.tab_widget.currentWidget()
        if not isinstance(current, QWebEngineView):
            fallback = self.get_active_whatsapp_tab()
            if fallback:
                self.tab_widget.setCurrentWidget(fallback["view"])
                return fallback

            QMessageBox.warning(self, "WhatsApp Required", "Please open a WhatsApp tab first.")
            return None

        meta = self.find_tab_meta_by_view(current)
        if meta and meta.get("name") == "WhatsApp":
            return meta

        fallback = self.get_active_whatsapp_tab()
        if fallback:
            self.tab_widget.setCurrentWidget(fallback["view"])
            return fallback

        QMessageBox.warning(self, "WhatsApp Required", "Please open a WhatsApp tab first.")
        return None

    def get_active_whatsapp_chat_context(self, wa_tab):
        if not wa_tab:
            return {}

        view = wa_tab.get("view")
        if not view:
            return {}

        script = """
        (function() {
            function normalizeText(value) {
                return String(value || "")
                    .replace(/\\u200e/g, "")
                    .replace(/\\u00A0/g, " ")
                    .replace(/\\s+/g, " ")
                    .trim();
            }

            function normalizePhone(raw) {
                const digits = String(raw || "").replace(/\\D/g, "");
                if (!digits) return "";
                if (digits.startsWith("0") && digits.length >= 8) return "62" + digits.slice(1);
                if (digits.startsWith("62") && digits.length >= 8) return digits;
                if (digits.length >= 8) return digits;
                return "";
            }

            function extractPhone(raw) {
                const text = String(raw || "");
                const jidMatch = text.match(/(\\d{8,20})@(?:s\\.whatsapp\\.net|c\\.us|lid)/i);
                if (jidMatch) return normalizePhone(jidMatch[1]);

                const phoneish = text.match(/(?:\\+|00)?\\d[\\d\\s\\-()]{7,20}\\d/);
                if (phoneish) return normalizePhone(phoneish[0]);
                return "";
            }

            function getHeaderChatTitle() {
                const selectors = [
                    'main header [data-testid="conversation-info-header-chat-title"]',
                    'header [data-testid="conversation-info-header-chat-title"]',
                    'main header h1',
                    'header h1',
                    'main header span[title]',
                    'main header div[title]',
                    'header span[title]',
                    'header div[title]'
                ];

                const bad = new Set([
                    "", "profile", "profile details", "contact info", "group info",
                    "search", "menu", "more", "whatsapp",
                    "click here for contact info", "click for contact info"
                ]);

                for (const sel of selectors) {
                    const nodes = Array.from(document.querySelectorAll(sel));
                    for (const el of nodes) {
                        const text = normalizeText(el.getAttribute("title") || el.textContent || "");
                        if (!text) continue;
                        if (bad.has(text.toLowerCase())) continue;
                        return text;
                    }
                }
                return "";
            }

            function getSelectedRowTitle() {
                const selected = document.querySelector(
                    '#pane-side [aria-selected="true"], #pane-side div[role="row"] [aria-selected="true"]'
                );
                const row = selected ? (selected.closest('div[role="row"]') || selected) : null;
                if (!row) return "";

                const bad = new Set([
                    "", "profile", "profile details", "contact info", "group info",
                    "search", "menu", "more", "whatsapp",
                    "click here for contact info", "click for contact info",
                    "today", "yesterday", "you"
                ]);

                const titledNodes = Array.from(row.querySelectorAll('span[title], div[title]'));
                for (const el of titledNodes) {
                    const text = normalizeText(el.getAttribute("title") || el.textContent || "");
                    if (!text) continue;
                    if (bad.has(text.toLowerCase())) continue;
                    return text;
                }

                const lines = String(row.innerText || row.textContent || "")
                    .split(/\n+/)
                    .map(normalizeText)
                    .filter(Boolean);

                for (const line of lines) {
                    const lower = line.toLowerCase();
                    if (bad.has(lower)) continue;
                    if (/^\d{1,2}:\d{2}/.test(lower)) continue;
                    if (/^\d{1,3}$/.test(lower)) continue;
                    return line;
                }

                return "";
            }

            function extractPhoneFromMessageElement(msgEl) {
                if (!msgEl) return "";

                const candidates = [];
                try {
                    candidates.push(msgEl.getAttribute("data-id") || "");
                    candidates.push(msgEl.getAttribute("data-pre-plain-text") || "");
                } catch (e) {}

                try {
                    const prePlainEl = msgEl.querySelector("[data-pre-plain-text]");
                    if (prePlainEl) {
                        candidates.push(prePlainEl.getAttribute("data-pre-plain-text") || "");
                    }
                } catch (e) {}

                for (const candidate of candidates) {
                    const phone = extractPhone(candidate);
                    if (phone) return phone;
                }

                return "";
            }

            function getPhoneFromPageContext() {
                try {
                    const p = new URLSearchParams(location.search).get("phone");
                    const phone = extractPhone(p);
                    if (phone) return phone;
                } catch (e) {}

                const title = getHeaderChatTitle();
                const selectedRowTitle = getSelectedRowTitle();
                if (title && window.__waContactInfoCache && window.__waContactInfoCache[title.toLowerCase()]) {
                    return window.__waContactInfoCache[title.toLowerCase()];
                }

                if (selectedRowTitle && window.__waContactInfoCache && window.__waContactInfoCache[selectedRowTitle.toLowerCase()]) {
                    return window.__waContactInfoCache[selectedRowTitle.toLowerCase()];
                }

                const nodes = Array.from(document.querySelectorAll(".message-in, .message-out")).slice(-30).reverse();
                for (const msgEl of nodes) {
                    const phone = extractPhoneFromMessageElement(msgEl);
                    if (phone) return phone;
                }

                if (/^\\+?\\d[\\d\\s\\-()]{7,20}$/.test(title)) {
                    return extractPhone(title);
                }

                 if (/^\\+?\\d[\\d\\s\\-()]{7,20}$/.test(selectedRowTitle)) {
                    return extractPhone(selectedRowTitle);
                }

                return "";
            }

            const title = getHeaderChatTitle() || getSelectedRowTitle();
            const phone = getPhoneFromPageContext();
            const hasCompose = !!document.querySelector('footer div[contenteditable="true"], main footer div[contenteditable="true"]');
            const hasMessages = !!document.querySelector(".message-in, .message-out");
            const hasQr = !!document.querySelector('canvas[aria-label="Scan me!"], canvas[aria-label*="Scan"]');

            return JSON.stringify({
                title: title || "",
                phone: phone || "",
                display_phone: phone || "",
                conversation_key: phone || (title ? title.toLowerCase() : ""),
                has_compose: hasCompose,
                has_messages: hasMessages,
                has_qr: hasQr
            });
        })();
        """

        loop = QEventLoop(self)
        holder = {"result": ""}
        timer = QTimer(self)
        timer.setSingleShot(True)

        def finish():
            if timer.isActive():
                timer.stop()
            loop.quit()

        def handle_result(result):
            holder["result"] = result or ""
            finish()

        timer.timeout.connect(finish)
        timer.start(5000)
        view.page().runJavaScript(script, handle_result)
        loop.exec()

        raw = holder.get("result") or ""
        if not raw:
            return {}

        try:
            data = json.loads(raw)
        except Exception:
            return {}

        return data if isinstance(data, dict) else {}

    def insert_message_into_whatsapp_compose(self, wa_tab, message_text):
        if not wa_tab or not wa_tab.get("view"):
            return False, "WhatsApp tab not found."

        escaped_message = json.dumps(str(message_text or ""))
        script = f"""
        (function() {{
            const selectors = [
                'footer div[contenteditable="true"][data-testid="conversation-compose-box-input"]',
                'main footer div[contenteditable="true"][data-testid="conversation-compose-box-input"]',
                'footer div[contenteditable="true"][role="textbox"]',
                'main footer div[contenteditable="true"][role="textbox"]',
                'footer div[contenteditable="true"]',
                'main footer div[contenteditable="true"]'
            ];

            function findComposeBox() {{
                for (const sel of selectors) {{
                    const candidates = Array.from(document.querySelectorAll(sel));
                    for (const el of candidates) {{
                        if (!el) continue;
                        const footer = el.closest("footer");
                        if (!footer) continue;

                        const meta = (
                            (el.getAttribute("aria-label") || "") + " " +
                            (el.getAttribute("aria-placeholder") || "") + " " +
                            (el.getAttribute("data-testid") || "")
                        ).toLowerCase();

                        if (meta.includes("search")) continue;
                        return el;
                    }}
                }}
                return null;
            }}

            function insertMessagePreserveLines(composeBox, text) {{
                const normalized = String(text || "").replace(/\\r\\n/g, "\\n");
                composeBox.focus();

                const selection = window.getSelection();
                const range = document.createRange();
                range.selectNodeContents(composeBox);
                range.deleteContents();
                range.collapse(true);

                selection.removeAllRanges();
                selection.addRange(range);

                const lines = normalized.split("\\n");
                lines.forEach((line, idx) => {{
                    if (idx > 0) {{
                        const br = document.createElement("br");
                        range.insertNode(br);
                        range.setStartAfter(br);
                        range.collapse(true);
                    }}
                    if (line.length > 0) {{
                        const textNode = document.createTextNode(line);
                        range.insertNode(textNode);
                        range.setStartAfter(textNode);
                        range.collapse(true);
                    }}
                }});

                selection.removeAllRanges();
                selection.addRange(range);

                composeBox.dispatchEvent(new InputEvent("input", {{
                    bubbles: true,
                    data: normalized,
                    inputType: "insertText"
                }}));
                composeBox.dispatchEvent(new Event("change", {{ bubbles: true }}));
            }}

            const composeBox = findComposeBox();
            if (!composeBox) {{
                return JSON.stringify({{ ok: false, error: "compose_box_not_found" }});
            }}

            insertMessagePreserveLines(composeBox, {escaped_message});
            return JSON.stringify({{ ok: true }});
        }})();
        """

        loop = QEventLoop(self)
        holder = {"result": ""}
        timer = QTimer(self)
        timer.setSingleShot(True)

        def finish():
            if timer.isActive():
                timer.stop()
            loop.quit()

        def handle_result(result):
            holder["result"] = result or ""
            finish()

        timer.timeout.connect(finish)
        timer.start(5000)
        wa_tab["view"].page().runJavaScript(script, handle_result)
        loop.exec()

        try:
            payload = json.loads(holder.get("result") or "")
        except Exception:
            payload = {}

        if payload.get("ok"):
            return True, ""

        return False, str(payload.get("error") or "failed_to_insert_message")

    def open_whatsapp_template_reply(self):
        wa_tab = self.get_current_whatsapp_tab_or_warn()
        if not wa_tab:
            return

        templates = load_templates()
        if not templates:
            QMessageBox.warning(self, "No Templates", "No enabled templates are available.")
            return

        chat_context = self.get_active_whatsapp_chat_context(wa_tab)
        if chat_context.get("has_qr"):
            QMessageBox.warning(self, "WhatsApp Login Required", "Please log in to WhatsApp first.")
            return

        if not (
            chat_context.get("title") or
            chat_context.get("phone") or
            chat_context.get("has_compose") or
            chat_context.get("has_messages")
        ):
            chat_context = {
                "title": "Current conversation",
                "phone": "",
                "display_phone": "",
                "conversation_key": "current_conversation",
                "has_compose": False,
                "has_messages": False,
                "has_qr": False
            }

        last_blast = load_last_blast()
        matched_recipient = find_last_blast_recipient_for_chat(chat_context, last_blast=last_blast)
        reply_recipient = build_reply_template_recipient(chat_context, matched_recipient)

        dlg = TemplateReplyDialog(
            chat_context=chat_context,
            reply_recipient=reply_recipient,
            matched_recipient=matched_recipient,
            templates=templates,
            parent=self
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        ok, error = self.insert_message_into_whatsapp_compose(wa_tab, dlg.get_message())
        if not ok:
            QMessageBox.warning(
                self,
                "Insert Failed",
                f"Failed to insert template into WhatsApp compose box.\nReason: {error}"
            )
            return

        self.status_bar.showMessage("Template inserted into current WhatsApp chat.", 4000)
    
    def fetch_incoming_reply_logs(self):
        for tab in self.tab_views:
            if tab["name"] != "WhatsApp":
                continue

            view = tab["view"]
            account_id = tab.get("account_id")

            view.page().runJavaScript(
                """
                (function() {
                    const logs = window.__waIncomingReplyLogs || [];
                    window.__waIncomingReplyLogs = [];
                    return JSON.stringify(logs);
                })();
                """,
                lambda result, acc=account_id: self.handle_incoming_reply_logs(result, acc)
            )


    def handle_incoming_reply_logs(self, result, account_id):
        self.bad_words = load_bad_words()

        if not result:
            return

        try:
            logs = json.loads(result)
        except Exception:
            return

        if not isinstance(logs, list):
            return

        existing_logs = load_manual_send_log()
        existing_sigs = set()
        for item in existing_logs:
            if not isinstance(item, dict):
                continue
            if not is_whatsapp_incoming_history_send_type(item.get("send_type")):
                continue

            raw_sig = str(item.get("sig", "")).strip()
            if raw_sig:
                existing_sigs.add(raw_sig)

            derived_sig = derive_whatsapp_history_signature_from_log_item(item)
            if derived_sig:
                existing_sigs.add(derived_sig)

        for entry in logs:
            if not isinstance(entry, dict):
                continue

            content = str(entry.get("content") or "").strip()
            if not content and not bool(entry.get("has_attachment")):
                continue

            fallback_sig = "|".join([
                str(entry.get("from_phone") or entry.get("from") or "").strip(),
                str(entry.get("content") or "").strip(),
                str(entry.get("ts") or "").strip()
            ]).strip()

            sig = str(entry.get("sig") or fallback_sig).strip()
            if sig and sig in existing_sigs:
                continue

            try:
                message_length = int(entry.get("message_length") or len(content))
            except Exception:
                message_length = len(content)

            from_phone = normalize_chat_key(entry.get("from_phone"))
            chat_label = str(entry.get("chat") or entry.get("from") or "").strip()

            bad_labels = {
                "",
                "click here for contact info",
                "contact info",
                "click for contact info",
                "profile",
                "profile details",
                "group info"
            }

            if chat_label.lower() in bad_labels:
                chat_label = ""

            conversation_key = normalize_chat_key(
                entry.get("conversation_key") or from_phone or chat_label
            )

            display_sender = chat_label or from_phone or "Customer"

            _, incoming_hits = mask_bad_words(content, self.bad_words)
            incoming_bad_words = sorted(set(incoming_hits))
            incoming_bad_count = len(incoming_hits)

            payload = {
                "timestamp": entry.get("ts") or datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "from": from_phone or "",
                "from_display": display_sender,
                "from_phone": from_phone or "",
                "chat_label": chat_label,
                "conversation_key": conversation_key,
                "to": self._format_whatsapp_label(account_id),
                "content": content,
                "message_length": message_length,
                "has_attachment": bool(entry.get("has_attachment")),
                "send_type": "incoming_reply",
                "trigger": str(entry.get("trigger") or "incoming_unread_scan"),
                "status": "received",
                "sig": sig,
                "bad_word_count": incoming_bad_count,
                "bad_words": incoming_bad_words
            }

            record_incoming_reply_activity(from_phone or chat_label or display_sender)
            save_manual_send_log(payload)
            update_contact_interaction(
                send_number=payload.get("from_phone"),
                timestamp_text=payload.get("timestamp"),
                direction="incoming",
                message=payload.get("content"),
                send_type="incoming_reply",
                account_label=payload.get("to"),
                status=payload.get("status"),
                display_number=payload.get("from_display"),
                trigger=payload.get("trigger"),
                auto_create=False
            )

            if sig:
                existing_sigs.add(sig)

        self.refresh_performance_dock()

    def install_whatsapp_download_banner_hider(self, profile=None):
        profile = profile or self.profile

        script_source = r"""
        (function() {
            if (window.__waDownloadBannerHiderInstalled) return;
            window.__waDownloadBannerHiderInstalled = true;

            if (location.hostname !== "web.whatsapp.com") return;

            const TEXT_PATTERNS = [
                "download whatsapp for windows",
                "download whatsapp for mac",
                "download for windows",
                "download for mac"
            ];

            const CANDIDATE_SELECTORS = [
                'a[href*="whatsapp.com/download"]',
                'button',
                '[role="button"]',
                'a'
            ];

            function norm(value) {
                return String(value || "")
                    .replace(/\u00A0/g, " ")
                    .replace(/\s+/g, " ")
                    .trim()
                    .toLowerCase();
            }

            function getText(el) {
                if (!el) return "";
                return norm(
                    el.innerText ||
                    el.textContent ||
                    (el.getAttribute ? el.getAttribute("aria-label") : "") ||
                    (el.getAttribute ? el.getAttribute("title") : "")
                );
            }

            function shouldHide(el) {
                if (!el || !(el instanceof Element)) return false;

                const text = getText(el);
                const href = norm(el.getAttribute ? el.getAttribute("href") : "");

                if (href.includes("whatsapp.com/download")) {
                    return true;
                }

                return TEXT_PATTERNS.some(p => text.includes(p));
            }

            function isSmallPromo(el) {
                try {
                    const r = el.getBoundingClientRect();
                    return (
                        r.width > 0 &&
                        r.height > 0 &&
                        r.width <= 520 &&
                        r.height <= 160
                    );
                } catch (e) {
                    return false;
                }
            }

            function hideElement(el) {
                if (!el || el.dataset.__ptnHiddenDownload === "1") return;

                el.dataset.__ptnHiddenDownload = "1";
                el.style.setProperty("display", "none", "important");
                el.style.setProperty("visibility", "hidden", "important");
                el.style.setProperty("pointer-events", "none", "important");
                el.style.setProperty("max-height", "0", "important");
                el.style.setProperty("overflow", "hidden", "important");
            }

            function sweep() {
                try {
                    for (const sel of CANDIDATE_SELECTORS) {
                        const nodes = document.querySelectorAll(sel);
                        nodes.forEach(el => {
                            if (!shouldHide(el)) return;
                            if (!isSmallPromo(el)) return;
                            hideElement(el);
                        });
                    }
                } catch (e) {
                    console.log("waDownloadBannerHider error:", e);
                }
            }

            let scheduled = false;
            function scheduleSweep() {
                if (scheduled) return;
                scheduled = true;

                setTimeout(() => {
                    scheduled = false;
                    sweep();
                }, 400);
            }

            function start() {
                sweep();

                try {
                    const observer = new MutationObserver(() => {
                        scheduleSweep();
                    });

                    observer.observe(document.body, {
                        childList: true,
                        subtree: true
                    });
                } catch (e) {}

                setInterval(sweep, 4000);
            }

            if (document.readyState === "loading") {
                document.addEventListener("DOMContentLoaded", function() {
                    setTimeout(start, 1200);
                }, { once: true });
            } else {
                setTimeout(start, 1200);
            }
        })();
        """

        script = QWebEngineScript()
        script.setName("wa_download_banner_hider")
        script.setSourceCode(script_source)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        profile.scripts().insert(script)

    def install_whatsapp_incoming_reply_logger(self, profile=None):
        profile = profile or self.profile
        script_source = r"""
        (function() {
            if (window.__waIncomingReplyLoggerInstalled) return;
            window.__waIncomingReplyLoggerInstalled = true;

            if (location.hostname !== "web.whatsapp.com") return;

            window.__waIncomingReplyLogs = window.__waIncomingReplyLogs || [];
            window.__waIncomingSeen = window.__waIncomingSeen || {};
            window.__waIncomingActiveChat = window.__waIncomingActiveChat || "";
            window.__waIncomingChatSwitchAt = window.__waIncomingChatSwitchAt || 0;
            window.__waIncomingUnreadScanner = window.__waIncomingUnreadScanner || {
                running: false,
                pending: null,
                lastOpenedKey: "",
                lastOpenedAt: 0
            };

            const MAX_LOGS = 500;
            const MAX_SEEN = 2000;
            const CHAT_SWITCH_SUPPRESS_MS = 1400;
            const UNREAD_REOPEN_COOLDOWN_MS = 9000;

            const BAD_HEADER_TITLES = new Set([
                "",
                "profile",
                "profile details",
                "contact info",
                "group info",
                "search",
                "menu",
                "more",
                "whatsapp",
                "click here for contact info",
                "click for contact info"
            ]);

            function sleep(ms) {
                return new Promise(resolve => setTimeout(resolve, ms));
            }

            function normalizeText(value) {
                return String(value || "")
                    .replace(/\u200e/g, "")
                    .replace(/\u00A0/g, " ")
                    .replace(/\r/g, "")
                    .replace(/[ \t]+\n/g, "\n")
                    .replace(/\n[ \t]+/g, "\n")
                    .replace(/[ \t]{2,}/g, " ")
                    .trim();
            }

            function pushLog(entry) {
                try {
                    window.__waIncomingReplyLogs.unshift(entry);
                    if (window.__waIncomingReplyLogs.length > MAX_LOGS) {
                        window.__waIncomingReplyLogs.length = MAX_LOGS;
                    }
                } catch (e) {}
            }

            function rememberSeen(sig) {
                try {
                    window.__waIncomingSeen[sig] = Date.now();

                    const keys = Object.keys(window.__waIncomingSeen);
                    if (keys.length > MAX_SEEN) {
                        keys.sort((a, b) => window.__waIncomingSeen[a] - window.__waIncomingSeen[b]);
                        while (keys.length > MAX_SEEN) {
                            const k = keys.shift();
                            delete window.__waIncomingSeen[k];
                        }
                    }
                } catch (e) {}
            }

            function isSeen(sig) {
                return !!window.__waIncomingSeen[sig];
            }

            function isHistorySyncRunning() {
                return !!(
                    window.__waHistorySyncState &&
                    window.__waHistorySyncState.status === "running"
                );
            }

            function normalizePhone(raw) {
                const digits = String(raw || "").replace(/\D/g, "");
                if (!digits) return "";

                if (digits.startsWith("0") && digits.length >= 8) {
                    return "62" + digits.slice(1);
                }
                if (digits.startsWith("62") && digits.length >= 8) {
                    return digits;
                }
                if (digits.length >= 8) {
                    return digits;
                }
                return "";
            }

            function extractPhone(raw) {
                const text = String(raw || "");

                const jidMatch = text.match(/(\d{8,20})@(?:s\.whatsapp\.net|c\.us|lid)/i);
                if (jidMatch) return normalizePhone(jidMatch[1]);

                const phoneish = text.match(/(?:\+|00)?\d[\d\s\-()]{7,20}\d/);
                if (phoneish) return normalizePhone(phoneish[0]);

                return "";
            }

            function looksLikePhoneText(text) {
                const digits = String(text || "").replace(/\D/g, "");
                return digits.length >= 8 && digits.length <= 20;
            }

            function isLikelySecondaryHeaderText(text) {
                const lower = normalizeText(text).toLowerCase();
                if (!lower) return true;
                if (BAD_HEADER_TITLES.has(lower)) return true;
                if (lower === "you") return true;
                if (lower === "online") return true;
                if (lower.includes("typing")) return true;
                if (lower.includes("recording")) return true;
                if (lower.includes("last seen")) return true;
                if (/^\d{1,2}:\d{2}/.test(lower)) return true;
                if (/^(today|yesterday|monday|tuesday|wednesday|thursday|friday|saturday|sunday)$/.test(lower)) {
                    return true;
                }
                return false;
            }

            function getSelectedRowTitle() {
                const selected = document.querySelector(
                    '#pane-side [aria-selected="true"], #pane-side div[role="row"] [aria-selected="true"]'
                );
                const row = selected ? (selected.closest('div[role="row"]') || selected) : null;
                if (!row) return "";

                const titledNodes = Array.from(row.querySelectorAll('span[title], div[title]'));
                for (const el of titledNodes) {
                    const text = normalizeText(el.getAttribute("title") || el.textContent || "");
                    if (!text || isLikelySecondaryHeaderText(text)) continue;
                    return text;
                }

                const lines = String(row.innerText || row.textContent || "")
                    .split(/\n+/)
                    .map(normalizeText)
                    .filter(Boolean);

                for (const line of lines) {
                    if (!isLikelySecondaryHeaderText(line)) {
                        return line;
                    }
                }

                return "";
            }

            function getHeaderChatTitle() {
                const selectors = [
                    'main header [data-testid="conversation-info-header-chat-title"]',
                    'header [data-testid="conversation-info-header-chat-title"]',
                    'main header h1',
                    'header h1',
                    'main header span[title]',
                    'main header div[title]',
                    'header span[title]',
                    'header div[title]',
                    'main header span[dir="auto"]',
                    'main header div[dir="auto"]',
                    'header span[dir="auto"]',
                    'header div[dir="auto"]'
                ];

                const seen = new Set();

                for (const sel of selectors) {
                    const nodes = Array.from(document.querySelectorAll(sel));
                    for (const el of nodes) {
                        const raw = el.getAttribute("title") || el.textContent || "";
                        const text = normalizeText(raw);
                        if (!text) continue;

                        const lower = text.toLowerCase();
                        if (isLikelySecondaryHeaderText(text)) continue;
                        if (seen.has(lower)) continue;
                        seen.add(lower);

                        const rect = el.getBoundingClientRect();
                        if (rect.width < 20 || rect.height < 10) continue;

                        return text;
                    }
                }

                const header = document.querySelector("main header") || document.querySelector("header");
                if (header) {
                    const lines = String(header.innerText || header.textContent || "")
                        .split(/\n+/)
                        .map(normalizeText)
                        .filter(Boolean);

                    for (const line of lines) {
                        const lower = line.toLowerCase();
                        if (seen.has(lower)) continue;
                        if (isLikelySecondaryHeaderText(line)) continue;
                        return line;
                    }
                }

                return getSelectedRowTitle();
            }

            function extractPhoneFromMessageElement(msgEl) {
                if (!msgEl) return "";

                const candidates = [];

                try {
                    candidates.push(msgEl.getAttribute("data-id") || "");
                    candidates.push(msgEl.getAttribute("data-pre-plain-text") || "");
                } catch (e) {}

                try {
                    const prePlainEl = msgEl.querySelector("[data-pre-plain-text]");
                    if (prePlainEl) {
                        candidates.push(prePlainEl.getAttribute("data-pre-plain-text") || "");
                    }
                } catch (e) {}

                try {
                    const nodes = msgEl.querySelectorAll("[data-id], [data-pre-plain-text]");
                    for (const el of nodes) {
                        candidates.push(el.getAttribute("data-id") || "");
                        candidates.push(el.getAttribute("data-pre-plain-text") || "");
                    }
                } catch (e) {}

                for (const candidate of candidates) {
                    const phone = extractPhone(candidate);
                    if (phone) return phone;
                }

                return "";
            }

            function getPhoneFromPageContext() {
                try {
                    const p = new URLSearchParams(location.search).get("phone");
                    const phone = extractPhone(p);
                    if (phone) return phone;
                } catch (e) {}

                const nodes = Array.from(document.querySelectorAll(".message-in, .message-out"))
                    .slice(-40)
                    .reverse();

                for (const msgEl of nodes) {
                    const phone = extractPhoneFromMessageElement(msgEl);
                    if (phone) return phone;
                }

                const headerTitle = getHeaderChatTitle();
                if (looksLikePhoneText(headerTitle)) {
                    return extractPhone(headerTitle);
                }

                return "";
            }

            function getCurrentChatIdentity(msgEl) {
                let title = getHeaderChatTitle();
                if (BAD_HEADER_TITLES.has(String(title || "").toLowerCase())) {
                    title = "";
                }

                let phone = extractPhoneFromMessageElement(msgEl);
                if (!phone) {
                    if (title && window.__waContactInfoCache && window.__waContactInfoCache[title.toLowerCase()]) {
                        phone = window.__waContactInfoCache[title.toLowerCase()];
                    }
                }
                if (!phone) {
                    phone = getPhoneFromPageContext();
                }

                const label = title || phone || "Customer";
                const key = phone || (title ? title.toLowerCase() : "unknown");
                return { phone, label, key };
            }

            function mergeIdentity(primary, fallback) {
                const base = primary || {};
                const alt = fallback || {};

                let phone = base.phone || alt.phone || "";
                let label = base.label || alt.label || "Customer";
                let key = base.key || alt.key || phone || (label ? label.toLowerCase() : "unknown");

                if (label === "Customer" && alt.label) {
                    label = alt.label;
                }
                if ((!base.key || base.key === "unknown") && alt.key) {
                    key = alt.key;
                }

                return { phone, label, key };
            }

            function detectAttachmentLabel(msgEl) {
                try {
                    if (msgEl.querySelector('img[src^="blob:"], img[src^="data:"]')) return "[image]";
                    if (msgEl.querySelector("video")) return "[video]";
                    if (msgEl.querySelector("audio")) return "[audio]";
                    if (msgEl.querySelector("canvas")) return "[sticker]";
                    if (msgEl.querySelector('a[download], a[href*="blob:"]')) return "[document]";
                } catch (e) {}
                return "";
            }

            function getMessageText(msgEl) {
                const selectors = [
                    '.selectable-text.copyable-text',
                    'span.selectable-text',
                    '.copyable-text'
                ];

                for (const sel of selectors) {
                    const el = msgEl.querySelector(sel);
                    if (!el) continue;

                    const text = normalizeText(el.innerText || el.textContent || "");
                    if (text) return text;
                }

                return normalizeText(msgEl.innerText || msgEl.textContent || "");
            }

            function getMessageSignature(msgEl, chatKey, content) {
                const dataId = msgEl.getAttribute("data-id") || "";
                let prePlain = "";

                try {
                    const prePlainEl = msgEl.querySelector("[data-pre-plain-text]");
                    if (prePlainEl) {
                        prePlain = prePlainEl.getAttribute("data-pre-plain-text") || "";
                    }
                } catch (e) {}

                return [chatKey, dataId, prePlain, content].join("||");
            }

            function processIncomingMessage(msgEl, markOnly, trigger, overrideIdentity) {
                try {
                    if (isHistorySyncRunning()) {
                        return;
                    }
                    if (!msgEl || !msgEl.classList || !msgEl.classList.contains("message-in")) {
                        return;
                    }

                    const identity = mergeIdentity(getCurrentChatIdentity(msgEl), overrideIdentity);
                    const attachmentLabel = detectAttachmentLabel(msgEl);
                    let content = getMessageText(msgEl);

                    if (!content && attachmentLabel) {
                        content = attachmentLabel;
                    }

                    content = normalizeText(content);
                    if (!content && !attachmentLabel) return;

                    const sig = getMessageSignature(msgEl, identity.key || identity.label, content);
                    if (!sig) return;

                    if (isSeen(sig)) return;
                    rememberSeen(sig);

                    if (markOnly) return;

                    pushLog({
                        ts: new Date().toISOString(),
                        from: identity.phone || "",
                        from_phone: identity.phone || "",
                        chat: identity.label || "",
                        conversation_key: identity.key || "",
                        content: content,
                        message_length: content.length,
                        has_attachment: !!attachmentLabel,
                        trigger: trigger || "incoming_unread_scan",
                        sig: sig
                    });
                } catch (e) {}
            }

            function collectMessageRoots(node) {
                const out = [];
                if (!node || node.nodeType !== 1) return out;

                if (node.classList && (node.classList.contains("message-in") || node.classList.contains("message-out"))) {
                    out.push(node);
                }

                if (node.querySelectorAll) {
                    node.querySelectorAll(".message-in, .message-out").forEach(el => out.push(el));
                }

                return out;
            }

            function seedVisibleMessages() {
                if (isHistorySyncRunning()) return;
                try {
                    const identity = getCurrentChatIdentity(null);
                    if (identity.key) {
                        window.__waIncomingActiveChat = identity.key;
                    }

                    document.querySelectorAll(".message-in, .message-out").forEach(el => {
                        processIncomingMessage(el, true);
                    });
                } catch (e) {}
            }

            function isAutoSendRunning() {
                return !!(window.__waAutoSendState && window.__waAutoSendState.status === "running");
            }

            function isForegroundContext() {
                try {
                    if (document.visibilityState && document.visibilityState !== "visible") {
                        return false;
                    }
                } catch (e) {}
                return true;
            }

            function getChatListRoot() {
                const selectors = [
                    '#pane-side div[aria-label="Chat list"]',
                    'div[aria-label="Chat list"][role="grid"]',
                    '#pane-side'
                ];

                for (const sel of selectors) {
                    const el = document.querySelector(sel);
                    if (el) return el;
                }

                return null;
            }

            function getChatRows() {
                const root = getChatListRoot();
                if (!root) return [];

                const rows = Array.from(root.querySelectorAll('div[role="row"]'));
                return rows.filter(Boolean);
            }

            function isLikelySecondaryRowText(text) {
                const lower = String(text || "").toLowerCase();
                if (!lower) return true;
                if (BAD_HEADER_TITLES.has(lower)) return true;
                if (lower === "you") return true;
                if (/^(today|yesterday|monday|tuesday|wednesday|thursday|friday|saturday|sunday)$/.test(lower)) {
                    return true;
                }
                if (/^\d{1,2}:\d{2}/.test(lower)) return true;
                if (/^\d{1,2}\.\d{2}/.test(lower)) return true;
                if (lower.includes("unread")) return true;
                if (/^\d{1,3}$/.test(lower)) return true;
                return false;
            }

            function extractRowTitle(row) {
                if (!row) return "";

                const seen = new Set();
                const nodes = Array.from(row.querySelectorAll('span[title], div[title]'));

                for (const el of nodes) {
                    const text = normalizeText(el.getAttribute("title") || el.textContent || "");
                    const lower = text.toLowerCase();
                    if (!text || isLikelySecondaryRowText(text)) continue;
                    if (seen.has(lower)) continue;
                    seen.add(lower);
                    return text;
                }

                const lines = String(row.innerText || row.textContent || "")
                    .split(/\n+/)
                    .map(normalizeText)
                    .filter(Boolean);

                for (const line of lines) {
                    if (!isLikelySecondaryRowText(line)) {
                        return line;
                    }
                }

                return "";
            }

            function extractUnreadCountFromText(raw) {
                const lower = normalizeText(raw).toLowerCase();
                if (!lower) return 0;

                const countMatch = lower.match(/(\d{1,3})\s+unread/);
                if (countMatch) {
                    return parseInt(countMatch[1], 10) || 1;
                }

                if (lower.includes("unread")) {
                    return 1;
                }

                return 0;
            }

            function extractNumericBubbleCount(row) {
                if (!row) return 0;

                let best = 0;
                const nodes = Array.from(row.querySelectorAll("span, div"));

                for (const node of nodes) {
                    const text = normalizeText(node.textContent || "");
                    if (!/^\d{1,3}$/.test(text)) continue;

                    const rect = node.getBoundingClientRect();
                    if (rect.width < 6 || rect.height < 6) continue;
                    if (rect.width > 48 || rect.height > 36) continue;

                    best = Math.max(best, parseInt(text, 10) || 0);
                }

                return best;
            }

            function getRowUnreadCount(row) {
                if (!row) return 0;

                const rowLevelCount = extractUnreadCountFromText(row.getAttribute("aria-label") || "");
                if (rowLevelCount) return rowLevelCount;

                const ariaNodes = Array.from(row.querySelectorAll("[aria-label]"));
                for (const node of ariaNodes) {
                    const count = extractUnreadCountFromText(node.getAttribute("aria-label") || "");
                    if (count) return count;
                }

                const bubbleCount = extractNumericBubbleCount(row);
                if (bubbleCount) return bubbleCount;

                return 0;
            }

            function isRowSelected(row) {
                if (!row) return false;
                if ((row.getAttribute("aria-selected") || "").toLowerCase() === "true") return true;
                return !!row.querySelector('[aria-selected="true"]');
            }

            function getRowClickable(row) {
                if (!row) return null;

                const selectors = [
                    'div[role="gridcell"][tabindex="0"]',
                    'div[role="gridcell"][tabindex="-1"]',
                    'div[role="gridcell"]',
                    '[tabindex="0"]',
                    'button'
                ];

                for (const sel of selectors) {
                    const el = row.querySelector(sel);
                    if (el) return el;
                }

                return row;
            }

            function clickRow(row) {
                const target = getRowClickable(row);
                if (!target) return false;

                try {
                    target.focus?.();
                } catch (e) {}

                try {
                    target.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
                } catch (e) {}

                try {
                    target.click();
                    return true;
                } catch (e) {}

                try {
                    target.dispatchEvent(new MouseEvent("mouseup", { bubbles: true }));
                } catch (e) {}

                return false;
            }

            function buildRowIdentity(candidate) {
                const label = normalizeText(candidate && candidate.title ? candidate.title : "");
                const phone = normalizePhone(label);
                const key = phone || (label ? label.toLowerCase() : "");
                return {
                    phone: phone || "",
                    label: label || "Customer",
                    key: key || "unknown"
                };
            }

            function findNextUnreadCandidate() {
                const scanner = window.__waIncomingUnreadScanner || {};
                const rows = getChatRows();
                const now = Date.now();

                for (const row of rows) {
                    if (!row) continue;
                    if (isRowSelected(row)) continue;

                    const unreadCount = getRowUnreadCount(row);
                    if (!unreadCount) continue;

                    const title = extractRowTitle(row);
                    const key = normalizePhone(title) || (title ? title.toLowerCase() : "");

                    if (key && scanner.lastOpenedKey === key) {
                        if ((now - (scanner.lastOpenedAt || 0)) < UNREAD_REOPEN_COOLDOWN_MS) {
                            continue;
                        }
                    }

                    return {
                        row: row,
                        title: title || "",
                        key: key || "",
                        unreadCount: Math.max(1, unreadCount || 1)
                    };
                }

                return null;
            }

            async function waitForChatReady(candidate, timeoutMs) {
                const startedAt = Date.now();
                const timeout = timeoutMs || 6000;

                while ((Date.now() - startedAt) < timeout) {
                    const identity = getCurrentChatIdentity(null);
                    const headerTitle = normalizeText(identity.label || getHeaderChatTitle() || "");
                    const headerKey = normalizeText(identity.key || "");
                    const hasMessages = !!document.querySelector(".message-in, .message-out");

                    if (hasMessages) {
                        if (!candidate) return true;

                        if (candidate.key && headerKey && candidate.key === headerKey) {
                            return true;
                        }

                        if (candidate.title && headerTitle) {
                            const expected = candidate.title.toLowerCase();
                            const actual = headerTitle.toLowerCase();
                            if (expected === actual || actual.includes(expected) || expected.includes(actual)) {
                                return true;
                            }
                        }

                        if (!candidate.key && !candidate.title) {
                            return true;
                        }
                    }

                    await sleep(250);
                }

                return !!document.querySelector(".message-in, .message-out");
            }

            function collectRecentIncomingMessages(limit, overrideIdentity) {
                const maxItems = Math.max(1, Math.min(10, parseInt(limit || 1, 10) || 1));
                const nodes = Array.from(document.querySelectorAll(".message-in")).reverse();
                const collected = [];

                for (const msgEl of nodes) {
                    const attachmentLabel = detectAttachmentLabel(msgEl);
                    let content = getMessageText(msgEl);

                    if (!content && attachmentLabel) {
                        content = attachmentLabel;
                    }

                    content = normalizeText(content);
                    if (!content && !attachmentLabel) continue;

                    const identity = mergeIdentity(getCurrentChatIdentity(msgEl), overrideIdentity);
                    const sig = getMessageSignature(msgEl, identity.key || identity.label, content);
                    if (!sig || isSeen(sig)) continue;

                    collected.push(msgEl);
                    if (collected.length >= maxItems) break;
                }

                return collected.reverse();
            }

            function scanVisibleIncomingTail(markOnly, trigger, limit, overrideIdentity) {
                const identity = mergeIdentity(getCurrentChatIdentity(null), overrideIdentity);
                const targets = collectRecentIncomingMessages(limit || 4, identity);

                for (const msgEl of targets) {
                    processIncomingMessage(msgEl, markOnly, trigger || "incoming_unread_scan", identity);
                }

                return targets.length;
            }

            async function capturePendingUnreadChat() {
                const scanner = window.__waIncomingUnreadScanner;
                const pending = scanner && scanner.pending;
                if (!pending) return false;

                const rowIdentity = buildRowIdentity(pending);
                const currentIdentity = mergeIdentity(getCurrentChatIdentity(null), rowIdentity);

                if (currentIdentity.key) {
                    window.__waIncomingActiveChat = currentIdentity.key;
                }

                const capturedCount = scanVisibleIncomingTail(
                    false,
                    "incoming_unread_scan",
                    pending.unreadCount || 1,
                    rowIdentity
                );

                seedVisibleMessages();
                return capturedCount > 0;
            }

            function ensureChatBaseline() {
                try {
                    const identity = getCurrentChatIdentity(null);
                    if (!identity.key) return;

                    const scanner = window.__waIncomingUnreadScanner || {};
                    if (scanner.pending) {
                        window.__waIncomingActiveChat = identity.key;
                        return;
                    }

                    if (identity.key !== window.__waIncomingActiveChat) {
                        window.__waIncomingActiveChat = identity.key;
                        window.__waIncomingChatSwitchAt = Date.now();
                        setTimeout(seedVisibleMessages, 800);
                    }
                } catch (e) {}
            }

            async function scanUnreadChats() {
                const scanner = window.__waIncomingUnreadScanner;
                if (!scanner || scanner.running || scanner.pending) return;
                if (isAutoSendRunning()) return;
                if (isHistorySyncRunning()) return;
                if (!isForegroundContext()) return;

                const candidate = findNextUnreadCandidate();
                if (!candidate) return;

                scanner.running = true;
                scanner.pending = {
                    key: candidate.key || "",
                    title: candidate.title || "",
                    unreadCount: Math.max(1, candidate.unreadCount || 1),
                    openedAt: Date.now()
                };

                try {
                    if (!clickRow(candidate.row)) {
                        scanner.pending = null;
                        return;
                    }

                    scanner.lastOpenedKey = candidate.key || candidate.title || "";
                    scanner.lastOpenedAt = Date.now();
                    window.__waIncomingChatSwitchAt = Date.now();

                    await sleep(900);
                    await waitForChatReady(candidate, 6500);
                    await sleep(450);
                    await capturePendingUnreadChat();
                } catch (e) {
                } finally {
                    scanner.pending = null;
                    scanner.running = false;
                }
            }

            function startObserver() {
                seedVisibleMessages();

                const observer = new MutationObserver(mutations => {
                    if (isHistorySyncRunning()) {
                        return;
                    }
                    ensureChatBaseline();

                    const scanner = window.__waIncomingUnreadScanner || {};
                    const suppressLogs =
                        !!scanner.pending ||
                        ((Date.now() - (window.__waIncomingChatSwitchAt || 0)) < CHAT_SWITCH_SUPPRESS_MS);

                    for (const mutation of mutations) {
                        for (const node of mutation.addedNodes) {
                            const roots = collectMessageRoots(node);
                            for (const root of roots) {
                                processIncomingMessage(root, suppressLogs, "incoming_unread_scan");
                            }
                        }
                    }

                    // WhatsApp sometimes updates the active open chat by mutating
                    // nested nodes instead of appending a fresh `.message-in` root.
                    // Re-scan the visible tail so newly arrived messages in the
                    // currently open conversation still land in receive history.
                    scanVisibleIncomingTail(
                        suppressLogs,
                        "incoming_unread_scan",
                        suppressLogs ? 8 : 4
                    );

                    setTimeout(function() {
                        scanUnreadChats();
                    }, 350);
                });

                observer.observe(document.body, {
                    childList: true,
                    subtree: true
                });

                setInterval(function() {
                    if (isHistorySyncRunning()) {
                        return;
                    }
                    ensureChatBaseline();
                    const scanner = window.__waIncomingUnreadScanner || {};
                    const suppressLogs =
                        !!scanner.pending ||
                        ((Date.now() - (window.__waIncomingChatSwitchAt || 0)) < CHAT_SWITCH_SUPPRESS_MS);

                    scanVisibleIncomingTail(
                        suppressLogs,
                        "incoming_unread_scan",
                        suppressLogs ? 8 : 4
                    );
                    scanUnreadChats();
                }, 1200);

                setTimeout(scanUnreadChats, 2200);
            }

            if (document.readyState === "loading") {
                document.addEventListener("DOMContentLoaded", function() {
                    setTimeout(startObserver, 1500);
                }, { once: true });
            } else {
                setTimeout(startObserver, 1500);
            }
        })();
        """
        script = QWebEngineScript()
        script.setName("wa_incoming_reply_logger")
        script.setSourceCode(script_source)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        profile.scripts().insert(script)

    def require_admin_password(self):
        pwd, ok = QInputDialog.getText(
            self,
            "Admin Login",
            "Enter Password:",
            QLineEdit.EchoMode.Password
        )
        return ok and pwd == ADMIN_PASSWORD

    def fetch_manual_send_logs(self):
        for tab in self.tab_views:
            if tab["name"] != "WhatsApp":
                continue

            view = tab["view"]
            account_id = tab.get("account_id")

            view.page().runJavaScript(
                """
                (function() {
                    const logs = window.__waManualSendLogs || [];
                    window.__waManualSendLogs = [];
                    return JSON.stringify(logs);
                })();
                """,
                lambda result, acc=account_id: self.handle_manual_send_logs(result, acc)
            )

    def handle_manual_send_logs(self, result, account_id):
        self.bad_words = load_bad_words()

        if not result:
            return

        try:
            logs = json.loads(result)
        except Exception:
            return

        if not isinstance(logs, list):
            return

        existing_logs = load_manual_send_log()
        existing_manual_sigs = {
            str(item.get("sig", "")).strip()
            for item in existing_logs
            if isinstance(item, dict) and str(item.get("send_type")) == "manual"
        }

        for entry in logs:
            if not isinstance(entry, dict):
                continue

            timestamp = entry.get("ts") or datetime.datetime.now(datetime.timezone.utc).isoformat()
            raw_content = str(entry.get("content") or "")
            content, forced_hits = mask_bad_words(raw_content, self.bad_words)

            try:
                message_length = int(entry.get("message_length") or len(content))
            except Exception:
                message_length = len(content)

            bad_word_hits = [
                str(x).strip().lower()
                for x in (entry.get("bad_word_hits") or entry.get("bad_words") or [])
                if str(x).strip()
            ]

            if forced_hits:
                bad_word_hits = list(forced_hits)
            else:
                _, python_hits = mask_bad_words(content, self.bad_words)
                if python_hits and not bad_word_hits:
                    bad_word_hits = list(python_hits)

            bad_words = sorted(set(bad_word_hits))
            bad_word_count = int(entry.get("bad_word_count") or len(bad_word_hits) or 0)

            to_phone = normalize_chat_key(entry.get("to_phone") or entry.get("to"))
            to_label = str(entry.get("to") or "").strip()

            bad_labels = {
                "",
                "click here for contact info",
                "contact info",
                "click for contact info"
            }

            if to_label.lower() in bad_labels:
                to_label = ""

            to_label = to_label or "Customer"
            conversation_key = normalize_chat_key(
                entry.get("conversation_key") or to_phone or to_label
            )

            reply_speed_seconds = compute_reply_speed_for_outgoing(
                existing_logs,
                conversation_key,
                timestamp
            )

            sig = str(entry.get("sig") or "").strip()
            if not sig:
                sig = "|".join([
                    str(entry.get("to_phone") or entry.get("to") or "").strip(),
                    str(entry.get("content") or "").strip(),
                    str(entry.get("ts") or "").strip(),
                    str(entry.get("trigger") or "").strip()
                ]).strip()

            if sig and sig in existing_manual_sigs:
                continue

            payload = {
                "timestamp": timestamp,
                "from": self._format_whatsapp_label(account_id),
                "to": to_phone or to_label,
                "to_phone": to_phone or "",
                "conversation_key": conversation_key,
                "content": content,
                "message_length": message_length,
                "has_attachment": bool(entry.get("has_attachment")),
                "send_type": "manual",
                "trigger": str(entry.get("trigger") or "unknown"),
                "status": "sent",
                "bad_word_count": bad_word_count,
                "bad_words": bad_words,
                "reply_speed_seconds": reply_speed_seconds,
                "reply_speed_hms": format_duration_hms(reply_speed_seconds) if reply_speed_seconds is not None else "",
                "sig": sig
            }

            record_manual_send_activity(payload.get("to"))
            save_manual_send_log(payload)
            if sig:
                existing_manual_sigs.add(sig)
            existing_logs.append(payload)
            update_contact_interaction(
                send_number=payload.get("to_phone") or payload.get("to"),
                timestamp_text=payload.get("timestamp"),
                direction="outgoing",
                message=payload.get("content"),
                send_type="manual",
                account_label=payload.get("from"),
                status=payload.get("status"),
                display_number=payload.get("to"),
                trigger=payload.get("trigger")
            )

            if bad_word_hits:
                when_dt = ensure_user_datetime(timestamp) or datetime.datetime.now(USER_TIMEZONE)
                increment_bad_word_counter(
                    bad_word_hits,
                    source=self._format_whatsapp_label(account_id),
                    when_dt=when_dt,
                    sender=self._format_whatsapp_label(account_id),
                    receiver=payload.get("to"),
                    message_preview=payload.get("content"),
                    trigger=payload.get("trigger"),
                    send_type=payload.get("send_type")
                )
        
        self.refresh_performance_dock()

    def _reset_collection_dock_state(self):
        self._collection_staff_signature = ""
        self._collection_staff_records = []
        if hasattr(self, "collection_blast_dock"):
            self.collection_blast_dock.set_records([])
            self.collection_blast_dock.set_waiting(
                "Waiting for /api/staff/collections response while you stay on My Collections page..."
            )
    
    def clear_histories_no_password(self):
        if not self.require_admin_password():
            QMessageBox.warning(self, "Error", "Incorrect password.")
            return

        reply = QMessageBox.question(
            self,
            "Clear Histories",
            "This will clear page history, network logs, saved blast history, manual send logs, and bad-word counters.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            with open(HISTORY_FILE, "wb") as f:
                f.write(encrypt_data([]))

            with open(NETWORK_LOG_FILE, "wb") as f:
                f.write(encrypt_data([]))

            with open(LAST_BLAST_FILE, "wb") as f:
                f.write(encrypt_data({
                    "recipients": [],
                    "numbers": [],
                    "message": "",
                    "attachment_path": "",
                    "updated_at": ""
                }))

            with open(MANUAL_SEND_LOG_FILE, "wb") as f:
                f.write(encrypt_data([]))

            clear_bad_word_counter()
            clear_activity_stats()
            self.status_bar.showMessage("Histories cleared.", 3000)
            self.show_tray_message("Audit", "Histories cleared.")
            QMessageBox.information(self, "Success", "Histories cleared.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to clear histories:\n{e}")
    
    def _format_whatsapp_label(self, account_id):
        tab = self.find_whatsapp_tab_by_account_id(account_id) if account_id is not None else None
        if tab:
            display = str(tab.get("wa_self_display") or "").strip()
            if display:
                return f"WhatsApp {display}"

        return f"WhatsApp {account_id}" if account_id is not None else "WhatsApp"


    def find_whatsapp_tab_by_account_id(self, account_id):
        for tab in self.tab_views:
            if tab["name"] == "WhatsApp" and tab.get("account_id") == account_id:
                return tab
        return None

    def _queue_or_start_bulk_job(self, wa_tab, selected_items, template_text, attachment_path=""):
        if not wa_tab:
            QMessageBox.critical(self, "Error", "WhatsApp tab not found.")
            return False

        if self._wa_sync_processing:
            QMessageBox.information(
                self,
                "Sync Running",
                "Please wait until the current WhatsApp history sync finishes."
            )
            return False

        self.bad_words = load_bad_words()

        raw_items = list(selected_items or [])
        if not raw_items:
            QMessageBox.warning(self, "No Recipients", "No recipients selected.")
            return False

        unique_items, duplicate_count = dedupe_bulk_recipients(raw_items)
        if not unique_items:
            QMessageBox.warning(self, "No Valid Recipients", "No valid recipients were found.")
            return False

        adjustment_notes = []
        if duplicate_count > 0:
            adjustment_notes.append(f"{duplicate_count} duplicate number(s) were removed automatically.")

        if len(unique_items) > MAX_BULK_RECIPIENTS:
            adjustment_notes.append(
                f"Only the first {MAX_BULK_RECIPIENTS} unique number(s) will be processed."
            )
            unique_items = unique_items[:MAX_BULK_RECIPIENTS]

        template_text = (template_text or "").strip()
        if not template_text:
            QMessageBox.warning(self, "No Message", "Message cannot be empty.")
            return False

        attachment_path = normalize_template_attachment_path(attachment_path)
        if attachment_path and not is_supported_template_image_path(attachment_path, require_exists=True):
            QMessageBox.warning(
                self,
                "Attachment Missing",
                "The selected template image attachment is missing or not a supported JPG / JPEG / PNG file."
            )
            return False

        global_values = prompt_template_global_values(
            self,
            template_text,
            unique_items,
            action_label="this bulk send"
        )
        if global_values is None:
            return False

        rendered_recipients = build_bulk_recipients(
            unique_items,
            template_text,
            self.bad_words,
            global_values=global_values
        )
        rendered_recipients = [x for x in rendered_recipients if x.get("send_number")]

        if not rendered_recipients:
            QMessageBox.warning(self, "No Valid Recipients", "No valid recipients were found.")
            return False

        if adjustment_notes:
            QMessageBox.information(self, "Bulk Send Adjusted", "\n".join(adjustment_notes))

        total_masked_hits = sum(len(x.get("bad_word_hits") or []) for x in rendered_recipients)
        if total_masked_hits:
            self.status_bar.showMessage(
                f"Masked {total_masked_hits} bad word occurrence(s) before bulk send.",
                6000
            )

        view = wa_tab["view"]
        account_id = wa_tab.get("account_id")

        if any(job["view"] == view for job in self._bulk_queue):
            QMessageBox.information(
                self,
                "Already Queued",
                f"{self._format_whatsapp_label(account_id)} already has a queued bulk blast."
            )
            return False

        if self._bulk_processing and view == self._bulk_target_view:
            QMessageBox.information(
                self,
                "Already Running",
                f"{self._format_whatsapp_label(account_id)} is currently blasting."
            )
            return False

        save_last_blast(rendered_recipients, template_text, attachment_path)

        job = {
            "view": view,
            "account_id": account_id,
            "recipients": rendered_recipients,
            "template": template_text,
            "attachment_path": attachment_path
        }

        if self._bulk_processing:
            self._bulk_queue.append(job)
            self._refresh_queue_overlays()

            current_label = self._format_whatsapp_label(self._bulk_target_account_id)
            queued_label = self._format_whatsapp_label(account_id)
            queue_pos = len(self._bulk_queue)

            self.status_bar.showMessage(
                f"{queued_label} added to queue (position {queue_pos}). {current_label} is blasting.",
                6000
            )

            QMessageBox.information(
                self,
                "Queued",
                f"{current_label} is currently blasting.\n\n"
                f"{queued_label} has been added to queue.\n"
                f"Queue position: {queue_pos}"
            )
            return True

        save_history({
            "timestamp": datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
            "tab": self._format_whatsapp_label(job.get("account_id")),
            "event": "bulk_job_created",
            "recipient_count": len(job["recipients"]),
            "template_message": job["template"],
            "has_attachment": bool(job.get("attachment_path")),
            "recipient": [r.get("send_number") for r in job["recipients"]]
        })

        return self._start_bulk_job(job)

    def create_collection_blast_dock(self):
        self.collection_blast_dock = CollectionBlastDock(self)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.collection_blast_dock)
        self.collection_blast_dock.hide()

        self.collection_blast_dock.select_all_btn.clicked.connect(
            self.collection_blast_dock.select_all
        )
        self.collection_blast_dock.clear_btn.clicked.connect(
            self.collection_blast_dock.clear_all
        )
        self.collection_blast_dock.queue_btn.clicked.connect(
            self.queue_collection_blast_from_dock
        )


    def refresh_collection_whatsapp_accounts(self):
        accounts = []
        selected_id = None

        active_wa = self.get_active_whatsapp_tab()
        if active_wa and active_wa["name"] == "WhatsApp":
            selected_id = active_wa.get("account_id")

        for tab in self.tab_views:
            if tab["name"] == "WhatsApp":
                acc_id = tab.get("account_id")
                accounts.append((acc_id, self._format_whatsapp_label(acc_id)))

        self.collection_blast_dock.set_whatsapp_accounts(accounts, selected_id)
        self.collection_blast_dock.set_templates(load_templates())
        self.collection_blast_dock.set_custom_message_enabled(
            self.is_custom_bulk_message_enabled()
        )


    def update_collection_blast_dock(self):
        current = self.tab_widget.currentWidget()
        is_target_page = False

        if isinstance(current, QWebEngineView):
            meta = self.find_tab_meta_by_view(current)
            if meta and meta["name"] == "Collection":
                current_url = current.url().toString()
                target_fragment = "collection.pendanaan.com/#/job/collections-list/my-collections"
                if target_fragment in current_url:
                    is_target_page = True

        # leaving target page
        if not is_target_page:
            if self._collection_target_active:
                self._collection_target_active = False
                self._collection_page_entered_at = ""
                self._reset_collection_dock_state()

            self.collection_blast_dock.hide()
            return

        # entering target page
        if not self._collection_target_active:
            self._collection_target_active = True
            self._collection_page_entered_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self._reset_collection_dock_state()

        self.collection_blast_dock.show()
        self.refresh_collection_whatsapp_accounts()

        js = """
        (function() {
            const items = window.__apiTableCandidates || [];
            for (const item of items) {
                const url = String(item.url || "");
                if (url.indexOf("/api/staff/collections") !== -1) {
                    return JSON.stringify(item);
                }
            }
            return null;
        })();
        """
        current.page().runJavaScript(js, self.handle_collection_staff_collections_candidate)

    def handle_collection_staff_collections_candidate(self, result):
        if not self.collection_blast_dock.isVisible():
            return

        if not result:
            return

        try:
            item = json.loads(result)
        except Exception:
            return

        item_dt = parse_iso_dt(item.get("ts", ""))
        entered_dt = parse_iso_dt(self._collection_page_entered_at)

        if item_dt and entered_dt and item_dt < entered_dt:
            return

        payload = item.get("payload", {})
        records = extract_uid_mobile_pairs(payload)

        signature = json.dumps(records, sort_keys=True, ensure_ascii=False)
        if signature == self._collection_staff_signature:
            return

        self._collection_staff_signature = signature
        self._collection_staff_records = records

        if records:
            wait_text = (
                f"Found {len(records)} number(s) from /api/staff/collections. "
                "Select some or all, choose WhatsApp account, then queue or start blast."
            )

            if self._bulk_processing:
                running_label = self._format_whatsapp_label(self._bulk_target_account_id)
                wait_text += f"\n\n{running_label} is currently blasting. New request will be queued."

            self.collection_blast_dock.set_records(records)
            self.collection_blast_dock.set_waiting(wait_text)
        else:
            self.collection_blast_dock.set_records([])
            self.collection_blast_dock.set_waiting(
                "API detected, but no objects with both uid and mobile_no were found."
            )


    def queue_collection_blast_from_dock(self):
        records = self.collection_blast_dock.selected_records()
        if not records:
            QMessageBox.warning(self, "No Selection", "Please select at least one mobile number.")
            return

        message = self.collection_blast_dock.get_effective_message()
        attachment_path = self.collection_blast_dock.get_effective_attachment_path()
        if not message:
            QMessageBox.warning(
                self,
                "No Message",
                "Please select a saved template first."
                if not self.is_custom_bulk_message_enabled()
                else "Please enter a message first."
            )
            return

        account_id = self.collection_blast_dock.selected_account_id()
        if account_id is None:
            QMessageBox.warning(self, "No WhatsApp Account", "Please choose a WhatsApp account.")
            return

        wa_tab = self.find_whatsapp_tab_by_account_id(account_id)
        if not wa_tab:
            QMessageBox.warning(self, "WhatsApp Tab Missing", "Selected WhatsApp tab was not found.")
            return

        numbers = [rec["send_number"] for rec in records]

        reply = QMessageBox.question(
            self,
            "Confirm Blast",
            f"Send message to {len(numbers)} selected number(s)\n"
            f"using {self._format_whatsapp_label(account_id)}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        ok = self._queue_or_start_bulk_job(wa_tab, numbers, message, attachment_path=attachment_path)
        if ok and self._bulk_processing and wa_tab["view"] != self._bulk_target_view:
            QMessageBox.information(
                self,
                "Queued",
                f"{self._format_whatsapp_label(wa_tab.get('account_id'))} has been queued.\n"
                "It will start automatically after the current blast finishes."
            )

    def closeEvent(self, event):
        try:
            self._record_attendance_touch(force=True, source="close")
        except Exception:
            pass

        try:
            self._flush_active_tab_time(stop=True)
        except Exception:
            pass

        try:
            if hasattr(self, "api_server"):
                self.api_server.shutdown()
                self.api_server.server_close()
        except Exception:
            pass

        super().closeEvent(event)
    
    def _clear_active_overlay(self, view=None):
        if view is None:
            view = self._bulk_target_view
        if not view:
            return

        try:
            view.page().runJavaScript("""
            (function() {
                const overlay = document.getElementById("__ptn_bulk_overlay");
                if (overlay) overlay.remove();
            })();
            """)
        except Exception:
            pass

    def _render_queue_overlay(self, view, position):
        if not view:
            return

        html = f"""
        <div style="
            background: rgba(40,40,40,0.92);
            color: white;
            font-family: Arial, sans-serif;
            font-size: 12px;
            border-radius: 12px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.35);
            padding: 14px;
            border: 1px solid rgba(255,255,255,0.10);
        ">
            <div style="font-size:14px;font-weight:700;margin-bottom:8px;">
                PT Pendanaan Teknologi Nusa
            </div>

            <div style="margin-bottom:8px;color:#ffd966;font-weight:700;">
                Queued
            </div>

            <div style="line-height:1.5;">
                Another WhatsApp bulk blast is currently running.<br>
                Please wait for your queue.<br><br>
                <b>Queue position:</b> {position}
            </div>
        </div>
        """

        js = f"""
        (function() {{
            const overlayId = "__ptn_bulk_queue_overlay";
            let overlay = document.getElementById(overlayId);

            if (!overlay) {{
                overlay = document.createElement("div");
                overlay.id = overlayId;
                overlay.style.position = "fixed";
                overlay.style.top = "12px";
                overlay.style.left = "12px";
                overlay.style.width = "340px";
                overlay.style.zIndex = "2147483647";
                overlay.style.pointerEvents = "none";
                document.body.appendChild(overlay);
            }}

            overlay.innerHTML = {json.dumps(html)};
        }})();
        """
        view.page().runJavaScript(js)

    def _clear_queue_overlay(self, view):
        if not view:
            return

        try:
            view.page().runJavaScript("""
            (function() {
                const overlay = document.getElementById("__ptn_bulk_queue_overlay");
                if (overlay) overlay.remove();
            })();
            """)
        except Exception:
            pass

    def _refresh_queue_overlays(self):
        valid_queue = []
        for job in self._bulk_queue:
            if self.find_tab_meta_by_view(job["view"]) is not None:
                valid_queue.append(job)

        self._bulk_queue = valid_queue

        for pos, job in enumerate(self._bulk_queue, start=1):
            self._render_queue_overlay(job["view"], pos)

    def _remove_queued_jobs_for_view(self, view):
        removed = 0
        kept = []

        for job in self._bulk_queue:
            if job["view"] == view:
                removed += 1
            else:
                kept.append(job)

        self._bulk_queue = kept

        if removed:
            self._clear_queue_overlay(view)
            self._refresh_queue_overlays()

        return removed

    def _start_bulk_job(self, job):
        view = job["view"]
        if self.find_tab_meta_by_view(view) is None:
            return False

        self._clear_queue_overlay(view)

        self._bulk_target_view = view
        self._bulk_target_account_id = job.get("account_id")
        self._bulk_recipients = list(job["recipients"])
        self._bulk_template = job["template"]
        self._bulk_attachment_path = normalize_template_attachment_path(job.get("attachment_path"))
        self._bulk_statuses = [
            {"number": r.get("display_number") or r.get("send_number"), "status": "pending"}
            for r in self._bulk_recipients
        ]
        self._bulk_index = 0
        self._bulk_processing = True
        self._bulk_send_started_at = 0.0

        try:
            view.loadFinished.disconnect(self._on_bulk_whatsapp_load)
        except TypeError:
            pass

        view.loadFinished.connect(self._on_bulk_whatsapp_load)
        self._render_bulk_overlay()
        self._load_next_bulk_whatsapp()
        record_blast_activity(self._bulk_recipients)
        self.refresh_performance_dock()
        return True

    def _start_next_queued_bulk_job(self):
        while self._bulk_queue:
            job = self._bulk_queue.pop(0)
            self._refresh_queue_overlays()

            if self.find_tab_meta_by_view(job["view"]) is None:
                continue

            label = self._format_whatsapp_label(job.get("account_id"))
            self.status_bar.showMessage(f"Starting queued bulk blast on {label}...", 5000)
            self.show_tray_message("Bulk Queue", f"Starting queued bulk blast on {label}")
            return self._start_bulk_job(job)

        return False

    def get_whatsapp_sync_target_tab(self):
        if self._wa_sync_target_view is not None:
            meta = self.find_tab_meta_by_view(self._wa_sync_target_view)
            if meta and meta["name"] == "WhatsApp":
                return meta
        return None

    def sync_whatsapp_histories(self):
        if self._bulk_processing:
            QMessageBox.information(
                self,
                "Bulk Running",
                "Please wait until the current bulk WhatsApp blast finishes."
            )
            return

        if self._wa_sync_processing:
            QMessageBox.information(
                self,
                "Sync Running",
                "WhatsApp history sync is already running."
            )
            return

        wa_tabs = [tab for tab in self.tab_views if tab["name"] == "WhatsApp"]
        if not wa_tabs:
            QMessageBox.warning(self, "WhatsApp Required", "Please open a WhatsApp tab first.")
            return

        reply = QMessageBox.question(
            self,
            "Sync WhatsApp Histories",
            (
                f"Scan and sync chat histories across {len(wa_tabs)} WhatsApp tab(s)?\n\n"
                "Only logged-in WhatsApp tabs will be processed.\n"
                "The currently syncing tab will be locked until that tab finishes."
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.bad_words = load_bad_words()
        self._wa_sync_tabs = [
            {
                "view": tab["view"],
                "account_id": tab.get("account_id"),
                "label": self._format_whatsapp_label(tab.get("account_id")),
                "status": "pending",
                "saved_messages": 0,
                "duplicate_messages": 0,
                "saved_chats": 0,
                "error": ""
            }
            for tab in wa_tabs
        ]
        self._wa_sync_tab_index = -1
        self._wa_sync_target_view = None
        self._wa_sync_target_account_id = None
        self._wa_sync_processing = True
        self._wa_sync_started_at = 0.0
        self._wa_sync_current_state = {}
        self._wa_sync_total_saved = 0
        self._wa_sync_total_duplicates = 0
        self._wa_sync_total_chats = 0
        self._wa_sync_log_cache = load_manual_send_log()
        self._wa_sync_existing_signatures = set()

        for item in self._wa_sync_log_cache:
            if not isinstance(item, dict):
                continue
            raw_sig = str(item.get("sig") or "").strip()
            if raw_sig:
                self._wa_sync_existing_signatures.add(raw_sig)
            derived_sig = derive_whatsapp_history_signature_from_log_item(item)
            if derived_sig:
                self._wa_sync_existing_signatures.add(derived_sig)

        save_history({
            "timestamp": datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
            "event": "whatsapp_history_sync_started",
            "tab_count": len(self._wa_sync_tabs),
            "tabs": [tab.get("label") for tab in self._wa_sync_tabs]
        })
        self.status_bar.showMessage("WhatsApp history sync started.", 5000)
        self._start_next_whatsapp_history_sync_tab()

    def _build_whatsapp_sync_overlay_html(self):
        icons = {
            "pending": "WAIT",
            "running": "RUN",
            "done": "DONE",
            "skipped": "SKIP",
            "error": "ERR"
        }

        current_label = (
            self._format_whatsapp_label(self._wa_sync_target_account_id)
            if self._wa_sync_target_account_id is not None else "-"
        )
        current_chat = str(self._wa_sync_current_state.get("currentChat") or "-").strip() or "-"
        scanned_chats = int(self._wa_sync_current_state.get("scannedChats") or 0)
        total_known_chats = int(self._wa_sync_current_state.get("totalKnownChats") or 0)
        if total_known_chats < scanned_chats:
            total_known_chats = scanned_chats

        rows = []
        for idx, tab in enumerate(self._wa_sync_tabs, start=1):
            status = str(tab.get("status") or "pending")
            label = str(tab.get("label") or f"WhatsApp {idx}")
            icon = icons.get(status, "•")
            detail = (
                f"Chats: {int(tab.get('saved_chats') or 0)} | "
                f"Saved: {int(tab.get('saved_messages') or 0)} | "
                f"Duplicates: {int(tab.get('duplicate_messages') or 0)}"
            )
            if tab.get("error"):
                detail += f" | {str(tab.get('error'))}"
            rows.append(
                f"""
                <div style="display:flex;justify-content:space-between;gap:10px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.08);">
                    <span>{idx}. {label}</span>
                    <b>{icon} {status.upper()}</b>
                </div>
                <div style="padding:0 0 6px 0;color:#dbeafe;font-size:11px;">{detail}</div>
                """
            )

        rows_html = "".join(rows) if rows else "<div>No sync job running.</div>"

        title_text = (
            "Scanning and syncing WhatsApp histories. Please wait until finish."
            if self._wa_sync_processing else
            "WhatsApp history sync finished."
        )

        return f"""
        <div style="
            background: rgba(18,18,18,0.92);
            color: white;
            font-family: Arial, sans-serif;
            font-size: 12px;
            border-radius: 12px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.35);
            padding: 14px;
            border: 1px solid rgba(255,255,255,0.10);
        ">
            <div style="font-size:14px;font-weight:700;margin-bottom:8px;">
                PT Pendanaan Teknologi Nusa
            </div>

            <div style="margin-bottom:8px;color:#ffd966;font-weight:700;">
                {title_text}
            </div>

            <div style="margin-bottom:8px;line-height:1.5;">
                <div><b>Current tab:</b> {current_label}</div>
                <div><b>Current chat:</b> {current_chat}</div>
                <div><b>Chats done:</b> {scanned_chats} / {total_known_chats or '-'}</div>
                <div><b>Saved histories:</b> {self._wa_sync_total_saved} &nbsp; <b>Duplicates skipped:</b> {self._wa_sync_total_duplicates}</div>
            </div>

            <div style="max-height:260px;overflow:auto;padding-right:4px;">
                {rows_html}
            </div>
        </div>
        """

    def _render_whatsapp_sync_overlay(self, view=None):
        if view is None:
            target = self.get_whatsapp_sync_target_tab()
            view = target["view"] if target else None
        if not view:
            return

        html = self._build_whatsapp_sync_overlay_html()
        js = f"""
        (function() {{
            const overlayId = "__ptn_sync_overlay";
            let overlay = document.getElementById(overlayId);

            if (!overlay) {{
                overlay = document.createElement("div");
                overlay.id = overlayId;
                overlay.tabIndex = 0;
                overlay.style.position = "fixed";
                overlay.style.inset = "0";
                overlay.style.zIndex = "2147483647";
                overlay.style.background = "rgba(0,0,0,0.08)";
                overlay.style.pointerEvents = "auto";
                overlay.style.display = "flex";
                overlay.style.alignItems = "flex-start";
                overlay.style.justifyContent = "flex-end";
                overlay.style.padding = "12px";
                overlay.style.boxSizing = "border-box";
                overlay.style.cursor = "not-allowed";
                overlay.style.outline = "none";

                const block = function(e) {{
                    e.preventDefault();
                    e.stopPropagation();
                    e.stopImmediatePropagation();
                    return false;
                }};

                ["click", "dblclick", "mousedown", "mouseup", "contextmenu", "wheel",
                "touchstart", "touchmove", "keydown", "keyup", "keypress", "paste", "drop"]
                .forEach(function(evt) {{
                    overlay.addEventListener(evt, block, true);
                }});

                document.body.appendChild(overlay);
            }}

            overlay.innerHTML = {json.dumps(html)};

            if (document.activeElement && typeof document.activeElement.blur === "function") {{
                try {{ document.activeElement.blur(); }} catch (e) {{}}
            }}

            try {{ overlay.focus(); }} catch (e) {{}}
        }})();
        """
        view.page().runJavaScript(js)

    def _clear_whatsapp_sync_overlay(self, view=None):
        if view is None:
            target = self.get_whatsapp_sync_target_tab()
            view = target["view"] if target else self._wa_sync_target_view
        if not view:
            return

        try:
            view.page().runJavaScript("""
            (function() {
                const overlay = document.getElementById("__ptn_sync_overlay");
                if (overlay) overlay.remove();
            })();
            """)
        except Exception:
            pass

    def _persist_whatsapp_sync_batch(self, batch, account_id):
        if not isinstance(batch, list) or not batch:
            return

        account_label = self._format_whatsapp_label(account_id)
        new_entries = []
        contact_updates = []
        saved_messages = 0
        duplicate_messages = 0
        saved_chats = 0

        for chat in batch:
            if not isinstance(chat, dict):
                continue

            chat_label = str(chat.get("chat_label") or "").strip()
            chat_phone = normalize_chat_key(chat.get("chat_phone"))
            conversation_key = normalize_chat_key(
                chat.get("conversation_key") or chat_phone or chat_label
            )
            messages = chat.get("messages") or []
            saved_any = False

            for message in messages:
                if not isinstance(message, dict):
                    continue

                direction = str(message.get("direction") or "").strip().lower()
                if direction not in {"incoming", "outgoing"}:
                    continue

                content = str(message.get("content") or "").strip()
                attachment_label = str(message.get("attachment_label") or "").strip()
                if not content and attachment_label:
                    content = attachment_label
                if not content and not bool(message.get("has_attachment")):
                    continue

                timestamp_value = (
                    str(message.get("timestamp_iso") or "").strip()
                    or str(message.get("timestamp_display") or "").strip()
                    or str(message.get("timestamp_raw") or "").strip()
                    or datetime.datetime.now(datetime.timezone.utc).isoformat()
                )
                author = str(message.get("author") or "").strip()
                has_attachment = bool(message.get("has_attachment"))
                raw_sig = str(message.get("sig") or "").strip()
                derived_sig = build_whatsapp_history_signature(
                    conversation_key=conversation_key or chat_phone or chat_label,
                    direction=direction,
                    timestamp_text=timestamp_value,
                    content=content,
                    has_attachment=has_attachment,
                    author=author
                )

                if raw_sig and raw_sig in self._wa_sync_existing_signatures:
                    duplicate_messages += 1
                    continue
                if derived_sig and derived_sig in self._wa_sync_existing_signatures:
                    duplicate_messages += 1
                    continue

                if raw_sig:
                    self._wa_sync_existing_signatures.add(raw_sig)
                if derived_sig:
                    self._wa_sync_existing_signatures.add(derived_sig)

                _, bad_word_hits = mask_bad_words(content, self.bad_words)
                bad_words = sorted(set(bad_word_hits))

                if direction == "incoming":
                    from_phone = chat_phone or ""
                    from_display = author or chat_label or from_phone or "Customer"
                    payload = {
                        "timestamp": timestamp_value,
                        "from": from_phone or "",
                        "from_display": from_display,
                        "from_phone": from_phone,
                        "chat_label": chat_label,
                        "conversation_key": conversation_key,
                        "content": content,
                        "message_length": int(message.get("message_length") or len(content)),
                        "has_attachment": has_attachment,
                        "send_type": "sync_incoming",
                        "trigger": "history_sync",
                        "status": "received",
                        "bad_word_count": len(bad_word_hits),
                        "bad_words": bad_words,
                        "message_author": author,
                        "sig": raw_sig or derived_sig
                    }
                    contact_updates.append({
                        "send_number": from_phone or chat_label,
                        "timestamp_text": timestamp_value,
                        "direction": "incoming",
                        "message": content,
                        "send_type": "sync_incoming",
                        "account_label": account_label,
                        "status": "received",
                        "display_number": chat_label or from_display or from_phone,
                        "suggested_name": chat_label or from_display,
                        "trigger": "history_sync",
                        "auto_create": True
                    })
                else:
                    to_value = chat_phone or chat_label or "Customer"
                    payload = {
                        "timestamp": timestamp_value,
                        "from": account_label,
                        "to": to_value,
                        "to_phone": chat_phone or "",
                        "chat_label": chat_label,
                        "conversation_key": conversation_key,
                        "content": content,
                        "message_length": int(message.get("message_length") or len(content)),
                        "has_attachment": has_attachment,
                        "send_type": "sync_outgoing",
                        "trigger": "history_sync",
                        "status": "sent",
                        "bad_word_count": len(bad_word_hits),
                        "bad_words": bad_words,
                        "message_author": author,
                        "sig": raw_sig or derived_sig
                    }
                    contact_updates.append({
                        "send_number": chat_phone or chat_label,
                        "timestamp_text": timestamp_value,
                        "direction": "outgoing",
                        "message": content,
                        "send_type": "sync_outgoing",
                        "account_label": account_label,
                        "status": "sent",
                        "display_number": chat_label or to_value,
                        "suggested_name": chat_label or to_value,
                        "trigger": "history_sync",
                        "auto_create": True
                    })

                new_entries.append(payload)
                saved_messages += 1
                saved_any = True

            if saved_any:
                saved_chats += 1

        if new_entries:
            self._wa_sync_log_cache.extend(new_entries)
            write_manual_send_log(self._wa_sync_log_cache)

        if contact_updates:
            update_contact_interactions_batch(contact_updates)

        self._wa_sync_total_saved += saved_messages
        self._wa_sync_total_duplicates += duplicate_messages
        self._wa_sync_total_chats += saved_chats

        if 0 <= self._wa_sync_tab_index < len(self._wa_sync_tabs):
            tab_state = self._wa_sync_tabs[self._wa_sync_tab_index]
            tab_state["saved_messages"] = int(tab_state.get("saved_messages", 0)) + saved_messages
            tab_state["duplicate_messages"] = int(tab_state.get("duplicate_messages", 0)) + duplicate_messages
            tab_state["saved_chats"] = int(tab_state.get("saved_chats", 0)) + saved_chats

    def _finalize_current_whatsapp_history_sync_tab(self, status, error_text=""):
        current_view = self._wa_sync_target_view
        current_label = self._format_whatsapp_label(self._wa_sync_target_account_id)

        if 0 <= self._wa_sync_tab_index < len(self._wa_sync_tabs):
            tab_state = self._wa_sync_tabs[self._wa_sync_tab_index]
            tab_state["status"] = status
            tab_state["error"] = str(error_text or "").strip()

            save_history({
                "timestamp": datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
                "event": "whatsapp_history_sync_tab",
                "tab": tab_state.get("label") or current_label,
                "status": status,
                "saved_messages": int(tab_state.get("saved_messages", 0)),
                "duplicate_messages": int(tab_state.get("duplicate_messages", 0)),
                "saved_chats": int(tab_state.get("saved_chats", 0)),
                "error": tab_state.get("error", "")
            })

        self._wa_sync_poll_timer.stop()
        self._clear_whatsapp_sync_overlay(current_view)

        if current_view:
            try:
                current_view.page().runJavaScript("""
                (function() {
                    window.__waHistorySyncBuffer = [];
                    if (window.__waHistorySyncState && window.__waHistorySyncState.status !== "running") {
                        window.__waHistorySyncState = null;
                    }
                })();
                """)
            except Exception:
                pass

        self._wa_sync_target_view = None
        self._wa_sync_target_account_id = None
        self._wa_sync_started_at = 0.0
        self._wa_sync_current_state = {}

        QTimer.singleShot(220, self._start_next_whatsapp_history_sync_tab)

    def _finish_whatsapp_history_sync(self):
        self._wa_sync_processing = False
        self._wa_sync_poll_timer.stop()

        completed_tabs = sum(1 for tab in self._wa_sync_tabs if tab.get("status") == "done")
        skipped_tabs = sum(1 for tab in self._wa_sync_tabs if tab.get("status") == "skipped")
        error_tabs = sum(1 for tab in self._wa_sync_tabs if tab.get("status") == "error")
        _, repaired_changed = self.repair_whatsapp_history_records(quiet=True)

        save_history({
            "timestamp": datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
            "event": "whatsapp_history_sync_finished",
            "tab_count": len(self._wa_sync_tabs),
            "done_tabs": completed_tabs,
            "skipped_tabs": skipped_tabs,
            "error_tabs": error_tabs,
            "saved_messages": self._wa_sync_total_saved,
            "duplicate_messages": self._wa_sync_total_duplicates,
            "saved_chats": self._wa_sync_total_chats,
            "history_repaired": bool(repaired_changed)
        })

        self.status_bar.showMessage(
            f"WhatsApp history sync finished. Saved {self._wa_sync_total_saved} histories.",
            7000
        )
        self.show_tray_message(
            "WhatsApp Sync",
            f"Saved {self._wa_sync_total_saved} histories across {completed_tabs} tab(s)."
        )

        QMessageBox.information(
            self,
            "WhatsApp History Sync",
            (
                f"Done tabs: {completed_tabs}\n"
                f"Skipped tabs: {skipped_tabs}\n"
                f"Errored tabs: {error_tabs}\n\n"
                f"Chats saved: {self._wa_sync_total_chats}\n"
                f"New histories saved: {self._wa_sync_total_saved}\n"
                f"Duplicate histories skipped: {self._wa_sync_total_duplicates}\n"
                f"History repair applied: {'Yes' if repaired_changed else 'No changes needed'}"
            )
        )

        self._wa_sync_tabs = []
        self._wa_sync_tab_index = -1
        self._wa_sync_target_view = None
        self._wa_sync_target_account_id = None
        self._wa_sync_started_at = 0.0
        self._wa_sync_current_state = {}

    def _start_next_whatsapp_history_sync_tab(self):
        if not self._wa_sync_processing:
            return

        while True:
            self._wa_sync_tab_index += 1
            if self._wa_sync_tab_index >= len(self._wa_sync_tabs):
                self._finish_whatsapp_history_sync()
                return

            tab_state = self._wa_sync_tabs[self._wa_sync_tab_index]
            meta = self.find_tab_meta_by_view(tab_state.get("view"))
            if meta is None:
                tab_state["status"] = "skipped"
                tab_state["error"] = "tab_closed"
                continue

            self._wa_sync_target_view = meta["view"]
            self._wa_sync_target_account_id = meta.get("account_id")
            self._wa_sync_current_state = {}
            self._wa_sync_started_at = time.monotonic()
            tab_state["status"] = "running"
            tab_state["error"] = ""

            try:
                self.tab_widget.setCurrentWidget(meta["view"])
            except Exception:
                pass

            self.status_bar.showMessage(f"Syncing {tab_state.get('label')}...", 4000)
            self._render_whatsapp_sync_overlay(meta["view"])
            self.inject_whatsapp_history_sync(meta["view"])
            if not self._wa_sync_poll_timer.isActive():
                self._wa_sync_poll_timer.start()
            return

    def _poll_whatsapp_history_sync_status(self):
        if not self._wa_sync_processing:
            self._wa_sync_poll_timer.stop()
            return

        target = self.get_whatsapp_sync_target_tab()
        if not target:
            self._finalize_current_whatsapp_history_sync_tab("error", "tab_missing")
            return

        if self._wa_sync_started_at and (time.monotonic() - self._wa_sync_started_at > self._wa_sync_timeout_sec):
            self._finalize_current_whatsapp_history_sync_tab("error", "timeout")
            return

        target["view"].page().runJavaScript(
            """
            (function() {
                const payload = {
                    state: window.__waHistorySyncState || null,
                    batch: window.__waHistorySyncBuffer || []
                };
                window.__waHistorySyncBuffer = [];
                return JSON.stringify(payload);
            })();
            """,
            self._handle_whatsapp_history_sync_status
        )

    def _handle_whatsapp_history_sync_status(self, result):
        if not self._wa_sync_processing:
            return

        payload = {}
        if result:
            try:
                payload = json.loads(result)
            except Exception:
                payload = {}

        batch = payload.get("batch") or []
        if batch:
            self._persist_whatsapp_sync_batch(batch, self._wa_sync_target_account_id)

        state = payload.get("state") or {}
        if isinstance(state, dict):
            self._wa_sync_current_state = state

        state_status = str(self._wa_sync_current_state.get("status") or "").strip().lower()
        current_chat = str(self._wa_sync_current_state.get("currentChat") or "").strip()
        if current_chat:
            self.status_bar.showMessage(
                f"Syncing {self._format_whatsapp_label(self._wa_sync_target_account_id)}: {current_chat}",
                2500
            )

        self._render_whatsapp_sync_overlay()

        if state_status in {"running", ""}:
            return

        if state_status == "done":
            self._finalize_current_whatsapp_history_sync_tab("done", "")
            return

        if state_status == "not_logged_in":
            self._finalize_current_whatsapp_history_sync_tab("skipped", "not_logged_in")
            return

        error_text = str(self._wa_sync_current_state.get("error") or state_status or "error").strip()
        self._finalize_current_whatsapp_history_sync_tab("error", error_text)

    def inject_whatsapp_history_sync(self, view):
        if not isinstance(view, QWebEngineView):
            return

        script = r"""
        (function() {
            if (window.__waHistorySyncState && window.__waHistorySyncState.status === "running") {
                return true;
            }

            window.__waHistorySyncBuffer = [];
            window.__waHistorySyncState = {
                status: "running",
                startedAt: new Date().toISOString(),
                finishedAt: "",
                error: "",
                currentChat: "",
                currentChatKey: "",
                scannedChats: 0,
                totalKnownChats: 0,
                totalMessages: 0,
                heartbeat: Date.now()
            };

            function setState(patch) {
                try {
                    Object.assign(window.__waHistorySyncState, patch || {});
                    window.__waHistorySyncState.heartbeat = Date.now();
                } catch (e) {}
            }

            function sleep(ms) {
                return new Promise(resolve => setTimeout(resolve, ms));
            }

            function normalizeText(value) {
                return String(value || "")
                    .replace(/\u200e/g, "")
                    .replace(/\u00A0/g, " ")
                    .replace(/\r/g, "")
                    .replace(/[ \t]+\n/g, "\n")
                    .replace(/\n[ \t]+/g, "\n")
                    .replace(/[ \t]{2,}/g, " ")
                    .trim();
            }

            function normalizePhone(raw) {
                const digits = String(raw || "").replace(/\D/g, "");
                if (!digits) return "";

                if (digits.startsWith("0") && digits.length >= 8) {
                    return "62" + digits.slice(1);
                }
                if (digits.startsWith("62") && digits.length >= 8) {
                    return digits;
                }
                if (digits.length >= 8) {
                    return digits;
                }
                return "";
            }

            function extractPhone(raw) {
                const text = String(raw || "");
                const jidMatch = text.match(/(\d{8,20})@(?:s\.whatsapp\.net|c\.us|lid)/i);
                if (jidMatch) return normalizePhone(jidMatch[1]);

                const phoneish = text.match(/(?:\+|00)?\d[\d\s\-()]{7,20}\d/);
                if (phoneish) return normalizePhone(phoneish[0]);

                return "";
            }

            function normalizeMeridiem(text) {
                return String(text || "").replace(/\b(a|p)\.?m\.?\b/gi, function(_, letter) {
                    return String(letter || "").toUpperCase() + "M";
                });
            }

            function parseDateText(text) {
                const raw = normalizeText(text);
                let match = raw.match(/(\d{4})-(\d{1,2})-(\d{1,2})/);
                if (match) {
                    return {
                        year: parseInt(match[1], 10),
                        month: parseInt(match[2], 10),
                        day: parseInt(match[3], 10)
                    };
                }

                match = raw.match(/(\d{1,2})[\/.\-](\d{1,2})[\/.\-](\d{2,4})/);
                if (!match) return null;

                let a = parseInt(match[1], 10);
                let b = parseInt(match[2], 10);
                let year = parseInt(match[3], 10);
                if (year < 100) year += 2000;

                let day = a;
                let month = b;

                if (a <= 12 && b > 12) {
                    month = a;
                    day = b;
                } else if (a > 12 && b <= 12) {
                    day = a;
                    month = b;
                }

                return { year: year, month: month, day: day };
            }

            function parseTimeText(text) {
                const raw = normalizeMeridiem(text);
                const match = raw.match(/(\d{1,2})[:.](\d{2})(?::(\d{2}))?\s*(AM|PM)?/i);
                if (!match) return null;

                let hour = parseInt(match[1], 10);
                const minute = parseInt(match[2], 10);
                const second = parseInt(match[3] || "0", 10);
                const meridiem = String(match[4] || "").toUpperCase();

                if (meridiem === "PM" && hour < 12) hour += 12;
                if (meridiem === "AM" && hour === 12) hour = 0;

                return { hour: hour, minute: minute, second: second };
            }

            function parsePrePlainMeta(prePlainText) {
                const raw = String(prePlainText || "").trim();
                const bracket = raw.match(/^\[([^\]]+)\]\s*(.*)$/);
                const header = bracket ? normalizeText(bracket[1]) : "";
                const author = normalizeText(bracket ? bracket[2] : "").replace(/:\s*$/, "");

                let dateInfo = null;
                let timeInfo = null;
                const parts = header.split(",").map(normalizeText).filter(Boolean);

                for (const part of parts) {
                    if (!dateInfo) dateInfo = parseDateText(part) || dateInfo;
                    if (!timeInfo) timeInfo = parseTimeText(part) || timeInfo;
                }

                if (!dateInfo) dateInfo = parseDateText(header);
                if (!timeInfo) timeInfo = parseTimeText(header);

                let timestampIso = "";
                let timestampDisplay = "";

                if (dateInfo && timeInfo) {
                    const localDt = new Date(
                        dateInfo.year,
                        Math.max(0, dateInfo.month - 1),
                        dateInfo.day,
                        timeInfo.hour,
                        timeInfo.minute,
                        timeInfo.second || 0
                    );
                    if (!isNaN(localDt.getTime())) {
                        const pad = function(n) { return String(n).padStart(2, "0"); };
                        timestampIso = localDt.toISOString();
                        timestampDisplay = [
                            dateInfo.year,
                            pad(dateInfo.month),
                            pad(dateInfo.day)
                        ].join("-") + " " + [
                            pad(timeInfo.hour),
                            pad(timeInfo.minute),
                            pad(timeInfo.second || 0)
                        ].join(":");
                    }
                }

                return {
                    raw: raw,
                    header: header,
                    author: author,
                    timestamp_iso: timestampIso,
                    timestamp_display: timestampDisplay
                };
            }

            function isQrOnlyMode() {
                return !!document.querySelector(
                    'canvas[aria-label="Scan me!"], canvas[aria-label*="Scan"], div[data-ref] canvas'
                );
            }

            function getChatListRoot() {
                const selectors = [
                    '#pane-side div[aria-label="Chat list"]',
                    'div[aria-label="Chat list"][role="grid"]',
                    '#pane-side'
                ];

                for (const sel of selectors) {
                    const el = document.querySelector(sel);
                    if (el) return el;
                }
                return null;
            }

            function isLoggedIn() {
                if (isQrOnlyMode()) return false;
                return !!getChatListRoot();
            }

            function getScrollableAncestor(node) {
                let current = node;
                while (current && current !== document.body) {
                    try {
                        if (current.scrollHeight > current.clientHeight + 20) {
                            return current;
                        }
                    } catch (e) {}
                    current = current.parentElement;
                }
                return null;
            }

            function getChatListScroller() {
                const root = getChatListRoot();
                return getScrollableAncestor(root) || root;
            }

            function getChatRows() {
                const root = getChatListRoot();
                if (!root) return [];
                return Array.from(root.querySelectorAll('div[role="row"]')).filter(Boolean);
            }

            const BAD_HEADER_TITLES = new Set([
                "",
                "profile",
                "profile details",
                "contact info",
                "group info",
                "search",
                "menu",
                "more",
                "whatsapp",
                "click here for contact info",
                "click for contact info"
            ]);

            function isLikelySecondaryHeaderText(text) {
                const lower = normalizeText(text).toLowerCase();
                if (!lower) return true;
                if (BAD_HEADER_TITLES.has(lower)) return true;
                if (lower === "you") return true;
                if (lower === "online") return true;
                if (lower.includes("typing")) return true;
                if (lower.includes("recording")) return true;
                if (lower.includes("last seen")) return true;
                if (/^\d{1,2}:\d{2}/.test(lower)) return true;
                if (/^(today|yesterday|monday|tuesday|wednesday|thursday|friday|saturday|sunday)$/.test(lower)) {
                    return true;
                }
                return false;
            }

            function isLikelySecondaryRowText(text) {
                const lower = normalizeText(text).toLowerCase();
                if (!lower) return true;
                if (BAD_HEADER_TITLES.has(lower)) return true;
                if (lower === "you") return true;
                if (/^(today|yesterday|monday|tuesday|wednesday|thursday|friday|saturday|sunday)$/.test(lower)) {
                    return true;
                }
                if (/^\d{1,2}:\d{2}/.test(lower)) return true;
                if (/^\d{1,2}\.\d{2}/.test(lower)) return true;
                if (lower.includes("unread")) return true;
                if (/^\d{1,3}$/.test(lower)) return true;
                return false;
            }

            function extractRowTitle(row) {
                if (!row) return "";

                const seen = new Set();
                const nodes = Array.from(row.querySelectorAll('span[title], div[title]'));

                for (const el of nodes) {
                    const text = normalizeText(el.getAttribute("title") || el.textContent || "");
                    const lower = text.toLowerCase();
                    if (!text || isLikelySecondaryRowText(text)) continue;
                    if (seen.has(lower)) continue;
                    seen.add(lower);
                    return text;
                }

                const lines = String(row.innerText || row.textContent || "")
                    .split(/\n+/)
                    .map(normalizeText)
                    .filter(Boolean);

                for (const line of lines) {
                    if (!isLikelySecondaryRowText(line)) {
                        return line;
                    }
                }
                return "";
            }

            function extractRowTimeText(row) {
                if (!row) return "";
                const nodes = Array.from(row.querySelectorAll("span, div"));
                for (const node of nodes) {
                    const text = normalizeText(node.textContent || "");
                    if (!text) continue;
                    const lower = text.toLowerCase();
                    if (
                        /^(today|yesterday|monday|tuesday|wednesday|thursday|friday|saturday|sunday)$/.test(lower) ||
                        /^\d{1,2}:\d{2}/.test(lower) ||
                        /^\d{1,2}\.\d{2}/.test(lower)
                    ) {
                        return text;
                    }
                }
                return "";
            }

            function buildRowKey(row, title) {
                const label = normalizeText(title || extractRowTitle(row));
                const phone = normalizePhone(label);
                if (phone) return phone;

                const rowText = normalizeText(row ? (row.innerText || row.textContent || "") : "");
                const timeText = extractRowTimeText(row);
                return [label.toLowerCase(), timeText.toLowerCase(), rowText.toLowerCase()]
                    .filter(Boolean)
                    .join("||");
            }

            function getSelectedRowTitle() {
                const selected = document.querySelector(
                    '#pane-side [aria-selected="true"], #pane-side div[role="row"] [aria-selected="true"]'
                );
                const row = selected ? (selected.closest('div[role="row"]') || selected) : null;
                return extractRowTitle(row);
            }

            function getHeaderChatTitle() {
                const selectors = [
                    'main header [data-testid="conversation-info-header-chat-title"]',
                    'header [data-testid="conversation-info-header-chat-title"]',
                    'main header h1',
                    'header h1',
                    'main header span[title]',
                    'main header div[title]',
                    'header span[title]',
                    'header div[title]',
                    'main header span[dir="auto"]',
                    'main header div[dir="auto"]',
                    'header span[dir="auto"]',
                    'header div[dir="auto"]'
                ];

                for (const sel of selectors) {
                    const nodes = Array.from(document.querySelectorAll(sel));
                    for (const el of nodes) {
                        const text = normalizeText(el.getAttribute("title") || el.textContent || "");
                        if (!text || isLikelySecondaryHeaderText(text)) continue;

                        const rect = el.getBoundingClientRect();
                        if (rect.width < 20 || rect.height < 10) continue;
                        return text;
                    }
                }

                const header = document.querySelector("main header") || document.querySelector("header");
                if (header) {
                    const lines = String(header.innerText || header.textContent || "")
                        .split(/\n+/)
                        .map(normalizeText)
                        .filter(Boolean);

                    for (const line of lines) {
                        if (!isLikelySecondaryHeaderText(line)) {
                            return line;
                        }
                    }
                }

                return getSelectedRowTitle();
            }

            function getMessagePrePlainText(msgEl) {
                if (!msgEl) return "";
                try {
                    const direct = msgEl.getAttribute("data-pre-plain-text") || "";
                    if (direct) return direct;
                } catch (e) {}

                try {
                    const prePlainEl = msgEl.querySelector("[data-pre-plain-text]");
                    if (prePlainEl) {
                        return prePlainEl.getAttribute("data-pre-plain-text") || "";
                    }
                } catch (e) {}

                return "";
            }

            function extractPhoneFromMessageElement(msgEl) {
                if (!msgEl) return "";

                const candidates = [];
                try {
                    candidates.push(msgEl.getAttribute("data-id") || "");
                    candidates.push(msgEl.getAttribute("data-pre-plain-text") || "");
                } catch (e) {}

                const prePlain = getMessagePrePlainText(msgEl);
                if (prePlain) {
                    candidates.push(prePlain);
                }

                try {
                    const nodes = msgEl.querySelectorAll("[data-id], [data-pre-plain-text], a[href]");
                    for (const el of nodes) {
                        candidates.push(el.getAttribute("data-id") || "");
                        candidates.push(el.getAttribute("data-pre-plain-text") || "");
                        candidates.push(el.getAttribute("href") || "");
                    }
                } catch (e) {}

                for (const candidate of candidates) {
                    const phone = extractPhone(candidate);
                    if (phone) return phone;
                }
                return "";
            }

            function looksLikePhoneText(text) {
                const digits = String(text || "").replace(/\D/g, "");
                return digits.length >= 8 && digits.length <= 20;
            }

            function getPhoneFromPageContext() {
                try {
                    const p = new URLSearchParams(location.search).get("phone");
                    const phone = extractPhone(p);
                    if (phone) return phone;
                } catch (e) {}

                const nodes = Array.from(document.querySelectorAll(".message-in, .message-out")).slice(-40).reverse();
                for (const msgEl of nodes) {
                    const phone = extractPhoneFromMessageElement(msgEl);
                    if (phone) return phone;
                }

                const headerTitle = getHeaderChatTitle();
                if (looksLikePhoneText(headerTitle)) {
                    return extractPhone(headerTitle);
                }
                return "";
            }

            function getCurrentChatIdentity(msgEl) {
                let title = getHeaderChatTitle();
                if (BAD_HEADER_TITLES.has(String(title || "").toLowerCase())) {
                    title = "";
                }

                let phone = extractPhoneFromMessageElement(msgEl);
                if (!phone && title && window.__waContactInfoCache && window.__waContactInfoCache[title.toLowerCase()]) {
                    phone = window.__waContactInfoCache[title.toLowerCase()];
                }
                if (!phone) {
                    phone = getPhoneFromPageContext();
                }

                const label = title || phone || "Customer";
                const key = phone || (label ? label.toLowerCase() : "unknown");
                return { phone: phone || "", label: label || "Customer", key: key || "unknown" };
            }

            function mergeIdentity(primary, fallback) {
                const base = primary || {};
                const alt = fallback || {};
                const phone = base.phone || alt.phone || "";
                const label = base.label || alt.label || "Customer";
                const key = base.key || alt.key || phone || (label ? label.toLowerCase() : "unknown");
                return { phone: phone, label: label, key: key };
            }

            function clickHeader() {
                const titleEl = document.querySelector('main header [data-testid="conversation-info-header-chat-title"]') ||
                    document.querySelector('header [data-testid="conversation-info-header-chat-title"]') ||
                    document.querySelector("main header") ||
                    document.querySelector("header");
                if (!titleEl) return false;

                let node = titleEl;
                while (node && node !== document.body) {
                    const role = (node.getAttribute && node.getAttribute("role")) || "";
                    if (role === "button" || node.tagName === "BUTTON") {
                        try {
                            node.click();
                            return true;
                        } catch (e) {}
                    }
                    node = node.parentElement;
                }

                try {
                    titleEl.click();
                    return true;
                } catch (e) {
                    return false;
                }
            }

            function getInfoPanel() {
                const selectors = [
                    '[data-testid="chat-info-drawer"]',
                    '[data-testid="drawer-right"]',
                    'div[role="complementary"]',
                    'aside'
                ];

                for (const sel of selectors) {
                    const el = document.querySelector(sel);
                    if (el) return el;
                }
                return null;
            }

            function scanPhoneFromPanel() {
                const panel = getInfoPanel();
                if (!panel) return "";

                const text = normalizeText(panel.innerText || panel.textContent || "");
                if (!text) return "";

                const jidMatch = text.match(/(\d{8,20})@(?:s\.whatsapp\.net|c\.us|lid)/i);
                if (jidMatch) return normalizePhone(jidMatch[1]);

                const phoneish = text.match(/(?:\+|00)?\d[\d\s\-()]{7,20}\d/);
                if (phoneish) return normalizePhone(phoneish[0]);
                return "";
            }

            function closeInfoPanel() {
                const buttons = Array.from(document.querySelectorAll(
                    'button, div[role="button"], span[role="button"]'
                ));

                for (const btn of buttons) {
                    const text = normalizeText(
                        btn.innerText || btn.textContent || btn.getAttribute("aria-label") || ""
                    ).toLowerCase();

                    if (text === "close" || text === "tutup") {
                        try {
                            btn.click();
                            return true;
                        } catch (e) {}
                    }
                }
                return false;
            }

            async function resolveCurrentChatIdentity(rowIdentity) {
                let identity = mergeIdentity(getCurrentChatIdentity(null), rowIdentity);
                const cacheKey = String(identity.label || "").toLowerCase();

                if (!identity.phone && cacheKey && window.__waContactInfoCache && window.__waContactInfoCache[cacheKey]) {
                    identity.phone = window.__waContactInfoCache[cacheKey];
                    identity.key = identity.phone || identity.key;
                }

                if (!identity.phone && identity.label && !looksLikePhoneText(identity.label)) {
                    try {
                        if (clickHeader()) {
                            await sleep(900);
                            let phone = "";
                            for (let i = 0; i < 6 && !phone; i++) {
                                phone = scanPhoneFromPanel();
                                if (!phone) await sleep(250);
                            }
                            if (phone) {
                                identity.phone = phone;
                                identity.key = phone;
                                if (cacheKey) {
                                    window.__waContactInfoCache = window.__waContactInfoCache || {};
                                    window.__waContactInfoCache[cacheKey] = phone;
                                }
                            }
                            await sleep(120);
                            closeInfoPanel();
                            await sleep(250);
                        }
                    } catch (e) {}
                }

                if (!identity.key) {
                    identity.key = identity.phone || (identity.label ? identity.label.toLowerCase() : "unknown");
                }
                return identity;
            }

            function detectAttachmentLabel(msgEl) {
                try {
                    if (msgEl.querySelector('img[src^="blob:"], img[src^="data:"]')) return "[image]";
                    if (msgEl.querySelector("video")) return "[video]";
                    if (msgEl.querySelector("audio")) return "[audio]";
                    if (msgEl.querySelector("canvas")) return "[sticker]";
                    if (msgEl.querySelector('a[download], a[href*="blob:"]')) return "[document]";
                } catch (e) {}
                return "";
            }

            function getMessageText(msgEl) {
                const selectors = [
                    '.selectable-text.copyable-text',
                    'span.selectable-text',
                    '.copyable-text'
                ];

                for (const sel of selectors) {
                    const el = msgEl.querySelector(sel);
                    if (!el) continue;
                    const text = normalizeText(el.innerText || el.textContent || "");
                    if (text) return text;
                }
                return normalizeText(msgEl.innerText || msgEl.textContent || "");
            }

            function getMessageDomSignature(msgEl, chatKey, content) {
                const dataId = msgEl.getAttribute("data-id") || "";
                const prePlain = getMessagePrePlainText(msgEl);
                return [chatKey, dataId, prePlain, content].join("||");
            }

            function getMessageScrollContainer() {
                const selectors = [
                    '#main [data-testid="conversation-panel-body"]',
                    '#main [data-testid="conversation-panel-messages"]',
                    '#main div[role="application"]',
                    'main [data-testid="conversation-panel-body"]',
                    'main [data-testid="conversation-panel-messages"]'
                ];

                for (const sel of selectors) {
                    const el = document.querySelector(sel);
                    if (!el) continue;
                    const scroller = getScrollableAncestor(el) || el;
                    if (scroller && scroller.scrollHeight > scroller.clientHeight + 20) {
                        return scroller;
                    }
                }

                const msg = document.querySelector(".message-in, .message-out");
                return getScrollableAncestor(msg);
            }

            function getFirstMessageMarker() {
                const first = document.querySelector(".message-in, .message-out");
                if (!first) return "";
                return [
                    first.getAttribute("data-id") || "",
                    getMessagePrePlainText(first)
                ].join("||");
            }

            async function loadAllMessagesInCurrentChat() {
                const scroller = getMessageScrollContainer();
                if (!scroller) return;

                let stableCount = 0;
                let lastMarker = "";
                let lastHeight = 0;

                for (let i = 0; i < 180; i++) {
                    const beforeTop = scroller.scrollTop;
                    const beforeHeight = scroller.scrollHeight;
                    const beforeMarker = getFirstMessageMarker();

                    try {
                        scroller.scrollTop = 0;
                    } catch (e) {}

                    await sleep(420);

                    const afterHeight = scroller.scrollHeight;
                    const afterMarker = getFirstMessageMarker();
                    const changed = (
                        beforeTop > 0 ||
                        beforeHeight !== afterHeight ||
                        beforeMarker !== afterMarker
                    );

                    if (!changed && afterMarker === lastMarker && afterHeight === lastHeight) {
                        stableCount += 1;
                    } else if (!changed) {
                        stableCount += 1;
                    } else {
                        stableCount = 0;
                    }

                    lastMarker = afterMarker;
                    lastHeight = afterHeight;

                    if (stableCount >= 3) {
                        break;
                    }
                }
            }

            function collectCurrentChatMessages(identity) {
                const nodes = Array.from(document.querySelectorAll(".message-in, .message-out"));
                const messages = [];
                const seen = new Set();

                for (const msgEl of nodes) {
                    if (!msgEl || !msgEl.classList) continue;

                    let direction = "";
                    if (msgEl.classList.contains("message-in")) direction = "incoming";
                    if (msgEl.classList.contains("message-out")) direction = "outgoing";
                    if (!direction) continue;

                    const attachmentLabel = detectAttachmentLabel(msgEl);
                    let content = getMessageText(msgEl);
                    if (!content && attachmentLabel) {
                        content = attachmentLabel;
                    }
                    content = normalizeText(content);
                    if (!content && !attachmentLabel) continue;

                    const prePlain = getMessagePrePlainText(msgEl);
                    const meta = parsePrePlainMeta(prePlain);
                    const domSig = getMessageDomSignature(msgEl, identity.key || identity.label, content);
                    if (seen.has(domSig)) continue;
                    seen.add(domSig);

                    messages.push({
                        direction: direction,
                        timestamp_iso: meta.timestamp_iso || "",
                        timestamp_display: meta.timestamp_display || "",
                        timestamp_raw: meta.raw || "",
                        content: content,
                        message_length: content.length,
                        has_attachment: !!attachmentLabel,
                        attachment_label: attachmentLabel || "",
                        author: meta.author || (direction === "outgoing" ? "You" : identity.label || ""),
                        sig: domSig
                    });
                }

                return messages;
            }

            function getRowClickable(row) {
                if (!row) return null;
                const selectors = [
                    'div[role="gridcell"][tabindex="0"]',
                    'div[role="gridcell"][tabindex="-1"]',
                    'div[role="gridcell"]',
                    '[tabindex="0"]',
                    'button'
                ];

                for (const sel of selectors) {
                    const el = row.querySelector(sel);
                    if (el) return el;
                }
                return row;
            }

            function clickRow(row) {
                const target = getRowClickable(row);
                if (!target) return false;

                try { target.focus && target.focus(); } catch (e) {}
                try { target.dispatchEvent(new MouseEvent("mousedown", { bubbles: true })); } catch (e) {}
                try {
                    target.click();
                    return true;
                } catch (e) {}
                try { target.dispatchEvent(new MouseEvent("mouseup", { bubbles: true })); } catch (e) {}
                return false;
            }

            async function waitForChatReady(candidate, timeoutMs) {
                const startedAt = Date.now();
                const timeout = timeoutMs || 7000;

                while ((Date.now() - startedAt) < timeout) {
                    const identity = getCurrentChatIdentity(null);
                    const headerTitle = normalizeText(identity.label || getHeaderChatTitle() || "");
                    const headerKey = normalizeText(identity.key || "");
                    const hasMessages = !!document.querySelector(".message-in, .message-out");

                    if (hasMessages) {
                        if (!candidate) return true;

                        if (candidate.key && headerKey && candidate.key === headerKey) {
                            return true;
                        }

                        if (candidate.title && headerTitle) {
                            const expected = candidate.title.toLowerCase();
                            const actual = headerTitle.toLowerCase();
                            if (expected === actual || actual.includes(expected) || expected.includes(actual)) {
                                return true;
                            }
                        }
                    }

                    await sleep(250);
                }
                return !!document.querySelector(".message-in, .message-out");
            }

            async function syncCurrentChat(row, rowTitle, visitedKeys) {
                const rowIdentity = {
                    phone: normalizePhone(rowTitle),
                    label: rowTitle || "Customer",
                    key: buildRowKey(row, rowTitle) || normalizePhone(rowTitle) || (rowTitle ? rowTitle.toLowerCase() : "unknown")
                };

                setState({
                    currentChat: rowIdentity.label,
                    currentChatKey: rowIdentity.key
                });

                if (!clickRow(row)) {
                    visitedKeys.add(rowIdentity.key);
                    return;
                }

                await sleep(800);
                await waitForChatReady({ title: rowTitle, key: rowIdentity.key }, 8000);

                const identity = await resolveCurrentChatIdentity(rowIdentity);
                const finalKey = identity.phone || identity.key || rowIdentity.key;
                visitedKeys.add(rowIdentity.key);
                visitedKeys.add(finalKey);

                setState({
                    currentChat: identity.label || rowIdentity.label,
                    currentChatKey: finalKey,
                    totalKnownChats: Math.max(
                        parseInt(window.__waHistorySyncState.totalKnownChats || 0, 10) || 0,
                        visitedKeys.size
                    )
                });

                await loadAllMessagesInCurrentChat();
                const messages = collectCurrentChatMessages(identity);

                window.__waHistorySyncBuffer.push({
                    conversation_key: finalKey,
                    chat_label: identity.label || rowIdentity.label,
                    chat_phone: identity.phone || "",
                    message_count: messages.length,
                    messages: messages
                });

                setState({
                    scannedChats: (parseInt(window.__waHistorySyncState.scannedChats || 0, 10) || 0) + 1,
                    totalMessages: (parseInt(window.__waHistorySyncState.totalMessages || 0, 10) || 0) + messages.length
                });
            }

            async function syncAllChats() {
                const scroller = getChatListScroller();
                if (!scroller) {
                    throw new Error("chat_list_not_found");
                }

                try {
                    scroller.scrollTop = 0;
                } catch (e) {}
                await sleep(450);

                const visitedKeys = new Set();
                let stableEndCount = 0;

                for (let pass = 0; pass < 420; pass++) {
                    setState({
                        totalKnownChats: Math.max(
                            parseInt(window.__waHistorySyncState.totalKnownChats || 0, 10) || 0,
                            visitedKeys.size
                        )
                    });

                    const rows = getChatRows();
                    let foundNewRow = false;

                    for (const row of rows) {
                        const title = extractRowTitle(row);
                        if (!title) continue;

                        const rowKey = buildRowKey(row, title);
                        if (!rowKey) continue;
                        if (visitedKeys.has(rowKey)) continue;

                        foundNewRow = true;
                        await syncCurrentChat(row, title, visitedKeys);
                        await sleep(200);
                    }

                    const maxTop = Math.max(0, scroller.scrollHeight - scroller.clientHeight);
                    const beforeTop = scroller.scrollTop;
                    const nextTop = Math.min(
                        maxTop,
                        beforeTop + Math.max(260, Math.round(scroller.clientHeight * 0.85))
                    );

                    if (nextTop === beforeTop) {
                        stableEndCount += 1;
                    } else {
                        stableEndCount = 0;
                        try {
                            scroller.scrollTop = nextTop;
                        } catch (e) {}
                        await sleep(420);
                    }

                    if (!foundNewRow && stableEndCount >= 3) {
                        break;
                    }
                }
            }

            async function main() {
                try {
                    if (!isLoggedIn()) {
                        setState({
                            status: "not_logged_in",
                            error: "not_logged_in",
                            finishedAt: new Date().toISOString()
                        });
                        return;
                    }

                    await sleep(1200);
                    await syncAllChats();
                    setState({
                        status: "done",
                        finishedAt: new Date().toISOString(),
                        currentChat: ""
                    });
                } catch (e) {
                    setState({
                        status: "error",
                        error: String((e && e.message) || e || "unknown_error"),
                        finishedAt: new Date().toISOString()
                    });
                }
            }

            main();
            return true;
        })();
        """

        view.page().runJavaScript(script)
    
    def configure_profile(self, profile, storage_key):
        os.makedirs(PROFILE_BASE_DIR, exist_ok=True)

        profile_dir = os.path.join(PROFILE_BASE_DIR, storage_key)
        storage_dir = os.path.join(profile_dir, "storage")
        cache_dir = os.path.join(profile_dir, "cache")

        os.makedirs(storage_dir, exist_ok=True)
        os.makedirs(cache_dir, exist_ok=True)

        profile.setPersistentStoragePath(storage_dir)
        profile.setCachePath(cache_dir)
        profile.setPersistentCookiesPolicy(
            QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies
        )
        profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.DiskHttpCache)

        # Explicit cache cap helps keep older PCs from ballooning in memory/disk pressure.
        profile.setHttpCacheMaximumSize(256 * 1024 * 1024)

        # Let the profile carry Accept-Language too, not only the interceptor.
        try:
            profile.setHttpAcceptLanguage(FORCED_LANGUAGE)
        except Exception:
            pass

        profile.setHttpUserAgent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

        # Shared settings for all pages in this profile.
        settings = profile.settings()

        # Available in newer Qt 6; speeds back/forward navigation when supported.
        if hasattr(QWebEngineSettings.WebAttribute, "BackForwardCacheEnabled"):
            settings.setAttribute(
                QWebEngineSettings.WebAttribute.BackForwardCacheEnabled,
                True
            )

        if ENABLE_SPOOF and ENABLE_GEO_JS_SPOOF:
            self.install_geolocation_script(profile)

        self.install_stealth_script(profile)
        self.install_disable_passkey_script(profile)
        self.install_capture_and_network_script(profile)

        if str(storage_key).startswith("whatsapp_"):
            self.install_whatsapp_bad_word_guard(profile)
            self.install_whatsapp_manual_send_logger(profile)
            self.install_whatsapp_incoming_reply_logger(profile)
            self.install_whatsapp_download_banner_hider(profile)
            self.install_whatsapp_cashier_mode_guard(profile)
            self.install_whatsapp_qr_only_mode(profile)
            self.install_whatsapp_contact_info_scraper(profile)

        interceptor = HeaderInterceptor(
            self.country,
            self.fake_ip,
            enable_spoof=ENABLE_SPOOF
        )
        profile.setUrlRequestInterceptor(interceptor)
        self.profile_interceptors.append(interceptor)

        profile.downloadRequested.connect(self.handle_download)
        return profile

    def create_shared_profile(self):
        profile = QWebEngineProfile("LockedBrowserSharedProfile", self)
        return self.configure_profile(profile, "shared")

    def create_performance_dock(self):
        self.performance_dock = PerformanceDock(self)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.performance_dock)
        self.performance_dock.resize(680, 900)
        self.performance_dock.show()

    def toggle_performance_dock(self):
        if not hasattr(self, "performance_dock"):
            return

        self.performance_dock.setVisible(not self.performance_dock.isVisible())

    def install_whatsapp_contact_info_scraper(self, profile=None):
        profile = profile or self.profile

        script_source = r"""
        (function() {
            if (window.__waContactInfoScraperInstalled) return;
            window.__waContactInfoScraperInstalled = true;

            if (location.hostname !== "web.whatsapp.com") return;

            window.__waContactInfoCache = window.__waContactInfoCache || {};
            let running = false;
            let lastAttemptKey = "";
            let lastAttemptAt = 0;

            function normalizeText(value) {
                return String(value || "")
                    .replace(/\u200e/g, "")
                    .replace(/\u00A0/g, " ")
                    .replace(/\s+/g, " ")
                    .trim();
            }

            function normalizePhone(raw) {
                const digits = String(raw || "").replace(/\D/g, "");
                if (!digits) return "";

                if (digits.startsWith("0") && digits.length >= 8) {
                    return "62" + digits.slice(1);
                }
                if (digits.startsWith("62") && digits.length >= 8) {
                    return digits;
                }
                if (digits.length >= 8) {
                    return digits;
                }
                return "";
            }

            function isLikelySecondaryHeaderText(text) {
                const lower = normalizeText(text).toLowerCase();
                if (!lower) return true;
                if (lower === "profile") return true;
                if (lower === "profile details") return true;
                if (lower === "contact info") return true;
                if (lower === "group info") return true;
                if (lower === "click here for contact info") return true;
                if (lower === "click for contact info") return true;
                if (lower === "online") return true;
                if (lower.includes("typing")) return true;
                if (lower.includes("recording")) return true;
                if (lower.includes("last seen")) return true;
                if (/^\d{1,2}:\d{2}/.test(lower)) return true;
                return false;
            }

            function getSelectedRowTitle() {
                const selected = document.querySelector(
                    '#pane-side [aria-selected="true"], #pane-side div[role="row"] [aria-selected="true"]'
                );
                const row = selected ? (selected.closest('div[role="row"]') || selected) : null;
                if (!row) return "";

                const nodes = Array.from(row.querySelectorAll('span[title], div[title]'));
                for (const el of nodes) {
                    const text = normalizeText(el.getAttribute("title") || el.textContent || "");
                    if (!text || isLikelySecondaryHeaderText(text)) continue;
                    return text;
                }

                const lines = String(row.innerText || row.textContent || "")
                    .split(/\n+/)
                    .map(normalizeText)
                    .filter(Boolean);

                for (const line of lines) {
                    if (!isLikelySecondaryHeaderText(line)) {
                        return line;
                    }
                }

                return "";
            }

            function getHeaderTitle() {
                const selectors = [
                    'main header [data-testid="conversation-info-header-chat-title"]',
                    'header [data-testid="conversation-info-header-chat-title"]',
                    'main header h1',
                    'header h1',
                    'main header span[title]',
                    'main header div[title]',
                    'header span[title]',
                    'header div[title]',
                    'main header span[dir="auto"]',
                    'main header div[dir="auto"]',
                    'header span[dir="auto"]',
                    'header div[dir="auto"]'
                ];

                for (const sel of selectors) {
                    const nodes = Array.from(document.querySelectorAll(sel));
                    for (const el of nodes) {
                        const text = normalizeText(el.getAttribute("title") || el.textContent || "");
                        if (!text || isLikelySecondaryHeaderText(text)) continue;

                        const rect = el.getBoundingClientRect();
                        if (rect.width < 20 || rect.height < 10) continue;
                        return text;
                    }
                }

                const header = document.querySelector("main header") || document.querySelector("header");
                if (header) {
                    const lines = String(header.innerText || header.textContent || "")
                        .split(/\n+/)
                        .map(normalizeText)
                        .filter(Boolean);

                    for (const line of lines) {
                        if (!isLikelySecondaryHeaderText(line)) {
                            return line;
                        }
                    }
                }

                return getSelectedRowTitle();
            }

            function clickHeader() {
                const titleEl = document.querySelector('main header [data-testid="conversation-info-header-chat-title"]') ||
                    document.querySelector('header [data-testid="conversation-info-header-chat-title"]') ||
                    document.querySelector("main header") ||
                    document.querySelector("header");
                if (!titleEl) return false;

                let node = titleEl;
                while (node && node !== document.body) {
                    const role = (node.getAttribute && node.getAttribute("role")) || "";
                    if (role === "button" || node.tagName === "BUTTON") {
                        try {
                            node.click();
                            return true;
                        } catch (e) {}
                    }
                    node = node.parentElement;
                }

                try {
                    titleEl.click();
                    return true;
                } catch (e) {
                    return false;
                }
            }

            function getInfoPanel() {
                const selectors = [
                    '[data-testid="chat-info-drawer"]',
                    '[data-testid="drawer-right"]',
                    'div[role="complementary"]',
                    'aside'
                ];

                for (const sel of selectors) {
                    const el = document.querySelector(sel);
                    if (el) return el;
                }
                return null;
            }

            function scanPhoneFromPanel() {
                const panel = getInfoPanel();
                if (!panel) return "";

                const text = normalizeText(panel.innerText || panel.textContent || "");
                if (!text) return "";

                const jidMatch = text.match(/(\d{8,20})@(?:s\.whatsapp\.net|c\.us|lid)/i);
                if (jidMatch) return normalizePhone(jidMatch[1]);

                const phoneish = text.match(/(?:\+|00)?\d[\d\s\-()]{7,20}\d/);
                if (phoneish) return normalizePhone(phoneish[0]);

                return "";
            }

            function closeInfoPanel() {
                const buttons = Array.from(document.querySelectorAll(
                    'button, div[role="button"], span[role="button"]'
                ));

                for (const btn of buttons) {
                    const text = normalizeText(
                        btn.innerText || btn.textContent || btn.getAttribute("aria-label") || ""
                    ).toLowerCase();

                    if (text === "close" || text === "tutup") {
                        try {
                            btn.click();
                            return true;
                        } catch (e) {}
                    }
                }
                return false;
            }

            async function inspectCurrentChat() {
                if (running) return;
                if (window.__waAutoSendState && window.__waAutoSendState.status === "running") return;
                if (window.__waHistorySyncState && window.__waHistorySyncState.status === "running") return;
                if (window.__waIncomingUnreadScanner && window.__waIncomingUnreadScanner.running) return;
                if (window.__waIncomingUnreadScanner && window.__waIncomingUnreadScanner.pending) return;

                const title = getHeaderTitle();
                const key = title.toLowerCase();

                if (!key) return;
                if (window.__waContactInfoCache[key]) return;

                const directPhone = normalizePhone(title);
                if (directPhone) {
                    window.__waContactInfoCache[key] = directPhone;
                    return;
                }

                if (lastAttemptKey === key && (Date.now() - lastAttemptAt) < 15000) {
                    return;
                }

                running = true;
                lastAttemptKey = key;
                lastAttemptAt = Date.now();

                try {
                    if (!clickHeader()) return;

                    await new Promise(r => setTimeout(r, 900));

                    const phone = scanPhoneFromPanel();
                    if (phone) {
                        window.__waContactInfoCache[key] = phone;
                    }

                    await new Promise(r => setTimeout(r, 150));
                    closeInfoPanel();
                } finally {
                    running = false;
                }
            }

            function scheduleInspect() {
                setTimeout(inspectCurrentChat, 700);
            }

            function start() {
                scheduleInspect();

                const obs = new MutationObserver(() => {
                    scheduleInspect();
                });

                obs.observe(document.documentElement || document.body, {
                    childList: true,
                    subtree: true
                });

                setInterval(inspectCurrentChat, 2500);
            }

            if (document.readyState === "loading") {
                document.addEventListener("DOMContentLoaded", start, { once: true });
            } else {
                start();
            }
        })();
        """

        script = QWebEngineScript()
        script.setName("wa_contact_info_scraper")
        script.setSourceCode(script_source)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        profile.scripts().insert(script)
    
    def refresh_performance_dock(self):
        if hasattr(self, "performance_dock"):
            self.performance_dock.refresh_dashboard()

    def install_whatsapp_bad_word_guard(self, profile=None):
        profile = profile or self.profile

        bad_words = load_bad_words()
        if not bad_words:
            return

        bad_words_json = json.dumps(sorted(set(bad_words), key=len, reverse=True))

        script_source = f"""
        (function() {{
            if (window.__waBadWordGuardInstalled) return;
            window.__waBadWordGuardInstalled = true;

            if (location.hostname !== "web.whatsapp.com") return;

            const BAD_WORDS = {bad_words_json};
            if (!BAD_WORDS.length) return;

            const COMPOSE_SELECTORS = [
                'footer div[contenteditable="true"][data-testid="conversation-compose-box-input"]',
                'main footer div[contenteditable="true"][data-testid="conversation-compose-box-input"]',
                'footer div[contenteditable="true"][role="textbox"]',
                'main footer div[contenteditable="true"][role="textbox"]',
                'footer div[contenteditable="true"]',
                'main footer div[contenteditable="true"]'
            ];

            const SEND_BUTTON_SELECTORS = [
                'footer button[aria-label="Send"]',
                'footer button[data-testid="compose-btn-send"]',
                'footer span[data-icon="send"]',
                'footer span[data-icon="wds-ic-send-filled"]',
                'button[aria-label="Send"]',
                'button[data-testid="compose-btn-send"]',
                'span[data-icon="send"]',
                'span[data-icon="wds-ic-send-filled"]'
            ];

            let applyingMask = false;
            let bypassNextSend = false;
            let lastMaskedSnapshot = "";

            function escapeRegExp(s) {{
                return String(s).replace(/[.*+?^${{}}()|[\\]\\\\]/g, '\\\\$&');
            }}

            const BAD_WORD_REGEX = new RegExp(
                "\\\\b(" + BAD_WORDS.map(escapeRegExp).join("|") + ")\\\\b",
                "gi"
            );

            function getComposeText(el) {{
                return ((el?.innerText || el?.textContent || "").replace(/\\u00A0/g, " ")).trim();
            }}

            function findComposeBox() {{
                for (const sel of COMPOSE_SELECTORS) {{
                    const candidates = Array.from(document.querySelectorAll(sel));
                    for (const el of candidates) {{
                        if (!el) continue;

                        const footer = el.closest("footer");
                        if (!footer) continue;

                        const meta = (
                            (el.getAttribute("aria-label") || "") + " " +
                            (el.getAttribute("aria-placeholder") || "") + " " +
                            (el.getAttribute("data-testid") || "")
                        ).toLowerCase();

                        if (meta.includes("search")) continue;

                        const rect = el.getBoundingClientRect();
                        if (rect.width < 80 || rect.height < 20) continue;

                        return el;
                    }}
                }}
                return null;
            }}

            function findSendButton() {{
                for (const sel of SEND_BUTTON_SELECTORS) {{
                    const btn = document.querySelector(sel);
                    if (!btn) continue;

                    if (btn.tagName === "SPAN" && btn.hasAttribute("data-icon")) {{
                        let parent = btn.parentElement;
                        while (parent && parent.tagName !== "BUTTON") parent = parent.parentElement;
                        if (parent) return parent;
                    }} else if (btn.tagName === "BUTTON") {{
                        return btn;
                    }}
                }}
                return null;
            }}

            function matchesSendButton(target) {{
                if (!target) return false;
                for (const sel of SEND_BUTTON_SELECTORS) {{
                    try {{
                        if (target.closest(sel)) return true;
                    }} catch (e) {{}}
                }}
                return false;
            }}

            function insertMessagePreserveLines(composeBox, text) {{
                const normalized = String(text || "").replace(/\\r\\n/g, "\\n");
                composeBox.focus();

                const selection = window.getSelection();
                const range = document.createRange();
                range.selectNodeContents(composeBox);
                range.deleteContents();
                range.collapse(true);

                selection.removeAllRanges();
                selection.addRange(range);

                const lines = normalized.split("\\n");

                lines.forEach((line, idx) => {{
                    if (idx > 0) {{
                        const br = document.createElement("br");
                        range.insertNode(br);
                        range.setStartAfter(br);
                        range.collapse(true);
                    }}

                    if (line.length > 0) {{
                        const textNode = document.createTextNode(line);
                        range.insertNode(textNode);
                        range.setStartAfter(textNode);
                        range.collapse(true);
                    }}
                }});

                selection.removeAllRanges();
                selection.addRange(range);

                composeBox.dispatchEvent(new InputEvent("input", {{
                    bubbles: true,
                    data: normalized,
                    inputType: "insertText"
                }}));
                composeBox.dispatchEvent(new Event("change", {{ bubbles: true }}));
            }}

            function scanAndMask(text) {{
                const hits = [];
                const masked = String(text || "").replace(BAD_WORD_REGEX, function(m) {{
                    hits.push(String(m).toLowerCase());
                    return "*".repeat(m.length);
                }});

                return {{
                    original: String(text || ""),
                    masked: masked,
                    hits: hits,
                    unique_hits: Array.from(new Set(hits))
                }};
            }}

            function storeBadWordMeta(result, trigger) {{
                window.__waLastBadWordScan = {{
                    ts: new Date().toISOString(),
                    trigger: trigger || "unknown",
                    bad_word_count: result.hits.length,
                    bad_words: result.unique_hits,
                    bad_word_hits: result.hits,
                    original_content: result.original,
                    masked_content: result.masked
                }};
            }}

            function sanitizeComposer(trigger) {{
                if (applyingMask) return false;

                const composeBox = findComposeBox();
                if (!composeBox) return false;

                const originalText = getComposeText(composeBox);
                if (!originalText) return false;

                const result = scanAndMask(originalText);
                if (!result.hits.length) return false;

                if (result.masked === originalText && lastMaskedSnapshot === result.masked) {{
                    storeBadWordMeta(result, trigger || "watcher");
                    return true;
                }}

                applyingMask = true;
                try {{
                    insertMessagePreserveLines(composeBox, result.masked);
                    lastMaskedSnapshot = result.masked;
                    storeBadWordMeta(result, trigger || "watcher");
                }} finally {{
                    setTimeout(function() {{
                        applyingMask = false;
                    }}, 30);
                }}

                return true;
            }}

            function triggerMaskedSend() {{
                const btn = findSendButton();
                if (btn) {{
                    bypassNextSend = true;
                    btn.click();
                    setTimeout(function() {{ bypassNextSend = false; }}, 300);
                    return true;
                }}

                const composeBox = findComposeBox();
                if (composeBox) {{
                    bypassNextSend = true;
                    composeBox.focus();
                    composeBox.dispatchEvent(new KeyboardEvent("keydown", {{
                        key: "Enter",
                        code: "Enter",
                        keyCode: 13,
                        which: 13,
                        bubbles: true,
                        cancelable: true
                    }}));
                    setTimeout(function() {{ bypassNextSend = false; }}, 300);
                    return true;
                }}

                return false;
            }}

            function processBeforeSend(event, trigger) {{
                if (bypassNextSend || applyingMask) return;

                const composeBox = findComposeBox();
                if (!composeBox) return;

                const originalText = getComposeText(composeBox);
                if (!originalText) return;

                const result = scanAndMask(originalText);
                if (!result.hits.length) return;

                event.preventDefault();
                event.stopPropagation();
                event.stopImmediatePropagation();

                applyingMask = true;
                try {{
                    insertMessagePreserveLines(composeBox, result.masked);
                    lastMaskedSnapshot = result.masked;
                    storeBadWordMeta(result, trigger || "send");
                }} finally {{
                    setTimeout(function() {{
                        applyingMask = false;
                        triggerMaskedSend();
                    }}, 140);
                }}
            }}

            document.addEventListener("beforeinput", function(e) {{
                const composeBox = findComposeBox();
                if (!composeBox) return;
                if (e.target === composeBox || composeBox.contains(e.target)) {{
                    setTimeout(function() {{
                        sanitizeComposer("beforeinput");
                    }}, 0);
                }}
            }}, true);

            document.addEventListener("input", function(e) {{
                const composeBox = findComposeBox();
                if (!composeBox) return;
                if (e.target === composeBox || composeBox.contains(e.target)) {{
                    setTimeout(function() {{
                        sanitizeComposer("input");
                    }}, 0);
                }}
            }}, true);

            document.addEventListener("paste", function(e) {{
                const composeBox = findComposeBox();
                if (!composeBox) return;
                if (e.target === composeBox || composeBox.contains(e.target)) {{
                    setTimeout(function() {{
                        sanitizeComposer("paste");
                    }}, 0);
                }}
            }}, true);

            document.addEventListener("keyup", function(e) {{
                const composeBox = findComposeBox();
                if (!composeBox) return;
                if (e.target === composeBox || composeBox.contains(e.target)) {{
                    setTimeout(function() {{
                        sanitizeComposer("keyup");
                    }}, 0);
                }}
            }}, true);

            document.addEventListener("drop", function(e) {{
                const composeBox = findComposeBox();
                if (!composeBox) return;
                if (e.target === composeBox || composeBox.contains(e.target)) {{
                    setTimeout(function() {{
                        sanitizeComposer("drop");
                    }}, 0);
                }}
            }}, true);

            document.addEventListener("click", function(e) {{
                if (matchesSendButton(e.target)) {{
                    processBeforeSend(e, "click");
                }}
            }}, true);

            document.addEventListener("keydown", function(e) {{
                if (e.key !== "Enter" || e.shiftKey) return;

                const composeBox = findComposeBox();
                if (!composeBox) return;

                if (composeBox === e.target || composeBox.contains(e.target)) {{
                    processBeforeSend(e, "enter");
                }}
            }}, true);

            const observer = new MutationObserver(function() {{
                sanitizeComposer("mutation");
            }});

            function startObserver() {{
                try {{
                    observer.observe(document.body, {{
                        childList: true,
                        subtree: true
                    }});
                }} catch (e) {{}}
            }}

            setInterval(function() {{
                sanitizeComposer("watchdog");
            }}, 700);

            if (document.readyState === "loading") {{
                document.addEventListener("DOMContentLoaded", function() {{
                    startObserver();
                }}, {{ once: true }});
            }} else {{
                startObserver();
            }}
        }})();
        """

        script = QWebEngineScript()
        script.setName("wa_bad_word_guard")
        script.setSourceCode(script_source)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        profile.scripts().insert(script)


    def get_or_create_whatsapp_profile(self, account_id):
        if account_id in self.whatsapp_profiles:
            return self.whatsapp_profiles[account_id]

        profile = QWebEngineProfile(f"LockedBrowserWhatsApp_{account_id}", self)
        profile = self.configure_profile(profile, f"whatsapp_{account_id}")
        self.whatsapp_profiles[account_id] = profile
        return profile


    def get_whatsapp_config(self):
        return self.get_config_by_name("WhatsApp")


    def get_active_whatsapp_tab(self):
        current = self.tab_widget.currentWidget()
        if isinstance(current, QWebEngineView):
            meta = self.find_tab_meta_by_view(current)
            if meta and meta["name"] == "WhatsApp":
                return meta

        for tab in self.tab_views:
            if tab["name"] == "WhatsApp":
                return tab
        return None


    def get_next_whatsapp_account_id(self):
        existing = set()

        state = load_app_state()
        for x in state.get("wa_account_ids", []):
            existing.add(int(x))

        for tab in self.tab_views:
            if tab["name"] == "WhatsApp" and tab.get("account_id") is not None:
                existing.add(int(tab["account_id"]))

        return (max(existing) + 1) if existing else 1


    def save_whatsapp_tabs_state(self):
        ids = sorted({
            int(tab["account_id"])
            for tab in self.tab_views
            if tab["name"] == "WhatsApp" and tab.get("account_id") is not None
        })

        if not ids:
            ids = [1]

        state = load_app_state()
        state["wa_account_ids"] = ids
        save_app_state(state)

    def add_whatsapp_account_tab(self, account_id=None, switch_to=True, save_state_after=True):
        config = self.get_whatsapp_config()
        if not config:
            QMessageBox.warning(self, "Missing Config", "WhatsApp config not found.")
            return None

        if account_id is None:
            account_id = self.get_next_whatsapp_account_id()

        for tab in self.tab_views:
            if tab["name"] == "WhatsApp" and tab.get("account_id") == account_id:
                self.tab_widget.setCurrentWidget(tab["view"])
                return tab["view"]

        profile = self.get_or_create_whatsapp_profile(account_id)

        self.add_browser_tab(
            config=config,
            title=f"WhatsApp {account_id}",
            is_fixed=False,
            switch_to=switch_to,
            initial_url=config["home"],
            profile=profile,
            account_id=account_id
        )

        if save_state_after:
            self.save_whatsapp_tabs_state()

        return True


    def create_dynamic_tab_from_meta(self, tab_meta):
        return self.add_browser_tab(
            config={
                "name": tab_meta["name"],
                "allowed_sites": tab_meta["allowed_sites"],
                "home": tab_meta["home"]
            },
            title=f"{tab_meta['name']} *",
            is_fixed=False,
            switch_to=True,
            profile=tab_meta.get("profile"),
            account_id=tab_meta.get("account_id")
        )
    
    def _build_bulk_overlay_html(self):
        icons = {
            "pending": "⏳",
            "sending": "🔄",
            "sent": "✅",
            "failed": "❌"
        }

        sent_count = sum(1 for x in self._bulk_statuses if x["status"] == "sent")
        failed_count = sum(1 for x in self._bulk_statuses if x["status"] == "failed")
        pending_count = sum(1 for x in self._bulk_statuses if x["status"] == "pending")
        sending_item = next((x for x in self._bulk_statuses if x["status"] == "sending"), None)

        current_text = sending_item["number"] if sending_item else "-"
        title_text = (
            "Automated blast is in progress. Please wait until finish."
            if self._bulk_processing else
            "Automated blast finished."
        )

        rows = []
        for i, item in enumerate(self._bulk_statuses, start=1):
            number = item["number"]
            status = item["status"]
            icon = icons.get(status, "•")
            rows.append(
                f"""
                <div style="display:flex;justify-content:space-between;gap:10px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.08);">
                    <span>{i}. {number}</span>
                    <b>{icon} {status.upper()}</b>
                </div>
                """
            )

        rows_html = "".join(rows) if rows else "<div>No bulk job running.</div>"

        return f"""
        <div style="
            background: rgba(18,18,18,0.92);
            color: white;
            font-family: Arial, sans-serif;
            font-size: 12px;
            border-radius: 12px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.35);
            padding: 14px;
            border: 1px solid rgba(255,255,255,0.10);
        ">
            <div style="font-size:14px;font-weight:700;margin-bottom:8px;">
                PT Pendanaan Teknologi Nusa
            </div>

            <div style="margin-bottom:8px;color:#ffd966;font-weight:700;">
                {title_text}
            </div>

            <div style="margin-bottom:8px;">
                <div><b>Current:</b> {current_text}</div>
                <div><b>Sent:</b> {sent_count} &nbsp; <b>Failed:</b> {failed_count} &nbsp; <b>Pending:</b> {pending_count}</div>
            </div>

            <div style="max-height:260px;overflow:auto;padding-right:4px;">
                {rows_html}
            </div>
        </div>
        """

    def _render_bulk_overlay(self):
        wa_tab = self.get_bulk_target_whatsapp_tab() or self.get_active_whatsapp_tab()
        if not wa_tab:
            return

        html = self._build_bulk_overlay_html()

        js = f"""
        (function() {{
            const overlayId = "__ptn_bulk_overlay";
            let overlay = document.getElementById(overlayId);

            if (!overlay) {{
                overlay = document.createElement("div");
                overlay.id = overlayId;
                overlay.tabIndex = 0;
                overlay.style.position = "fixed";
                overlay.style.inset = "0";
                overlay.style.zIndex = "2147483647";
                overlay.style.background = "rgba(0,0,0,0.08)";
                overlay.style.pointerEvents = "auto";
                overlay.style.display = "flex";
                overlay.style.alignItems = "flex-start";
                overlay.style.justifyContent = "flex-end";
                overlay.style.padding = "12px";
                overlay.style.boxSizing = "border-box";
                overlay.style.cursor = "not-allowed";
                overlay.style.outline = "none";

                const block = function(e) {{
                    e.preventDefault();
                    e.stopPropagation();
                    e.stopImmediatePropagation();
                    return false;
                }};

                ["click", "dblclick", "mousedown", "mouseup", "contextmenu", "wheel",
                "touchstart", "touchmove", "keydown", "keyup", "keypress", "paste", "drop"]
                .forEach(function(evt) {{
                    overlay.addEventListener(evt, block, true);
                }});

                document.body.appendChild(overlay);
            }}

            overlay.innerHTML = {json.dumps(html)};

            if (document.activeElement && typeof document.activeElement.blur === "function") {{
                try {{ document.activeElement.blur(); }} catch (e) {{}}
            }}

            try {{ overlay.focus(); }} catch (e) {{}}
        }})();
        """
        wa_tab["view"].page().runJavaScript(js)

    def _poll_bulk_whatsapp_status(self):
        if not self._bulk_processing:
            self._bulk_poll_timer.stop()
            return

        wa_tab = self.get_bulk_target_whatsapp_tab()
        if not wa_tab:
            self._bulk_poll_timer.stop()
            self._bulk_processing = False
            QMessageBox.critical(self, "Error", "Bulk target WhatsApp tab no longer exists.")
            return

        if self._bulk_send_started_at and (time.monotonic() - self._bulk_send_started_at > self._bulk_send_timeout_sec):
            current_recipient = {}
            if 0 <= self._bulk_index < len(self._bulk_recipients):
                current_recipient = self._bulk_recipients[self._bulk_index]

            number = current_recipient.get("send_number", "UNKNOWN")
            display_number = current_recipient.get("display_number", number)

            print(f"Timeout while sending to {number}")

            if 0 <= self._bulk_index < len(self._bulk_statuses):
                self._bulk_statuses[self._bulk_index]["status"] = "failed"

            save_history({
                "timestamp": datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
                "tab": self._format_whatsapp_label(self._bulk_target_account_id),
                "event": "bulk_send_result",
                "number": number,
                "display_number": display_number,
                "status": "failed",
                "template_message": self._bulk_template,
                "message": current_recipient.get("message", ""),
                "error": "timeout"
            })

            save_manual_send_log({
                "timestamp": datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
                "from": self._format_whatsapp_label(self._bulk_target_account_id),
                "to": str(number),
                "content": current_recipient.get("message", ""),
                "message_length": len(current_recipient.get("message", "") or ""),
                "has_attachment": bool(self._bulk_attachment_path),
                "send_type": "bulk_auto",
                "trigger": "bulk_blast",
                "status": "failed",
                "bad_word_count": len(current_recipient.get("bad_word_hits") or []),
                "bad_words": current_recipient.get("bad_words") or []
            })

            self._render_bulk_overlay()
            self._bulk_poll_timer.stop()
            QTimer.singleShot(1000, self._increment_and_load_next)
            return

        view = wa_tab["view"]
        view.page().runJavaScript(
            """
            (function() {
                if (!window.__waAutoSendState) return null;
                return JSON.stringify(window.__waAutoSendState);
            })();
            """,
            self._handle_bulk_whatsapp_status
        )

    def get_bulk_target_whatsapp_tab(self):
        if self._bulk_target_view is not None:
            meta = self.find_tab_meta_by_view(self._bulk_target_view)
            if meta and meta["name"] == "WhatsApp":
                return meta
        return None
    
    def _handle_bulk_whatsapp_status(self, result):
        if not self._bulk_processing:
            return

        if not result:
            return

        try:
            state = json.loads(result)
        except Exception:
            return

        status = state.get("status")
        if status == "running":
            return

        self._bulk_poll_timer.stop()

        current_recipient = (
            self._bulk_recipients[self._bulk_index]
            if 0 <= self._bulk_index < len(self._bulk_recipients)
            else {}
        )

        actual_number = current_recipient.get("send_number") or "UNKNOWN"
        display_number = current_recipient.get("display_number") or actual_number
        actual_message = current_recipient.get("message", "")

        if status == "sent":
            if 0 <= self._bulk_index < len(self._bulk_statuses):
                self._bulk_statuses[self._bulk_index]["status"] = "sent"
            print(f"Message sent successfully for number {actual_number}")
            self.status_bar.showMessage(f"Sent to {display_number}", 3000)
        else:
            if 0 <= self._bulk_index < len(self._bulk_statuses):
                self._bulk_statuses[self._bulk_index]["status"] = "failed"
            err = state.get("error") or "unknown"
            print(f"Failed to send for number {actual_number}: {err}")
            self.status_bar.showMessage(f"Failed to send to {display_number}", 3000)

        save_history({
            "timestamp": datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
            "tab": self._format_whatsapp_label(self._bulk_target_account_id),
            "event": "bulk_send_result",
            "number": actual_number,
            "display_number": display_number,
            "status": status,
            "template_message": self._bulk_template,
            "message": actual_message,
            "has_attachment": bool(self._bulk_attachment_path)
        })

        bad_word_hits = current_recipient.get("bad_word_hits") or []
        bad_words = current_recipient.get("bad_words") or []

        save_manual_send_log({
            "timestamp": datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
            "from": self._format_whatsapp_label(self._bulk_target_account_id),
            "to": str(actual_number),
            "content": actual_message,
            "message_length": len(actual_message or ""),
            "has_attachment": bool(self._bulk_attachment_path),
            "send_type": "bulk_auto",
            "trigger": "bulk_blast",
            "status": "sent" if status == "sent" else "failed",
            "bad_word_count": len(bad_word_hits),
            "bad_words": bad_words
        })

        if status == "sent":
            update_contact_interaction(
                send_number=actual_number,
                timestamp_text=datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
                direction="outgoing",
                message=actual_message,
                send_type="bulk_auto",
                account_label=self._format_whatsapp_label(self._bulk_target_account_id),
                status="sent",
                display_number=display_number,
                trigger="bulk_blast",
                auto_create=True
            )

        if status == "sent" and bad_word_hits:
            increment_bad_word_counter(
                bad_word_hits,
                source=self._format_whatsapp_label(self._bulk_target_account_id),
                when_dt=datetime.datetime.now(USER_TIMEZONE),
                sender=self._format_whatsapp_label(self._bulk_target_account_id),
                receiver=str(display_number or actual_number),
                message_preview=actual_message,
                trigger="bulk_blast",
                send_type="bulk_auto"
            )

        self._render_bulk_overlay()
        self.refresh_performance_dock()
        QTimer.singleShot(2000, self._increment_and_load_next)


    def _load_next_bulk_whatsapp(self):
        if not self._bulk_processing or self._bulk_index >= len(self._bulk_recipients):
            self._bulk_processing = False
            QMessageBox.information(self, "Bulk Send", "All messages processed.")
            return

        wa_tab = self.get_bulk_target_whatsapp_tab()
        if not wa_tab:
            self._bulk_processing = False
            QMessageBox.critical(self, "Error", "Bulk target WhatsApp tab no longer exists.")
            return

        recipient = self._bulk_recipients[self._bulk_index]
        number = recipient.get("send_number")
        url = f"https://web.whatsapp.com/send?phone={number}"
        wa_tab["view"].setUrl(QUrl(url))

    def _on_bulk_whatsapp_load(self, ok):
        view = self.sender()
        if not isinstance(view, QWebEngineView):
            return

        wa_tab = self.get_bulk_target_whatsapp_tab()
        if not wa_tab:
            return

        if not self._bulk_processing or view != wa_tab["view"]:
            return

        if not ok:
            current_recipient = self._bulk_recipients[self._bulk_index]
            print(f"Failed to load WhatsApp page for number {current_recipient.get('send_number')}")
            QTimer.singleShot(3000, self._increment_and_load_next)
            return

        self._bulk_send_started_at = time.monotonic()

        if 0 <= self._bulk_index < len(self._bulk_statuses):
            self._bulk_statuses[self._bulk_index]["status"] = "sending"

        self._render_bulk_overlay()

        current_recipient = self._bulk_recipients[self._bulk_index]
        self.inject_whatsapp_auto_send(
            view,
            current_recipient.get("message", ""),
            attachment_path=self._bulk_attachment_path
        )

        if not self._bulk_poll_timer.isActive():
            self._bulk_poll_timer.start()

    def _increment_and_load_next(self):
        if not self._bulk_processing:
            return

        wa_tab = self.get_bulk_target_whatsapp_tab()
        if wa_tab:
            wa_tab["view"].page().runJavaScript("window.__waAutoSendState = null;")
            if hasattr(wa_tab["view"].page(), "auto_file_chooser_path"):
                wa_tab["view"].page().auto_file_chooser_path = ""

        self._bulk_index += 1

        if self._bulk_index >= len(self._bulk_recipients):
            finished_view = self._bulk_target_view
            finished_label = self._format_whatsapp_label(self._bulk_target_account_id)

            self._bulk_processing = False
            self._bulk_poll_timer.stop()

            if finished_view:
                try:
                    finished_view.loadFinished.disconnect(self._on_bulk_whatsapp_load)
                except TypeError:
                    pass

            self._clear_active_overlay(finished_view)

            save_last_blast(self._bulk_recipients, self._bulk_template, self._bulk_attachment_path)

            self._bulk_target_view = None
            self._bulk_target_account_id = None
            self._bulk_recipients = []
            self._bulk_template = ""
            self._bulk_attachment_path = ""

            started_next = self._start_next_queued_bulk_job()

            if not started_next:
                QMessageBox.information(self, "Bulk Send", f"{finished_label}: all messages processed.")

            return

        self._load_next_bulk_whatsapp()

    def inject_whatsapp_auto_send(self, view, message, attachment_path=""):
        attachment_path = normalize_template_attachment_path(attachment_path)
        escaped_message = json.dumps(message)
        escaped_attachment = json.dumps(attachment_path)

        page = view.page() if isinstance(view, QWebEngineView) else None
        if page and hasattr(page, "auto_file_chooser_path"):
            page.auto_file_chooser_path = attachment_path if attachment_path and os.path.exists(attachment_path) else ""
        script = f"""
        (function() {{
            if (window.__waAutoSendState && window.__waAutoSendState.status === "running") {{
                console.log("WhatsApp auto-sender already running on this page.");
                return true;
            }}

            window.__waAutoSendState = {{
                status: "running",
                startedAt: Date.now(),
                error: null
            }};

            const TARGET_MESSAGE = {escaped_message};
            const TARGET_ATTACHMENT = {escaped_attachment};
            console.log('WhatsApp auto-sender started. Message:', TARGET_MESSAGE);

            const COMPOSE_SELECTORS = [
                'footer div[contenteditable="true"][data-testid="conversation-compose-box-input"]',
                'main footer div[contenteditable="true"][data-testid="conversation-compose-box-input"]',
                'footer div[contenteditable="true"][role="textbox"]',
                'main footer div[contenteditable="true"][role="textbox"]',
                'footer div[contenteditable="true"]',
                'main footer div[contenteditable="true"]'
            ];

            const GO_TO_CHAT_SELECTORS = [
                'div[role="button"][aria-label*="chat"]',
                'a[href*="whatsapp.com"]',
                'div[aria-label*="Go to chat"]'
            ];

            const SEND_BUTTON_SELECTORS = [
                'footer button[aria-label="Send"]',
                'footer button[data-testid="compose-btn-send"]',
                'footer span[data-icon="send"]',
                'footer span[data-icon="wds-ic-send-filled"]',
                'button[aria-label="Send"]',
                'button[data-testid="compose-btn-send"]',
                'span[data-icon="send"]',
                'span[data-icon="wds-ic-send-filled"]'
            ];

            const QR_SELECTOR = 'canvas[aria-label="Scan me!"]';

            const ATTACH_BUTTON_SELECTORS = [
                'footer button[aria-label*="Attach"]',
                'footer div[role="button"][title*="Attach"]',
                'footer span[data-icon="plus-rounded"]',
                'footer span[data-icon="clip"]',
                'button[aria-label*="Attach"]',
                'div[role="button"][title*="Attach"]',
                'span[data-icon="plus-rounded"]',
                'span[data-icon="clip"]'
            ];

            const INVALID_PATTERNS = [
                'phone number shared via url is invalid',
                'the phone number shared via url is invalid',
                'phone number shared via url is invalid.',
                'this phone number isn\\'t on whatsapp',
                'this phone number is not on whatsapp',
                'this number isn\\'t on whatsapp',
                'this number is not on whatsapp',
                'number shared via url is invalid',
                'nomor telepon yang dibagikan melalui url tidak valid',
                'nomor ini tidak terdaftar di whatsapp',
                'nomor telepon ini tidak terdaftar di whatsapp'
            ];

            function normalizeText(s) {{
                return String(s || "")
                    .replace(/\\u00A0/g, " ")
                    .replace(/\\s+/g, " ")
                    .trim()
                    .toLowerCase();
            }}

            function getPageText() {{
                try {{
                    return normalizeText(document.body ? document.body.innerText : "");
                }} catch (e) {{
                    return "";
                }}
            }}

            function detectInvalidRecipient() {{
                const bodyText = getPageText();
                for (const pattern of INVALID_PATTERNS) {{
                    if (bodyText.includes(pattern)) {{
                        return pattern;
                    }}
                }}

                // Extra selector-based checks
                const candidates = Array.from(document.querySelectorAll(
                    'div[role="dialog"], div[data-animate-modal-popup="true"], main, body'
                ));

                for (const el of candidates) {{
                    const txt = normalizeText(el.innerText || el.textContent || "");
                    for (const pattern of INVALID_PATTERNS) {{
                        if (txt.includes(pattern)) {{
                            return pattern;
                        }}
                    }}
                }}

                return "";
            }}

            function dismissInvalidDialogIfAny() {{
                const labels = ['ok', 'close', 'tutup', 'cancel'];
                const nodes = Array.from(document.querySelectorAll('button, div[role="button"], span[role="button"]'));

                for (const node of nodes) {{
                    const txt = normalizeText(node.innerText || node.textContent || node.getAttribute('aria-label') || '');
                    if (labels.includes(txt)) {{
                        try {{
                            node.click();
                            return true;
                        }} catch (e) {{}}
                    }}
                }}
                return false;
            }}

            function waitForAnySelector(selectors, timeout = 60000, parent = document) {{
                return new Promise((resolve, reject) => {{
                    const check = () => {{
                        for (const sel of selectors) {{
                            const el = parent.querySelector(sel);
                            if (el) return el;
                        }}
                        return null;
                    }};

                    const element = check();
                    if (element) return resolve(element);

                    const observer = new MutationObserver(() => {{
                        const found = check();
                        if (found) {{
                            observer.disconnect();
                            resolve(found);
                        }}
                    }});

                    observer.observe(parent, {{ childList: true, subtree: true }});

                    setTimeout(() => {{
                        observer.disconnect();
                        reject(new Error('Timeout waiting for selector'));
                    }}, timeout);
                }});
            }}

            function clickElement(element) {{
                if (!element) return false;
                try {{
                    element.focus?.();
                    element.click();
                    return true;
                }} catch (e) {{
                    console.log('Click error:', e);
                    return false;
                }}
            }}

            function findComposeBox() {{
                for (const sel of COMPOSE_SELECTORS) {{
                    const candidates = Array.from(document.querySelectorAll(sel));

                    for (const el of candidates) {{
                        if (!el) continue;

                        const footer = el.closest('footer');
                        if (!footer) continue;

                        const meta = (
                            (el.getAttribute('aria-label') || '') + ' ' +
                            (el.getAttribute('aria-placeholder') || '') + ' ' +
                            (el.getAttribute('data-testid') || '')
                        ).toLowerCase();

                        if (meta.includes('search')) continue;

                        const rect = el.getBoundingClientRect();
                        if (rect.width < 80 || rect.height < 20) continue;

                        return el;
                    }}
                }}
                return null;
            }}

            function findSendButton() {{
                const found = [];
                for (const sel of SEND_BUTTON_SELECTORS) {{
                    const nodes = Array.from(document.querySelectorAll(sel));
                    for (const btn of nodes) {{
                        if (!btn) continue;

                        let target = btn;
                        if (btn.tagName === 'SPAN' && btn.hasAttribute('data-icon')) {{
                            let parent = btn.parentElement;
                            while (parent && parent.tagName !== 'BUTTON') parent = parent.parentElement;
                            if (parent) target = parent;
                        }}

                        if (!target || found.includes(target)) continue;

                        const rect = target.getBoundingClientRect();
                        if (rect.width < 8 || rect.height < 8) continue;
                        found.push(target);
                    }}
                }}

                if (!found.length) return null;
                found.sort((a, b) => {{
                    const ra = a.getBoundingClientRect();
                    const rb = b.getBoundingClientRect();
                    return (rb.bottom + rb.right) - (ra.bottom + ra.right);
                }});
                return found[0];
            }}

            function findAttachButton() {{
                for (const sel of ATTACH_BUTTON_SELECTORS) {{
                    const nodes = Array.from(document.querySelectorAll(sel));
                    for (const node of nodes) {{
                        if (!node) continue;
                        let target = node;
                        if (node.tagName === 'SPAN' && node.hasAttribute('data-icon')) {{
                            let parent = node.parentElement;
                            while (parent && parent.tagName !== 'BUTTON' && !parent.getAttribute?.('role')) parent = parent.parentElement;
                            if (parent) target = parent;
                        }}

                        const rect = target.getBoundingClientRect();
                        if (rect.width < 8 || rect.height < 8) continue;
                        return target;
                    }}
                }}
                return null;
            }}

            function listFileInputs() {{
                return Array.from(document.querySelectorAll('input[type="file"]'));
            }}

            function findBestImageFileInput() {{
                const inputs = listFileInputs();
                for (const input of inputs) {{
                    const accept = String(input.getAttribute('accept') || '').toLowerCase();
                    if (!accept || accept.includes('image') || accept.includes('.jpg') || accept.includes('.jpeg') || accept.includes('.png')) {{
                        return input;
                    }}
                }}
                return inputs[0] || null;
            }}

            function hasSelectedAttachment() {{
                return listFileInputs().some(input => {{
                    try {{
                        return !!(input.files && input.files.length);
                    }} catch (e) {{
                        return false;
                    }}
                }});
            }}

            async function waitForSelectedAttachment(timeoutMs) {{
                const startedAt = Date.now();
                while ((Date.now() - startedAt) < timeoutMs) {{
                    if (hasSelectedAttachment()) return true;
                    await new Promise(r => setTimeout(r, 250));
                }}
                return false;
            }}

            async function waitForComposeBox(timeoutMs) {{
                const startedAt = Date.now();
                while ((Date.now() - startedAt) < timeoutMs) {{
                    const composeBox = findComposeBox();
                    if (composeBox) return composeBox;
                    await new Promise(r => setTimeout(r, 250));
                }}
                return null;
            }}

            async function uploadAndSendAttachmentOnly() {{
                let fileInput = findBestImageFileInput();
                if (!fileInput) {{
                    const attachButton = findAttachButton();
                    if (attachButton) {{
                        clickElement(attachButton);
                        await new Promise(r => setTimeout(r, 700));
                        fileInput = findBestImageFileInput();
                    }}
                }}

                if (!fileInput) {{
                    return {{ ok: false, error: 'attachment_input_not_found' }};
                }}

                try {{
                    fileInput.click();
                }} catch (e) {{
                    try {{
                        fileInput.dispatchEvent(new MouseEvent('click', {{ bubbles: true, cancelable: true }}));
                    }} catch (err) {{}}
                }}

                const selected = await waitForSelectedAttachment(10000);
                if (!selected) {{
                    return {{ ok: false, error: 'attachment_not_selected' }};
                }}

                await new Promise(r => setTimeout(r, 1400));
                const sendButton = findSendButton();
                if (!sendButton) {{
                    return {{ ok: false, error: 'attachment_send_button_not_found' }};
                }}

                clickElement(sendButton);
                await new Promise(r => setTimeout(r, 1800));
                return {{ ok: true, error: null }};
            }}

            function insertMessagePreserveLines(composeBox, text) {{
                const normalized = String(text || "").replace(/\\r\\n/g, "\\n");
                composeBox.focus();

                const selection = window.getSelection();
                const range = document.createRange();
                range.selectNodeContents(composeBox);
                range.deleteContents();
                range.collapse(true);

                selection.removeAllRanges();
                selection.addRange(range);

                const lines = normalized.split("\\n");

                lines.forEach((line, idx) => {{
                    if (idx > 0) {{
                        const br = document.createElement("br");
                        range.insertNode(br);
                        range.setStartAfter(br);
                        range.collapse(true);
                    }}

                    if (line.length > 0) {{
                        const textNode = document.createTextNode(line);
                        range.insertNode(textNode);
                        range.setStartAfter(textNode);
                        range.collapse(true);
                    }}
                }});

                selection.removeAllRanges();
                selection.addRange(range);

                composeBox.dispatchEvent(new InputEvent('input', {{
                    bubbles: true,
                    data: normalized,
                    inputType: 'insertText'
                }}));
                composeBox.dispatchEvent(new Event('change', {{ bubbles: true }}));
            }}

            async function attemptSend() {{
                try {{
                    await waitForAnySelector([QR_SELECTOR], 5000);
                    console.log('QR code detected – not logged in.');
                    return {{ ok: false, error: 'not_logged_in_qr' }};
                }} catch (e) {{
                    console.log('No QR code, proceeding.');
                }}

                // Sometimes WhatsApp shows a "Go to chat" or "Continue to chat" gate first
                try {{
                    const goToChat = await waitForAnySelector(GO_TO_CHAT_SELECTORS, 4000);
                    if (goToChat) {{
                        clickElement(goToChat);
                        await new Promise(r => setTimeout(r, 800));
                    }}
                }} catch (e) {{
                    console.log('No Go to chat button.');
                }}

                try {{
                    const allButtons = document.querySelectorAll('div[role="button"], button');
                    for (let btn of allButtons) {{
                        const txt = (btn.textContent || '').toLowerCase();
                        if (txt.includes('go to chat') || txt.includes('continue to chat')) {{
                            clickElement(btn);
                            await new Promise(r => setTimeout(r, 1000));
                            break;
                        }}
                    }}
                }} catch (e) {{}}

                // Fast fail if recipient is not on WhatsApp
                let composeBox = null;
                const waitStart = Date.now();
                while ((Date.now() - waitStart) < 15000) {{
                    const invalidReason = detectInvalidRecipient();
                    if (invalidReason) {{
                        console.log('Invalid / non-WhatsApp recipient detected:', invalidReason);
                        dismissInvalidDialogIfAny();
                        return {{ ok: false, error: 'not_on_whatsapp' }};
                    }}

                    composeBox = findComposeBox();
                    if (composeBox) break;

                    await new Promise(r => setTimeout(r, 250));
                }}

                if (!composeBox) {{
                    const invalidReason = detectInvalidRecipient();
                    if (invalidReason) {{
                        dismissInvalidDialogIfAny();
                        return {{ ok: false, error: 'not_on_whatsapp' }};
                    }}

                    console.log('Compose box timeout.');
                    return {{ ok: false, error: 'compose_box_timeout' }};
                }}

                if (TARGET_ATTACHMENT) {{
                    const attachmentResult = await uploadAndSendAttachmentOnly();
                    if (!attachmentResult.ok) {{
                        return attachmentResult;
                    }}
                    composeBox = null;
                }}

                if (!TARGET_MESSAGE) {{
                    return {{ ok: true, error: null }};
                }}

                composeBox = composeBox || await waitForComposeBox(10000);
                if (!composeBox) {{
                    return {{ ok: false, error: 'compose_box_timeout_after_attachment' }};
                }}

                insertMessagePreserveLines(composeBox, TARGET_MESSAGE);
                await new Promise(r => setTimeout(r, 1200));

                const sendButton = findSendButton();
                if (!sendButton) {{
                    const invalidReason = detectInvalidRecipient();
                    if (invalidReason) {{
                        dismissInvalidDialogIfAny();
                        return {{ ok: false, error: 'not_on_whatsapp' }};
                    }}

                    console.log('Send button not found.');
                    return {{ ok: false, error: 'send_button_not_found' }};
                }}

                clickElement(sendButton);

                for (let i = 0; i < 10; i++) {{
                    await new Promise(r => setTimeout(r, 400));

                    const invalidReason = detectInvalidRecipient();
                    if (invalidReason) {{
                        dismissInvalidDialogIfAny();
                        return {{ ok: false, error: 'not_on_whatsapp' }};
                    }}

                    const liveComposeBox = findComposeBox();
                    const remaining = liveComposeBox
                        ? ((liveComposeBox.innerText || liveComposeBox.textContent || '').replace(/\\u00A0/g, ' ')).trim()
                        : "";

                    if (!remaining) {{
                        return {{ ok: true, error: null }};
                    }}
                }}

                console.log('Message still present after send attempt; stopping to avoid double send.');
                return {{ ok: false, error: 'message_not_cleared_after_send' }};
            }}

            setTimeout(async () => {{
                try {{
                    const result = await attemptSend();
                    window.__waAutoSendState = {{
                        status: result.ok ? "sent" : "failed",
                        finishedAt: Date.now(),
                        error: result.error || null
                    }};
                    console.log("WA final status:", result.ok ? "sent" : "failed", result.error || "");
                }} catch (e) {{
                    window.__waAutoSendState = {{
                        status: "failed",
                        finishedAt: Date.now(),
                        error: String(e)
                    }};
                    console.log("WA final error:", e);
                }}
            }}, 1800);

            return true;
        }})();
        """
        view.page().runJavaScript(script)

    def bulk_whatsapp_send(self):
        if self._wa_sync_processing:
            QMessageBox.information(
                self,
                "Sync Running",
                "Please wait until the current WhatsApp history sync finishes."
            )
            return

        wa_tab = self.get_active_whatsapp_tab()
        if not wa_tab:
            QMessageBox.critical(self, "Error", "Open or select a WhatsApp tab first.")
            return

        last_blast = load_last_blast()
        templates = load_templates()
        allow_custom_message = self.is_custom_bulk_message_enabled()

        if not allow_custom_message and not templates:
            QMessageBox.warning(
                self,
                "No Templates Available",
                "Custom bulk message is disabled by admin.\n\nPlease create a saved template first."
            )
            return

        dlg = BulkWhatsAppDialog(
            last_blast=last_blast,
            templates=templates,
            allow_custom_message=allow_custom_message,
            parent=self
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        recipients = dlg.get_selected_recipients()
        message = dlg.get_message()
        attachment_path = dlg.get_attachment_path()

        if not recipients:
            QMessageBox.warning(self, "No Recipients", "No recipients selected.")
            return

        self._queue_or_start_bulk_job(wa_tab, recipients, message, attachment_path=attachment_path)

    def set_custom_proxy(self):
        host, ok = QInputDialog.getText(
            self,
            "Proxy Settings",
            "Enter proxy IP / host (leave blank for DIRECT):"
        )
        if not ok:
            return

        host = host.strip()

        if not host:
            self.apply_proxy_config({
                "enabled": False
            }, rebuild=True)

            save_network_log({
                "type": "proxy_config",
                "action": "disable",
                "proxy": {
                    "enabled": False,
                    "type": "DIRECT",
                    "host": "",
                    "port": 0,
                    "username": ""
                },
                "ts": datetime.datetime.now().isoformat()
            })

            QMessageBox.information(self, "Proxy", "Proxy disabled. Browser is now DIRECT.")
            return

        port, ok = QInputDialog.getInt(
            self,
            "Proxy Settings",
            "Enter proxy port:",
            value=8080,
            min=1,
            max=65535
        )
        if not ok:
            return

        proxy_type, ok = QInputDialog.getItem(
            self,
            "Proxy Type",
            "Select proxy type:",
            ["HTTP", "SOCKS5"],
            0,
            False
        )
        if not ok:
            return

        username, ok = QInputDialog.getText(
            self,
            "Proxy Credentials",
            "Username (optional):"
        )
        if not ok:
            return

        password = ""
        if username.strip():
            password, ok = QInputDialog.getText(
                self,
                "Proxy Credentials",
                "Password:",
                QLineEdit.EchoMode.Password
            )
            if not ok:
                return

        new_proxy = {
            "enabled": True,
            "type": proxy_type,
            "host": host,
            "port": port,
            "username": username.strip(),
            "password": password
        }

        self.apply_proxy_config(new_proxy, rebuild=True)

        save_network_log({
            "type": "proxy_config",
            "action": "enable",
            "proxy": {
                "enabled": True,
                "type": proxy_type,
                "host": host,
                "port": port,
                "username": username.strip()
            },
            "ts": datetime.datetime.now().isoformat()
        })

        self.status_bar.showMessage(f"Proxy set: {proxy_type} {host}:{port}", 5000)

        # This still tests QtNetwork, useful as a connectivity smoke test
        self.verify_proxy_connectivity()

    def install_disable_passkey_script(self, profile=None):
        profile = profile or self.profile

        script_source = r"""
        (function() {
            try {
                if (window.PublicKeyCredential) {
                    try { delete window.PublicKeyCredential; } catch (e) {}
                    try { window.PublicKeyCredential = undefined; } catch (e) {}
                }

                if (navigator.credentials) {
                    const origGet = navigator.credentials.get?.bind(navigator.credentials);
                    const origCreate = navigator.credentials.create?.bind(navigator.credentials);

                    if (origGet) {
                        navigator.credentials.get = function(options) {
                            if (options && options.publicKey) {
                                return Promise.reject(new Error("WebAuthn disabled"));
                            }
                            return origGet(options);
                        };
                    }

                    if (origCreate) {
                        navigator.credentials.create = function(options) {
                            if (options && options.publicKey) {
                                return Promise.reject(new Error("WebAuthn disabled"));
                            }
                            return origCreate(options);
                        };
                    }
                }
            } catch (e) {}
        })();
        """
        script = QWebEngineScript()
        script.setName("disable_passkey")
        script.setSourceCode(script_source)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        profile.scripts().insert(script)
    
    
    def get_url_host(self, url_str):
        try:
            return (urlparse(url_str).hostname or "").lower()
        except Exception:
            return ""

    def find_config_for_url(self, url_str):
        host = self.get_url_host(url_str)
        if not host:
            return None

        exact_match = None
        wildcard_match = None

        for config in TAB_CONFIG:
            for site in config["allowed_sites"]:
                site_host = self.get_url_host(site)

                if not site_host:
                    continue

                # exact match first
                if site_host != "*.google.com" and host == site_host:
                    exact_match = config
                    break

                # wildcard google fallback
                if site_host == "*.google.com" and is_google_host_allowed(host):
                    wildcard_match = config

            if exact_match:
                break

        return exact_match or wildcard_match


    def find_tab_meta_by_view(self, view):
        for tab in self.tab_views:
            if tab["view"] == view:
                return tab
        return None

    def refresh_whatsapp_identity_for_view(self, view):
        meta = self.find_tab_meta_by_view(view)
        if not meta or meta.get("name") != "WhatsApp":
            return

        js = r"""
        (function() {
            function collectStorageValues(storageObj) {
                const out = [];
                try {
                    for (let i = 0; i < storageObj.length; i++) {
                        const k = storageObj.key(i);
                        const v = storageObj.getItem(k);
                        out.push(String(k || ""));
                        out.push(String(v || ""));
                    }
                } catch (e) {}
                return out;
            }

            const candidates = [];
            candidates.push(...collectStorageValues(window.localStorage));
            candidates.push(...collectStorageValues(window.sessionStorage));

            const exactKeys = [
                "last-wid",
                "last-wid-md",
                "waLastLoggedInUser",
                "lastLoggedInUser"
            ];

            for (const key of exactKeys) {
                try {
                    const v1 = localStorage.getItem(key);
                    if (v1) candidates.unshift(String(v1));
                } catch (e) {}
                try {
                    const v2 = sessionStorage.getItem(key);
                    if (v2) candidates.unshift(String(v2));
                } catch (e) {}
            }

            const rx = /(\d{8,20})@(?:s\.whatsapp\.net|c\.us|lid)/i;

            for (const item of candidates) {
                const text = String(item || "");
                const m = text.match(rx);
                if (m && m[1]) {
                    return m[1];
                }
            }

            for (const item of candidates) {
                const digits = String(item || "").replace(/\D/g, "");
                if (digits.length >= 8 && digits.length <= 20) {
                    return digits;
                }
            }

            return "";
        })();
        """
        view.page().runJavaScript(
            js,
            lambda result, v=view: self.handle_whatsapp_identity_result(result, v)
        )

    def handle_whatsapp_identity_result(self, result, view):
        meta = self.find_tab_meta_by_view(view)
        if not meta or meta.get("name") != "WhatsApp":
            return

        send_number, display_number = normalize_whatsapp_self_number(result)
        if not send_number:
            return

        meta["wa_self_number"] = send_number
        meta["wa_self_display"] = display_number or send_number

        idx = self.tab_widget.indexOf(view)
        if idx >= 0:
            self.tab_widget.setTabText(idx, self._format_whatsapp_label(meta.get("account_id")))
        
        self.refresh_collection_whatsapp_accounts()
    
    
    def find_open_fixed_tab_by_name(self, name):
        for tab in self.tab_views:
            if tab["name"] == name and tab.get("is_fixed"):
                return tab
        return None


    def on_proxy_auth_required(self, request_url, authenticator, proxy_host):
        username = str(self.proxy_info.get("username") or "").strip()
        password = str(self.proxy_info.get("password") or "")

        # If user already configured credentials, use them automatically
        if self.proxy_info.get("enabled") and username:
            authenticator.setUser(username)
            authenticator.setPassword(password)
            return

        # Fallback prompt if proxy requests auth later
        user, ok = QInputDialog.getText(
            self,
            "Proxy Authentication Required",
            f"Proxy host: {proxy_host}\nUsername:"
        )
        if not ok:
            return

        pwd, ok = QInputDialog.getText(
            self,
            "Proxy Authentication Required",
            "Password:",
            QLineEdit.EchoMode.Password
        )
        if not ok:
            return

        authenticator.setUser(user)
        authenticator.setPassword(pwd)
    
    def add_browser_tab(self, config, title=None, is_fixed=False, switch_to=False, initial_url=None, profile=None, account_id=None):
        profile = profile or self.profile

        page = CustomWebEnginePage(profile, config["name"], self)
        page.proxyAuthenticationRequired.connect(self.on_proxy_auth_required)
        view = QWebEngineView()
        view.setPage(page)
        page.browser_view = view

        view.setContextMenuPolicy(Qt.ContextMenuPolicy.DefaultContextMenu)
        view.page().setDevToolsPage(None)

        view.urlChanged.connect(lambda url, v=view: self.enforce_tab_allowed_sites(url, v))
        view.loadFinished.connect(lambda ok, v=view: self.record_tab_history(ok, v))
        view.loadFinished.connect(
            lambda ok, p=page, name=config["name"]:
                p.runJavaScript(f"window._tabName = {json.dumps(name)};")
        )

        index = self.tab_widget.addTab(view, title or config["name"])

        self.tab_views.append({
            "view": view,
            "name": config["name"],
            "allowed_sites": config["allowed_sites"],
            "home": config["home"],
            "is_fixed": is_fixed,
            "profile": profile,
            "account_id": account_id,
            "wa_self_number": "",
            "wa_self_display": ""
        })

        if config["name"] == "WhatsApp":
            view.loadFinished.connect(
                lambda ok, v=view: QTimer.singleShot(
                    1800,
                    lambda vv=v: self.refresh_whatsapp_identity_for_view(vv)
                ) if ok else None
            )
            view.loadFinished.connect(
                lambda ok, v=view: QTimer.singleShot(
                    900,
                    lambda vv=v: self.push_cashier_mode_to_whatsapp_view(vv)
                ) if ok else None
            )

        if switch_to:
            self.tab_widget.setCurrentIndex(index)

        if initial_url:
            QTimer.singleShot(0, lambda: view.setUrl(QUrl(initial_url)))

        self._refresh_tab_close_buttons()

        return page


    def create_dynamic_tab_for_config(self, config):
        return self.add_browser_tab(
            config=config,
            title=f"{config['name']} *",
            is_fixed=False,
            switch_to=True,
            profile=self.profile
        )


    def focus_or_open_fixed_tab(self, config, url_str):
        existing = self.find_open_fixed_tab_by_name(config["name"])
        if existing:
            self.tab_widget.setCurrentWidget(existing["view"])
            existing["view"].setUrl(QUrl(url_str))
            return existing["view"]

        self.add_browser_tab(
            config=config,
            title=config["name"],
            is_fixed=True,
            switch_to=True,
            initial_url=url_str,
            profile=self.profile
        )
        return None

    def _handle_custom_tab_close(self, view):
        if not view:
            return
        index = self.tab_widget.indexOf(view)
        if index >= 0:
            self.handle_tab_close_requested(index)

    def _refresh_tab_close_buttons(self):
        tab_bar = self.tab_widget.tabBar()
        if not tab_bar:
            return

        for idx, meta in enumerate(self.tab_views):
            view = meta.get("view")
            if meta.get("is_fixed"):
                tab_bar.setTabButton(idx, QTabBar.ButtonPosition.RightSide, None)
                continue

            existing = tab_bar.tabButton(idx, QTabBar.ButtonPosition.RightSide)
            if (
                isinstance(existing, QPushButton) and
                existing.property("tab_view_id") == id(view)
            ):
                continue

            btn = QPushButton("x", tab_bar)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setToolTip("Close tab")
            btn.setFixedSize(22, 22)
            btn.setProperty("tab_view_id", id(view))
            btn.setStyleSheet("""
                QPushButton {
                    background: #f4f8ff;
                    color: #335789;
                    border: 1px solid #c7d7f2;
                    border-radius: 11px;
                    padding: 0px;
                    font-size: 12px;
                    font-weight: 800;
                }
                QPushButton:hover {
                    background: #e4eeff;
                    color: #17386a;
                }
                QPushButton:pressed {
                    background: #d5e4ff;
                }
            """)
            btn.clicked.connect(lambda _checked=False, v=view: self._handle_custom_tab_close(v))
            tab_bar.setTabButton(idx, QTabBar.ButtonPosition.RightSide, btn)


    def close_web_view_tab(self, view):
        index = self.tab_widget.indexOf(view)
        if index == -1:
            return

        tab_meta = self.find_tab_meta_by_view(view)
        if tab_meta and tab_meta.get("is_fixed"):
            return

        self.tab_views = [t for t in self.tab_views if t["view"] != view]
        self.tab_widget.removeTab(index)
        view.deleteLater()
        self._refresh_tab_close_buttons()

        if tab_meta and tab_meta["name"] == "WhatsApp":
            self.save_whatsapp_tabs_state()


    def handle_tab_close_requested(self, index):
        widget = self.tab_widget.widget(index)
        if widget is None:
            return

        if not isinstance(widget, QWebEngineView):
            self.tab_widget.removeTab(index)
            widget.deleteLater()
            return

        tab_meta = self.find_tab_meta_by_view(widget)
        if tab_meta and tab_meta.get("is_fixed"):
            return

        if self._bulk_processing and widget == self._bulk_target_view:
            label = self._format_whatsapp_label(self._bulk_target_account_id)
            QMessageBox.information(
                self,
                "Cannot Close Tab",
                f"{label} is currently running a bulk blast.\n\nPlease wait until it finishes."
            )
            return

        if self._wa_sync_processing and widget == self._wa_sync_target_view:
            label = self._format_whatsapp_label(self._wa_sync_target_account_id)
            QMessageBox.information(
                self,
                "Cannot Close Tab",
                f"{label} is currently running a WhatsApp history sync.\n\nPlease wait until it finishes."
            )
            return

        if tab_meta and tab_meta["name"] == "WhatsApp":
            wa_count = sum(1 for t in self.tab_views if t["name"] == "WhatsApp")
            if wa_count <= 1:
                QMessageBox.information(
                    self,
                    "Cannot Close",
                    "At least one WhatsApp account tab must remain."
                )
                return

            removed = self._remove_queued_jobs_for_view(widget)
            if removed > 0:
                QMessageBox.information(
                    self,
                    "Queued Job Removed",
                    f"Removed {removed} queued bulk blast(s) for this WhatsApp tab."
                )

        self.close_web_view_tab(widget)

    def get_config_by_name(self, name):
        for config in TAB_CONFIG:
            if config["name"] == name:
                return config
        return None

    def create_new_tab_for_group(self, group_name):
        config = self.get_config_by_name(group_name)
        if not config:
            return None

        return self.add_browser_tab(
            config=config,
            title=f"{group_name} (new)",
            is_fixed=False,
            switch_to=True
        )
    
    def find_tab_by_name(self, name):
        for tab in self.tab_views:
            if tab["name"] == name:
                return tab
        return None

    def install_capture_and_network_script(self, profile=None):
        profile = profile or self.profile
        script_source = r"""
        (function() {
            if (window.__captureAndLogInstalled) return;
            window.__captureAndLogInstalled = true;

            window.__networkLogs = [];
            window.__apiTableCandidates = [];

            const MAX_LOGS = 200;
            const MAX_API_ITEMS = 50;

            function truncate(value, maxLen) {
                maxLen = maxLen || 4000;
                if (typeof value === "string" && value.length > maxLen) {
                    return value.slice(0, maxLen) + "... [truncated]";
                }
                return value;
            }

            function addLog(entry) {
                try {
                    entry.ts = new Date().toISOString();
                    window.__networkLogs.unshift(entry);
                    if (window.__networkLogs.length > MAX_LOGS) {
                        window.__networkLogs.length = MAX_LOGS;
                    }
                } catch (e) {}
            }

            function rememberApi(entry) {
                try {
                    window.__apiTableCandidates.unshift(entry);
                    if (window.__apiTableCandidates.length > MAX_API_ITEMS) {
                        window.__apiTableCandidates.length = MAX_API_ITEMS;
                    }
                } catch (e) {}
            }

            function isCollectionApi(rawUrl) {
                try {
                    const u = new URL(rawUrl, window.location.href);
                    return u.hostname === "collection.pendanaan.com";
                } catch (e) {
                    return false;
                }
            }

            function maybeStoreCollectionApi(url, method, status, headersObj, text) {
                try {
                    if (!isCollectionApi(url)) return;

                    let parsed = null;
                    try {
                        parsed = JSON.parse(text);
                    } catch (e) {
                        return;
                    }

                    rememberApi({
                        ts: new Date().toISOString(),
                        method: method || "GET",
                        url: url,
                        status: status,
                        headers: headersObj || {},
                        payload: parsed
                    });
                } catch (e) {}
            }

            const origFetch = window.fetch;
            window.fetch = function(input, init) {
                const url = typeof input === "string" ? input : input.url;
                const method = (init && init.method) || "GET";
                const requestHeaders = (init && init.headers) || {};
                const requestBody = (init && init.body) || null;

                return origFetch.apply(this, arguments).then(async response => {
                    try {
                        const cloned = response.clone();
                        const responseHeaders = {};
                        cloned.headers.forEach((value, key) => {
                            responseHeaders[key] = value;
                        });

                        let responseBody = null;
                        const contentType = (cloned.headers.get("content-type") || "").toLowerCase();

                        if (contentType.includes("json") || contentType.includes("text") || contentType.includes("javascript")) {
                            responseBody = await cloned.text();
                        } else {
                            responseBody = "[binary data]";
                        }

                        addLog({
                            type: "fetch",
                            method: method,
                            url: url,
                            requestHeaders: requestHeaders,
                            requestBody: requestBody ? truncate(String(requestBody)) : null,
                            responseStatus: cloned.status,
                            responseHeaders: responseHeaders,
                            responseBody: responseBody ? truncate(responseBody) : null
                        });

                        if (typeof responseBody === "string") {
                            maybeStoreCollectionApi(url, method, cloned.status, responseHeaders, responseBody);
                        }
                    } catch (e) {}
                    return response;
                });
            };

            const OrigXHR = window.XMLHttpRequest;
            function XHRWrapper() {
                const xhr = new OrigXHR();
                let method = "GET";
                let url = "";
                let requestHeaders = {};
                let requestBody = null;

                const origOpen = xhr.open;
                xhr.open = function(m, u) {
                    method = m || "GET";
                    url = u || "";
                    return origOpen.apply(xhr, arguments);
                };

                const origSetRequestHeader = xhr.setRequestHeader;
                xhr.setRequestHeader = function(header, value) {
                    requestHeaders[header] = value;
                    return origSetRequestHeader.apply(xhr, arguments);
                };

                const origSend = xhr.send;
                xhr.send = function(body) {
                    requestBody = body;
                    return origSend.call(xhr, body);
                };

                xhr.addEventListener("loadend", function() {
                    try {
                        const headersRaw = xhr.getAllResponseHeaders() || "";
                        const headersObj = {};
                        headersRaw.trim().split(/[\r\n]+/).forEach(line => {
                            const parts = line.split(": ");
                            const key = parts.shift();
                            const value = parts.join(": ");
                            if (key) headersObj[key.toLowerCase()] = value;
                        });

                        const text = (xhr.responseType === "" || xhr.responseType === "text")
                            ? xhr.responseText
                            : "[non-text response]";

                        addLog({
                            type: "xhr",
                            method: method,
                            url: url,
                            requestHeaders: requestHeaders,
                            requestBody: requestBody ? truncate(String(requestBody)) : null,
                            responseStatus: xhr.status,
                            responseHeaders: headersObj,
                            responseBody: text ? truncate(String(text)) : null
                        });

                        if (typeof text === "string" && text !== "[non-text response]") {
                            maybeStoreCollectionApi(url, method, xhr.status, headersObj, text);
                        }
                    } catch (e) {}
                });

                return xhr;
            }
            window.XMLHttpRequest = XHRWrapper;

            const OrigWebSocket = window.WebSocket;
            function WebSocketWrapper(url, protocols) {
                const ws = new OrigWebSocket(url, protocols);
                const logEntry = {
                    type: "websocket",
                    url: url,
                    messages: []
                };
                addLog(logEntry);

                const origSend = ws.send;
                ws.send = function(data) {
                    logEntry.messages.push({
                        direction: "sent",
                        data: truncate(String(data))
                    });
                    return origSend.call(ws, data);
                };

                ws.addEventListener("message", function(event) {
                    logEntry.messages.push({
                        direction: "received",
                        data: truncate(String(event.data))
                    });
                });

                return ws;
            }
            window.WebSocket = WebSocketWrapper;
        })();
        """
        script = QWebEngineScript()
        script.setName("capture_and_network")
        script.setSourceCode(script_source)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        profile.scripts().insert(script)

    def install_whatsapp_manual_send_logger(self, profile=None):
        profile = profile or self.profile
        script_source = r"""
        (function() {
            if (window.__waManualSendLoggerInstalled) return;
            window.__waManualSendLoggerInstalled = true;

            if (location.hostname !== "web.whatsapp.com") return;

            window.__waManualSendLogs = window.__waManualSendLogs || [];
            window.__waManualPendingSig = null;
            window.__waManualPendingAt = 0;

            const COMPOSE_SELECTORS = [
                'footer div[contenteditable="true"][data-testid="conversation-compose-box-input"]',
                'main footer div[contenteditable="true"][data-testid="conversation-compose-box-input"]',
                'footer div[contenteditable="true"][role="textbox"]',
                'main footer div[contenteditable="true"][role="textbox"]',
                'footer div[contenteditable="true"]',
                'main footer div[contenteditable="true"]'
            ];

            const SEND_BUTTON_SELECTORS = [
                'footer button[aria-label="Send"]',
                'footer button[data-testid="compose-btn-send"]',
                'footer span[data-icon="send"]',
                'footer span[data-icon="wds-ic-send-filled"]',
                'button[aria-label="Send"]',
                'button[data-testid="compose-btn-send"]',
                'span[data-icon="send"]',
                'span[data-icon="wds-ic-send-filled"]'
            ];

            function pushLog(entry) {
                try {
                    window.__waManualSendLogs.unshift(entry);
                    if (window.__waManualSendLogs.length > 300) {
                        window.__waManualSendLogs.length = 300;
                    }
                } catch (e) {}
            }

            function getComposeText(el) {
                return ((el?.innerText || el?.textContent || "").replace(/\u00A0/g, " ")).trim();
            }

            function findComposeBox() {
                for (const sel of COMPOSE_SELECTORS) {
                    const candidates = Array.from(document.querySelectorAll(sel));
                    for (const el of candidates) {
                        if (!el) continue;

                        const footer = el.closest("footer");
                        if (!footer) continue;

                        const meta = (
                            (el.getAttribute("aria-label") || "") + " " +
                            (el.getAttribute("aria-placeholder") || "") + " " +
                            (el.getAttribute("data-testid") || "")
                        ).toLowerCase();

                        if (meta.includes("search")) continue;

                        const rect = el.getBoundingClientRect();
                        if (rect.width < 80 || rect.height < 20) continue;

                        return el;
                    }
                }
                return null;
            }

            function normalizeText(value) {
                return String(value || "")
                    .replace(/\u200e/g, "")
                    .replace(/\u00A0/g, " ")
                    .replace(/\r/g, "")
                    .replace(/[ \t]+\n/g, "\n")
                    .replace(/\n[ \t]+/g, "\n")
                    .replace(/[ \t]{2,}/g, " ")
                    .trim();
            }

            function normalizePhone(raw) {
                const digits = String(raw || "").replace(/\D/g, "");
                if (!digits) return "";

                if (digits.startsWith("0") && digits.length >= 8) {
                    return "62" + digits.slice(1);
                }
                if (digits.startsWith("62") && digits.length >= 8) {
                    return digits;
                }
                if (digits.length >= 8) {
                    return digits;
                }
                return "";
            }

            function extractPhone(raw) {
                const text = String(raw || "");

                const jidMatch = text.match(/(\d{8,20})@(?:c|s)\.us/i);
                if (jidMatch) return normalizePhone(jidMatch[1]);

                const phoneish = text.match(/(?:\+|00)?\d[\d\s\-()]{7,20}\d/);
                if (phoneish) return normalizePhone(phoneish[0]);

                return "";
            }

            function getHeaderChatTitle() {
                const selectors = [
                    'header [data-testid="conversation-info-header-chat-title"]',
                    'header h1',
                    'header span[title]',
                    'header div[title]'
                ];

                const banned = new Set([
                    "profile",
                    "info",
                    "search",
                    "menu",
                    "more",
                    "whatsapp",
                    "click here for contact info",
                    "contact info",
                    "click for contact info"
                ]);

                for (const sel of selectors) {
                    const nodes = Array.from(document.querySelectorAll(sel));
                    for (const el of nodes) {
                        const text = normalizeText(el.getAttribute("title") || el.textContent || "");
                        if (!text) continue;
                        if (banned.has(text.toLowerCase())) continue;
                        return text;
                    }
                }

                return "";
            }

            function getPhoneFromPageContext() {
                try {
                    const p = new URLSearchParams(location.search).get("phone");
                    const phone = extractPhone(p);
                    if (phone) return phone;
                } catch (e) {}

                const nodes = Array.from(document.querySelectorAll(".message-in, .message-out")).slice(-30).reverse();

                try {
                    const links = Array.from(document.querySelectorAll('a[href], div[data-id], span[data-id]'));
                    for (const el of links) {
                        const phone = extractPhone(
                            el.getAttribute("href") ||
                            el.getAttribute("data-id") ||
                            ""
                        );
                        if (phone) return phone;
                    }
                } catch (e) {}
                for (const msgEl of nodes) {
                    const prePlainEl = msgEl.querySelector("[data-pre-plain-text]");
                    const candidates = [
                        msgEl.getAttribute("data-id") || "",
                        msgEl.getAttribute("data-pre-plain-text") || "",
                        prePlainEl ? (prePlainEl.getAttribute("data-pre-plain-text") || "") : "",
                        msgEl.innerText || msgEl.textContent || ""
                    ];

                    for (const candidate of candidates) {
                        const phone = extractPhone(candidate);
                        if (phone) return phone;
                    }
                }

                const headerTitle = getHeaderChatTitle();
                return extractPhone(headerTitle);
            }

            function getCurrentRecipientInfo() {
                const title = getHeaderChatTitle();
                let phone = getPhoneFromPageContext();

                if (!phone && title && window.__waContactInfoCache && window.__waContactInfoCache[title.toLowerCase()]) {
                    phone = window.__waContactInfoCache[title.toLowerCase()];
                }

                const label = phone || title || "";
                const key = phone || (title ? title.toLowerCase() : "");
                return { phone, label, key };
            }

            function hasAttachmentInComposer() {
                return !!document.querySelector(
                    'footer img[src^="blob:"], footer video[src^="blob:"], footer canvas, footer [data-testid*="media"]'
                );
            }

            function isBulkRunning() {
                return !!(window.__waAutoSendState && window.__waAutoSendState.status === "running");
            }

            function matchesSendButton(target) {
                if (!target) return false;
                for (const sel of SEND_BUTTON_SELECTORS) {
                    try {
                        if (target.closest(sel)) return true;
                    } catch (e) {}
                }
                return false;
            }

            function consumeRecentBadWordScan(messageContent) {
                try {
                    const scan = window.__waLastBadWordScan;
                    if (!scan) {
                        return { bad_word_count: 0, bad_words: [], bad_word_hits: [] };
                    }

                    const scanTs = new Date(scan.ts || 0).getTime();
                    if (!scanTs || (Date.now() - scanTs) > 15000) {
                        return { bad_word_count: 0, bad_words: [], bad_word_hits: [] };
                    }

                    const originalContent = String(scan.original_content || "").trim();
                    const maskedContent = String(scan.masked_content || "").trim();
                    const currentContent = String(messageContent || "").trim();

                    const matchesOriginal = originalContent && originalContent === currentContent;
                    const matchesMasked = maskedContent && maskedContent === currentContent;

                    if ((originalContent || maskedContent) && !matchesOriginal && !matchesMasked) {
                        return { bad_word_count: 0, bad_words: [], bad_word_hits: [] };
                    }

                    window.__waLastBadWordScan = null;

                    return {
                        bad_word_count: parseInt(scan.bad_word_count || 0, 10) || 0,
                        bad_words: Array.isArray(scan.bad_words) ? scan.bad_words : [],
                        bad_word_hits: Array.isArray(scan.bad_word_hits) ? scan.bad_word_hits : []
                    };
                } catch (e) {
                    return { bad_word_count: 0, bad_words: [], bad_word_hits: [] };
                }
            }

            function queueManualSendLog(trigger) {
                if (isBulkRunning()) return;

                const composeBox = findComposeBox();
                if (!composeBox) return;

                const text = getComposeText(composeBox);
                const attachmentFlag = hasAttachmentInComposer();

                if (!text && !attachmentFlag) return;

                const messageContent = text || "";
                const messageLength = messageContent.length;

                const recipientInfo = getCurrentRecipientInfo();
                const now = Date.now();
                const signature = JSON.stringify({
                    to: recipientInfo.key || recipientInfo.phone || recipientInfo.label || "",
                    content: messageContent,
                    has_attachment: attachmentFlag,
                    trigger: trigger
                });

                if (
                    window.__waManualPendingSig === signature &&
                    (now - window.__waManualPendingAt) < 2000
                ) {
                    return;
                }

                window.__waManualPendingSig = signature;
                window.__waManualPendingAt = now;

                let attempts = 0;

                function finalizeManualSendCheck() {
                    if (isBulkRunning()) {
                        window.__waManualPendingSig = null;
                        window.__waManualPendingAt = 0;
                        return;
                    }

                    const afterBox = findComposeBox() || composeBox;
                    const remainingText = getComposeText(afterBox);
                    const remainingAttachment = hasAttachmentInComposer();

                    if ((remainingText || remainingAttachment) && attempts < 5) {
                        attempts += 1;
                        setTimeout(finalizeManualSendCheck, 1000);
                        return;
                    }

                    if (remainingText || remainingAttachment) {
                        window.__waManualPendingSig = null;
                        window.__waManualPendingAt = 0;
                        return;
                    }

                    const badWordMeta = consumeRecentBadWordScan(messageContent);

                    const sig = JSON.stringify({
                        to: recipientInfo.key || recipientInfo.phone || recipientInfo.label || "",
                        content: messageContent,
                        has_attachment: attachmentFlag,
                        trigger: trigger,
                        sent_at: new Date().toISOString()
                    });

                    pushLog({
                        ts: new Date().toISOString(),
                        to: recipientInfo.phone || recipientInfo.label || "",
                        to_phone: recipientInfo.phone || "",
                        conversation_key: recipientInfo.key || "",
                        content: messageContent,
                        message_length: messageLength,
                        has_attachment: attachmentFlag,
                        trigger: trigger,
                        bad_word_count: badWordMeta.bad_word_count,
                        bad_words: badWordMeta.bad_words,
                        bad_word_hits: badWordMeta.bad_word_hits
                    });

                    window.__waManualPendingSig = null;
                    window.__waManualPendingAt = 0;
                }

                setTimeout(finalizeManualSendCheck, 1800);
            }

            document.addEventListener("click", function(e) {
                if (matchesSendButton(e.target)) {
                    queueManualSendLog("click");
                }
            }, true);

            document.addEventListener("keydown", function(e) {
                if (e.key !== "Enter" || e.shiftKey) return;

                const composeBox = findComposeBox();
                if (!composeBox) return;

                if (composeBox === e.target || composeBox.contains(e.target)) {
                    queueManualSendLog("enter");
                }
            }, true);
        })();
        """
        script = QWebEngineScript()
        script.setName("wa_manual_send_logger")
        script.setSourceCode(script_source)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        profile.scripts().insert(script)

    def install_whatsapp_cashier_mode_guard(self, profile=None):
        profile = profile or self.profile
        script_source = r"""
        (function() {
            if (window.__waCashierModeGuardInstalled) return;
            window.__waCashierModeGuardInstalled = true;

            if (location.hostname !== "web.whatsapp.com") return;

            window.__waCashierModeEnabled = !!window.__waCashierModeEnabled;

            const COMPOSE_SELECTORS = [
                'footer div[contenteditable="true"][data-testid="conversation-compose-box-input"]',
                'main footer div[contenteditable="true"][data-testid="conversation-compose-box-input"]',
                'footer div[contenteditable="true"][role="textbox"]',
                'main footer div[contenteditable="true"][role="textbox"]',
                'footer div[contenteditable="true"]',
                'main footer div[contenteditable="true"]'
            ];

            function findComposeBox() {
                for (const sel of COMPOSE_SELECTORS) {
                    const candidates = Array.from(document.querySelectorAll(sel));
                    for (const el of candidates) {
                        if (!el) continue;
                        const footer = el.closest("footer");
                        if (!footer) continue;

                        const meta = (
                            (el.getAttribute("aria-label") || "") + " " +
                            (el.getAttribute("aria-placeholder") || "") + " " +
                            (el.getAttribute("data-testid") || "")
                        ).toLowerCase();

                        if (meta.includes("search")) continue;
                        return el;
                    }
                }
                return null;
            }

            function ensureBanner() {
                let banner = document.getElementById("__ptn_cashier_mode_banner");
                if (!window.__waCashierModeEnabled) {
                    if (banner) banner.remove();
                    return;
                }

                if (!banner) {
                    banner = document.createElement("div");
                    banner.id = "__ptn_cashier_mode_banner";
                    banner.style.position = "fixed";
                    banner.style.right = "14px";
                    banner.style.bottom = "86px";
                    banner.style.zIndex = "2147483647";
                    banner.style.background = "rgba(255,243,205,0.96)";
                    banner.style.color = "#664d03";
                    banner.style.border = "1px solid #ffe69c";
                    banner.style.borderRadius = "10px";
                    banner.style.padding = "8px 10px";
                    banner.style.fontSize = "12px";
                    banner.style.fontFamily = "Arial, sans-serif";
                    banner.style.fontWeight = "700";
                    banner.style.pointerEvents = "none";
                    banner.textContent = "Cashier mode active. Use Reply Template.";
                    document.body.appendChild(banner);
                }
            }

            function applyComposeVisual() {
                const composeBox = findComposeBox();
                if (!composeBox) {
                    ensureBanner();
                    return;
                }

                if (window.__waCashierModeEnabled) {
                    composeBox.style.setProperty("background", "rgba(255, 243, 205, 0.35)", "important");
                    composeBox.style.setProperty("caret-color", "transparent", "important");
                } else {
                    composeBox.style.removeProperty("background");
                    composeBox.style.removeProperty("caret-color");
                }

                ensureBanner();
            }

            function isComposeTarget(target) {
                const composeBox = findComposeBox();
                if (!composeBox || !target) return false;
                return target === composeBox || composeBox.contains(target);
            }

            function shouldBlockKey(e) {
                if (e.key === "Enter" && !e.shiftKey) return false;
                if (e.key === "Tab") return false;
                if (e.key.startsWith("Arrow")) return false;
                if (e.key === "Home" || e.key === "End" || e.key === "PageUp" || e.key === "PageDown") return false;
                if (e.key === "Escape") return false;
                return true;
            }

            function blockEvent(e) {
                if (!window.__waCashierModeEnabled) return;
                if (!isComposeTarget(e.target)) return;
                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();
                applyComposeVisual();
                return false;
            }

            document.addEventListener("beforeinput", blockEvent, true);
            document.addEventListener("paste", blockEvent, true);
            document.addEventListener("drop", blockEvent, true);
            document.addEventListener("keydown", function(e) {
                if (!window.__waCashierModeEnabled) return;
                if (!isComposeTarget(e.target)) return;
                if (!shouldBlockKey(e)) return;
                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();
                applyComposeVisual();
            }, true);

            window.addEventListener("__ptn_cashier_mode_changed", function() {
                setTimeout(applyComposeVisual, 0);
            });

            const obs = new MutationObserver(function() {
                applyComposeVisual();
            });

            function start() {
                applyComposeVisual();
                try {
                    obs.observe(document.documentElement || document.body, {
                        childList: true,
                        subtree: true
                    });
                } catch (e) {}

                setInterval(applyComposeVisual, 1200);
            }

            if (document.readyState === "loading") {
                document.addEventListener("DOMContentLoaded", start, { once: true });
            } else {
                start();
            }
        })();
        """
        script = QWebEngineScript()
        script.setName("wa_cashier_mode_guard")
        script.setSourceCode(script_source)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        profile.scripts().insert(script)
            
    def open_detected_api_picker(self):
        current = self.tab_widget.currentWidget()

        if not isinstance(current, QWebEngineView):
            QMessageBox.information(
                self,
                "Open a Web Tab",
                "Switch to the Collection web tab first."
            )
            return

        current_host = (urlparse(current.url().toString()).hostname or "").lower()
        if current_host != "collection.pendanaan.com":
            QMessageBox.information(
                self,
                "Collection Only",
                "This feature only works while viewing collection.pendanaan.com."
            )
            return

        js = """
        (function() {
            const items = window.__apiTableCandidates || [];
            return JSON.stringify(items.map((x, i) => ({
                index: i,
                method: x.method,
                status: x.status,
                url: x.url,
                ts: x.ts
            })));
        })();
        """
        current.page().runJavaScript(js, self.handle_detected_api_list)

    def handle_detected_api_list(self, result):
        if not result:
            QMessageBox.information(self, "No APIs", "No detected JSON APIs yet.")
            return

        try:
            apis = json.loads(result)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to read detected APIs: {e}")
            return

        if not apis:
            QMessageBox.information(self, "No APIs", "No detected JSON APIs yet.")
            return

        dlg = ApiPickerDialog(apis, self)
        if dlg.exec() != QDialog.DialogCode.Accepted or dlg.selected_index is None:
            return

        selected = apis[dlg.selected_index]
        current = self.tab_widget.currentWidget()

        js = f"""
        (function() {{
            const items = window.__apiTableCandidates || [];
            const item = items[{selected["index"]}];
            return JSON.stringify(item || null);
        }})();
        """
        current.page().runJavaScript(js, self.open_sheet_from_captured_api)

    def open_sheet_from_captured_api(self, result):
        if not result:
            QMessageBox.warning(self, "Error", "No captured API payload was returned.")
            return

        try:
            item = json.loads(result)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to parse captured API payload: {e}")
            return

        if not item:
            QMessageBox.warning(self, "Error", "Selected API payload is no longer available.")
            return

        api_url = item.get("url", "Captured API")
        payload = item.get("payload", {})
        status = item.get("status", "")

        sheet = ApiSheetTab(
            api_url=api_url,
            admin_password=ADMIN_PASSWORD,
            refresh_callback=lambda sw: None,   # optional: disable refresh
            close_callback=self.close_dynamic_tab,
            parent=self
        )
        sheet.refresh_btn.setVisible(False)  # no refetch
        sheet.set_payload(payload, status_text=f"Locked view. Captured response. HTTP {status}")

        tab_title = f"Sheet: {urlparse(api_url).path or '/'}"
        self.tab_widget.addTab(sheet, tab_title)
        self.tab_widget.setCurrentWidget(sheet)

    def close_dynamic_tab(self, widget):
        index = self.tab_widget.indexOf(widget)
        if index != -1:
            self.tab_widget.removeTab(index)
            widget.deleteLater()

    def create_tab_view(self, config):
        page = CustomWebEnginePage(self.profile, config["name"], self)
        view = QWebEngineView()
        view.setPage(page)

        view.setContextMenuPolicy(Qt.ContextMenuPolicy.DefaultContextMenu)
        view.page().setDevToolsPage(None)

        view.urlChanged.connect(lambda url, v=view: self.enforce_tab_allowed_sites(url, v))
        view.loadFinished.connect(lambda ok, v=view, name=config["name"]: self.record_tab_history(ok, v))
        view.loadFinished.connect(lambda ok, p=page, name=config["name"]:
                                p.runJavaScript(f"window._tabName = {json.dumps(name)};"))

        return view

    def enforce_tab_allowed_sites(self, url, view):
        tab = self.find_tab_meta_by_view(view)
        if not tab:
            return

        current = url.toString()
        if not host_allowed(current, tab["allowed_sites"]):
            # safety fallback only
            if tab.get("is_fixed"):
                view.setUrl(QUrl(tab["home"]))
            else:
                self.close_web_view_tab(view)
            self.status_bar.showMessage(
                f"Navigation blocked – only {tab['name']} sites allowed.",
                3000
            )

    def record_tab_history(self, ok, view):
        if not ok:
            return
        tab_name = "Unknown"
        for tab in self.tab_views:
            if tab["view"] == view:
                tab_name = self.tab_widget.tabText(self.tab_widget.indexOf(view))
                break
        url = view.url().toString()
        title = view.page().title()
        now = datetime.datetime.now(USER_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "timestamp": now,
            "tab": tab_name,
            "url": url,
            "title": title,
            "event": "page_load"
        }
        save_history(entry)
        self.status_bar.showMessage(f"[{tab_name}] Loaded: {title[:50]}...", 2000)

    # ---------- JavaScript injection ----------
    def install_geolocation_script(self, profile=None):
        profile = profile or self.profile
        lat, lon = self.coords

        script_source = f"""
        (function() {{
            var fakeCoords = {{
                latitude: {lat},
                longitude: {lon},
                accuracy: 10,
                altitude: null,
                altitudeAccuracy: null,
                heading: null,
                speed: null
            }};
            var fakePosition = {{
                coords: fakeCoords,
                timestamp: Date.now()
            }};

            navigator.geolocation.getCurrentPosition = function(success, error, options) {{
                if (success) success(fakePosition);
            }};
            navigator.geolocation.watchPosition = function(success, error, options) {{
                if (success) success(fakePosition);
                return 0;
            }};
        }})();
        """
        script = QWebEngineScript()
        script.setName("geolocation_spoof")
        script.setSourceCode(script_source)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        profile.scripts().insert(script)

    def install_stealth_script(self, profile=None):
        profile = profile or self.profile

        script_source = """
        (function() {
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
                configurable: true
            });
        })();
        """
        script = QWebEngineScript()
        script.setName("stealth")
        script.setSourceCode(script_source)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        profile.scripts().insert(script)

    def show_bad_word_stats(self):
        if not self.require_admin_password():
            QMessageBox.warning(self, "Error", "Incorrect password.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Bad Word Daily Counter")
        dlg.setGeometry(240, 240, 1180, 720)

        layout = QVBoxLayout(dlg)

        info = QLabel(
            "This view shows encrypted daily bad-word counts from outgoing messages only.\n"
            "Source shows which WhatsApp tab/account produced the bad-word event, and detail now includes sender and receiver information."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)

        day_table = QTableWidget(0, 7, self)
        prepare_plain_table_widget(
            day_table,
            ["Day", "Hits", "Events", "Top Words", "Top Sources", "Top Senders", "Top Receivers"],
            stretch_last=False
        )
        day_table.setColumnWidth(0, 110)
        day_table.setColumnWidth(1, 70)
        day_table.setColumnWidth(2, 70)
        day_table.setColumnWidth(3, 220)
        day_table.setColumnWidth(4, 220)
        day_table.setColumnWidth(5, 220)
        day_table.setColumnWidth(6, 220)
        splitter.addWidget(day_table)

        detail_box = QTextEdit(self)
        detail_box.setReadOnly(True)
        splitter.addWidget(detail_box)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)

        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("Refresh")
        close_btn = QPushButton("Close")
        btn_row.addStretch()
        btn_row.addWidget(refresh_btn)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

        def render():
            days = load_bad_word_counter().get("days", {})
            rows = sorted(days.items(), key=lambda x: x[0], reverse=True)
            day_table.setRowCount(len(rows))

            for row_index, (day, bucket) in enumerate(rows):
                by_word = dict(bucket.get("by_word", {}))
                by_source = dict(bucket.get("by_source", {}))
                by_sender = dict(bucket.get("by_sender", {}))
                by_receiver = dict(bucket.get("by_receiver", {}))

                top_words = sorted(by_word.items(), key=lambda x: x[1], reverse=True)[:5]
                top_sources = sorted(by_source.items(), key=lambda x: x[1], reverse=True)[:5]
                top_senders = sorted(by_sender.items(), key=lambda x: x[1], reverse=True)[:5]
                top_receivers = sorted(by_receiver.items(), key=lambda x: x[1], reverse=True)[:5]

                top_words_text = ", ".join(f"{w}({c})" for w, c in top_words) if top_words else "-"
                top_sources_text = ", ".join(f"{src}({c})" for src, c in top_sources) if top_sources else "-"
                top_senders_text = ", ".join(f"{src}({c})" for src, c in top_senders) if top_senders else "-"
                top_receivers_text = ", ".join(f"{dst}({c})" for dst, c in top_receivers) if top_receivers else "-"

                day_table.setItem(row_index, 0, make_table_item(day, user_data=day))
                day_table.setItem(row_index, 1, make_table_item(str(bucket.get("total_hits", 0))))
                day_table.setItem(row_index, 2, make_table_item(str(bucket.get("events", 0))))
                day_table.setItem(row_index, 3, make_table_item(top_words_text))
                day_table.setItem(row_index, 4, make_table_item(top_sources_text))
                day_table.setItem(row_index, 5, make_table_item(top_senders_text))
                day_table.setItem(row_index, 6, make_table_item(top_receivers_text))

            if day_table.rowCount() > 0:
                select_first_table_row(day_table)
                update_detail()
            else:
                detail_box.clear()

        def update_detail():
            row = day_table.currentRow()
            if row < 0:
                detail_box.clear()
                return

            days = load_bad_word_counter().get("days", {})
            day_item = day_table.item(row, 0)
            day = str(day_item.data(Qt.ItemDataRole.UserRole) or "") if day_item else ""
            detail_payload = make_timestamps_display_friendly(days.get(day, {}))
            detail_box.setPlainText(json.dumps(detail_payload, indent=2, ensure_ascii=False))

        day_table.itemSelectionChanged.connect(update_detail)
        refresh_btn.clicked.connect(render)
        close_btn.clicked.connect(dlg.accept)

        render()
        dlg.exec()

    # ---------- Periodic network log fetching ----------
    def fetch_network_logs(self):
        for tab in self.tab_views:
            tab["view"].page().runJavaScript(
                """
                (function() {
                    const logs = window.__networkLogs || [];
                    window.__networkLogs = [];
                    return JSON.stringify(logs);
                })();
                """,
                self.handle_network_logs
            )

    def handle_network_logs(self, result):
        if not result:
            return

        try:
            logs = json.loads(result)
            enriched = []

            for entry in logs:
                if not isinstance(entry, dict):
                    continue

                entry["proxy_snapshot"] = dict(self.proxy_info)
                entry["via_proxy"] = bool(self.proxy_info.get("enabled"))

                # Important honesty note:
                # via_proxy=True means the browser had global proxy enabled when this log was captured.
                # It is not a deep packet-level proof that the remote server actually accepted the proxy route.
                enriched.append(entry)

            append_network_logs(enriched)
        except Exception as e:
            print("Error processing network logs:", e)

    def repair_whatsapp_history_records(self, quiet=True):
        logs = load_manual_send_log()
        repaired_logs, changed = repair_whatsapp_history_log_entries(
            logs,
            bad_words=load_bad_words()
        )

        if changed:
            write_manual_send_log(repaired_logs)
            try:
                self.refresh_performance_dock()
            except Exception:
                pass
            if not quiet:
                self.status_bar.showMessage("WhatsApp history records repaired.", 4000)

        return repaired_logs, changed

    def export_whatsapp_history_rows_to_excel(self, rows, suggested_name="whatsapp_histories.xlsx"):
        rows = [row for row in list(rows or []) if isinstance(row, dict)]
        if not rows:
            QMessageBox.information(self, "No Histories", "There are no histories to export.")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export WhatsApp Histories",
            suggested_name,
            "Excel Files (*.xlsx)"
        )
        if not save_path:
            return

        try:
            if not save_path.lower().endswith(".xlsx"):
                save_path += ".xlsx"

            ordered_rows = sorted(rows, key=lambda row: (row.get("sort_key"), row.get("index", 0)))
            export_rows = []
            for row in ordered_rows:
                export_rows.append({
                    "timestamp": row.get("timestamp_display") or "-",
                    "direction": row.get("direction") or "",
                    "send_type": row.get("send_type") or "",
                    "status": row.get("status") or "",
                    "contact_display": row.get("contact_display") or "",
                    "contact_phone": row.get("contact_phone") or "",
                    "account": row.get("self_account") or "",
                    "from": row.get("from_text") or "",
                    "to": row.get("to_text") or "",
                    "conversation_key": row.get("conversation_key") or "",
                    "trigger": row.get("trigger") or "",
                    "message_length": int(row.get("message_length") or 0),
                    "has_attachment": bool(row.get("has_attachment")),
                    "bad_word_count": int(row.get("bad_word_count") or 0),
                    "bad_words": row.get("bad_words_text") or "",
                    "reply_speed": row.get("reply_speed_hms") or "",
                    "message_author": row.get("message_author") or "",
                    "content": row.get("content") or ""
                })

            summaries = build_whatsapp_conversation_summaries(ordered_rows)
            summary_rows = []
            for summary in summaries:
                summary_rows.append({
                    "contact_display": summary.get("contact_display") or "",
                    "contact_phone": summary.get("contact_phone") or "",
                    "conversation_key": summary.get("contact_key") or "",
                    "total_messages": int(summary.get("total_count") or 0),
                    "sent_messages": int(summary.get("sent_count") or 0),
                    "received_messages": int(summary.get("received_count") or 0),
                    "first_message_at": format_user_datetime_text(summary.get("first_timestamp"), default="-"),
                    "last_message_at": format_user_datetime_text(summary.get("last_timestamp"), default="-"),
                    "accounts": summary.get("self_accounts_text") or "",
                    "last_preview": summary.get("last_preview") or ""
                })

            with pd.ExcelWriter(save_path, engine="openpyxl") as writer:
                pd.DataFrame(export_rows).to_excel(writer, index=False, sheet_name="Messages")
                pd.DataFrame(summary_rows).to_excel(writer, index=False, sheet_name="Contacts")

            QMessageBox.information(self, "Exported", f"WhatsApp histories saved to:\n{save_path}")
        except Exception as e:
            QMessageBox.warning(self, "Export Failed", f"Failed to export WhatsApp histories:\n{e}")

    def open_whatsapp_conversation_browser(self, rows, title="Conversation History by Contact"):
        rows = [row for row in list(rows or []) if isinstance(row, dict)]
        if not rows:
            QMessageBox.information(self, "No Histories", "There are no conversation histories to view.")
            return

        base_summaries = build_whatsapp_conversation_summaries(rows)
        if not base_summaries:
            QMessageBox.information(self, "No Conversations", "No contact conversations were found.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        dlg.setGeometry(230, 180, 1500, 820)

        layout = QVBoxLayout(dlg)

        info = QLabel(
            "Browse WhatsApp histories grouped by contact. Select a contact on the left to see the full sent and received conversation on the right."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("Search:"))
        search_edit = QLineEdit(self)
        search_edit.setPlaceholderText("Search contact name or phone...")
        top_row.addWidget(search_edit)

        top_row.addWidget(QLabel("Messages:"))
        direction_combo = QComboBox(self)
        direction_combo.addItem("All", "all")
        direction_combo.addItem("Sent Only", "outgoing")
        direction_combo.addItem("Received Only", "incoming")
        top_row.addWidget(direction_combo)
        top_row.addStretch()

        export_btn = QPushButton("Export Conversation")
        close_btn = QPushButton("Close")
        top_row.addWidget(export_btn)
        top_row.addWidget(close_btn)
        layout.addLayout(top_row)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        contact_table = QTableWidget(0, 6, self)
        prepare_plain_table_widget(
            contact_table,
            ["Contact", "Sent", "Received", "First Message", "Last Message", "Accounts"],
            stretch_last=False
        )
        contact_table.setColumnWidth(0, 220)
        contact_table.setColumnWidth(1, 70)
        contact_table.setColumnWidth(2, 80)
        contact_table.setColumnWidth(3, 140)
        contact_table.setColumnWidth(4, 140)
        contact_table.setColumnWidth(5, 180)
        splitter.addWidget(contact_table)

        right_splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(right_splitter)

        message_table = QTableWidget(0, 9, self)
        prepare_plain_table_widget(
            message_table,
            ["Timestamp", "Direction", "From", "To", "Preview", "Status", "Trigger", "Type", "Bad Words"],
            stretch_last=False
        )
        message_table.setColumnWidth(0, 150)
        message_table.setColumnWidth(1, 90)
        message_table.setColumnWidth(2, 170)
        message_table.setColumnWidth(3, 170)
        message_table.setColumnWidth(4, 280)
        message_table.setColumnWidth(5, 90)
        message_table.setColumnWidth(6, 110)
        message_table.setColumnWidth(7, 110)
        message_table.setColumnWidth(8, 100)
        right_splitter.addWidget(message_table)

        detail_box = QTextEdit(self)
        detail_box.setReadOnly(True)
        right_splitter.addWidget(detail_box)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 5)
        right_splitter.setStretchFactor(0, 3)
        right_splitter.setStretchFactor(1, 2)

        visible_summaries = []
        current_message_rows = []

        def render_contacts():
            nonlocal visible_summaries
            query = str(search_edit.text() or "").strip().lower()
            visible_summaries = []
            contact_table.setRowCount(0)

            for summary in base_summaries:
                haystack = " ".join([
                    str(summary.get("contact_display") or ""),
                    str(summary.get("contact_phone") or ""),
                    str(summary.get("contact_key") or "")
                ]).lower()
                if query and query not in haystack:
                    continue

                visible_summaries.append(summary)
            contact_table.setRowCount(len(visible_summaries))
            for row_index, summary in enumerate(visible_summaries):
                row_values = [
                    str(summary.get("contact_display") or summary.get("contact_key") or "-"),
                    str(int(summary.get("sent_count") or 0)),
                    str(int(summary.get("received_count") or 0)),
                    format_user_datetime_text(summary.get("first_timestamp"), default="-"),
                    format_user_datetime_text(summary.get("last_timestamp"), default="-"),
                    summary.get("self_accounts_text") or "-"
                ]
                for col, value in enumerate(row_values):
                    user_data = summary.get("contact_key") if col == 0 else None
                    contact_table.setItem(row_index, col, make_table_item(value, user_data=user_data))

            if contact_table.rowCount() > 0:
                select_first_table_row(contact_table)
            else:
                message_table.setRowCount(0)
                detail_box.clear()

        def render_messages():
            nonlocal current_message_rows
            row_index = contact_table.currentRow()
            current_message_rows = []
            message_table.setRowCount(0)

            if row_index < 0:
                detail_box.clear()
                return

            current_item = contact_table.item(row_index, 0)
            target_key = str(current_item.data(Qt.ItemDataRole.UserRole) or "").strip() if current_item else ""
            summary = next((item for item in visible_summaries if str(item.get("contact_key")) == target_key), None)
            if not summary:
                detail_box.clear()
                return

            mode = direction_combo.currentData()
            for row in summary.get("rows") or []:
                if mode != "all" and row.get("direction") != mode:
                    continue
                current_message_rows.append(row)

            message_table.setRowCount(len(current_message_rows))
            for message_index, row in enumerate(current_message_rows):
                send_type = str(row.get("send_type") or "")
                if send_type == "sync_incoming":
                    direction_text = "SYNC IN"
                elif send_type == "incoming_reply":
                    direction_text = "IN"
                elif send_type == "sync_outgoing":
                    direction_text = "SYNC OUT"
                elif send_type == "bulk_auto":
                    direction_text = "BULK"
                else:
                    direction_text = "OUT"

                row_values = [
                    row.get("timestamp_display") or "-",
                    direction_text,
                    row.get("from_text") or "-",
                    row.get("to_text") or "-",
                    row.get("preview") or "-",
                    str(row.get("status") or "-").upper(),
                    str(row.get("trigger") or "-"),
                    send_type or "-",
                    str(int(row.get("bad_word_count") or 0))
                ]
                for col, value in enumerate(row_values):
                    user_data = row if col == 0 else None
                    message_table.setItem(message_index, col, make_table_item(value, user_data=user_data))

            if message_table.rowCount() > 0:
                message_table.setCurrentCell(message_table.rowCount() - 1, 0)
                message_table.selectRow(message_table.rowCount() - 1)
                update_detail()
            else:
                detail_box.clear()

        def update_detail():
            row_index = message_table.currentRow()
            if row_index < 0:
                detail_box.clear()
                return
            current_item = message_table.item(row_index, 0)
            row = current_item.data(Qt.ItemDataRole.UserRole) if current_item else {}
            detail_box.setPlainText(build_whatsapp_history_detail_text(row))

        def export_current_conversation():
            row_index = contact_table.currentRow()
            if row_index < 0 or not current_message_rows:
                QMessageBox.information(dlg, "No Conversation", "Select a contact conversation first.")
                return

            current_item = contact_table.item(row_index, 0)
            target_key = str(current_item.data(Qt.ItemDataRole.UserRole) or "").strip() if current_item else ""
            summary = next((item for item in visible_summaries if str(item.get("contact_key")) == target_key), None)
            if not summary:
                QMessageBox.information(dlg, "No Conversation", "Select a contact conversation first.")
                return
            safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(summary.get("contact_display") or target_key or "conversation")).strip("_")
            safe_name = safe_name or "conversation"
            self.export_whatsapp_history_rows_to_excel(
                current_message_rows,
                suggested_name=f"{safe_name}.xlsx"
            )

        search_edit.textChanged.connect(render_contacts)
        direction_combo.currentIndexChanged.connect(render_messages)
        contact_table.itemSelectionChanged.connect(render_messages)
        message_table.itemSelectionChanged.connect(update_detail)
        export_btn.clicked.connect(export_current_conversation)
        close_btn.clicked.connect(dlg.accept)

        render_contacts()
        dlg.exec()

    # ---------- UI ----------
    def create_top_bar(self):
        bar = QToolBar()
        bar.setMovable(False)
        bar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        bar.setIconSize(QSize(0, 0))
        self.addToolBar(bar)
        
        bar.addSeparator()

        menu_btn = QPushButton("Menu", self)
        tools_menu = QMenu(menu_btn)
        menu_btn.setMenu(tools_menu)

        # Navigation
        tools_menu.addAction("Reload", self.reload_current_tab)
        tools_menu.addAction("Home", self.go_home_current_tab)
        tools_menu.addSeparator()

        # Logs / history
        tools_menu.addAction("View History", self.show_history)
        tools_menu.addAction("View Network Log", self.show_network_log)
        tools_menu.addAction("View Manual Send Log", self.show_manual_send_log)
        tools_menu.addAction("Clear Manual Send Log", self.clear_manual_send_log)
        tools_menu.addAction("Clear Histories", self.clear_histories_no_password)
        tools_menu.addSeparator()

        # Features
        tools_menu.addAction("Detected API Tables", self.open_detected_api_picker)
        tools_menu.addAction("Manage Contacts", self.open_contact_manager)
        tools_menu.addAction("Reply With Template", self.open_whatsapp_template_reply)
        tools_menu.addAction("Sync WhatsApp Histories", self.sync_whatsapp_histories)
        tools_menu.addAction("Set Proxy", self.set_custom_proxy)
        tools_menu.addAction("View Bad Word Stats", self.show_bad_word_stats)
        tools_menu.addAction("Manage Templates", self.open_template_manager)
        tools_menu.addAction("Set Bulk Message Mode", self.configure_custom_bulk_message_policy)
        tools_menu.addAction("Set Cashier Mode", self.configure_cashier_mode)
        tools_menu.addAction("Attendance", self.show_attendance)
        tools_menu.addAction("View User Stats", self.show_user_stats)
        tools_menu.addSeparator()

        # Admin
        tools_menu.addAction("Admin Clear History", self.admin_clear)

        menu_btn.setMenu(tools_menu)
        bar.addWidget(menu_btn)
        
        bar.addSeparator()

        # Keep only these outside
        bulk_btn = QPushButton("Bulk Send")
        bulk_btn.clicked.connect(self.bulk_whatsapp_send)
        bulk_btn.setMinimumWidth(104)
        bar.addWidget(bulk_btn)

        sync_btn = QPushButton("Sync Histories")
        sync_btn.clicked.connect(self.sync_whatsapp_histories)
        sync_btn.setMinimumWidth(120)
        bar.addWidget(sync_btn)

        reply_template_btn = QPushButton("Reply Template")
        reply_template_btn.clicked.connect(self.open_whatsapp_template_reply)
        reply_template_btn.setMinimumWidth(126)
        bar.addWidget(reply_template_btn)

        add_wa_btn = QPushButton("Add Account")
        add_wa_btn.clicked.connect(lambda: self.add_whatsapp_account_tab())
        add_wa_btn.setMinimumWidth(118)
        bar.addWidget(add_wa_btn)

        perf_btn = QPushButton("Performance")
        perf_btn.clicked.connect(self.toggle_performance_dock)
        perf_btn.setMinimumWidth(104)
        bar.addWidget(perf_btn)

        bar.addSeparator()

        self.proxy_label = QLabel("  Proxy: DIRECT  ")
        bar.addWidget(self.proxy_label)

        self.bulk_policy_label = QLabel("")
        bar.addWidget(self.bulk_policy_label)
        self.update_bulk_message_policy_label()

        self.cashier_mode_label = QLabel("")
        bar.addWidget(self.cashier_mode_label)
        self.update_cashier_mode_label()

        self.country_label = None
        if ENABLE_SPOOF:
            self.country_label = QLabel(f"  Spoof: {self.country}  ")
            bar.addWidget(self.country_label)

    def install_whatsapp_qr_only_mode(self, profile=None):
        profile = profile or self.profile

        script_source = r"""
        (function() {
            if (window.__waQrOnlyModeInstalled) return;
            window.__waQrOnlyModeInstalled = true;

            if (location.hostname !== "web.whatsapp.com") return;

            function getQrCanvas() {
                return document.querySelector(
                    'canvas[aria-label="Scan me!"], canvas[aria-label*="Scan"], div[data-ref] canvas'
                );
            }

            function applyQrOnlyMode() {
                const body = document.body;
                if (!body) return;

                const qr = getQrCanvas();
                const enabled = !!qr;

                const allNodes = [body].concat(Array.from(body.querySelectorAll("*")));
                allNodes.forEach(node => {
                    const keep = enabled && (node === qr || node.contains(qr));

                    if (enabled && !keep) {
                        if (node.dataset.__ptnOrigDisplay === undefined) {
                            node.dataset.__ptnOrigDisplay = node.style.display || "";
                        }
                        node.style.setProperty("display", "none", "important");
                    } else if (!enabled && node.dataset.__ptnOrigDisplay !== undefined) {
                        node.style.display = node.dataset.__ptnOrigDisplay;
                        delete node.dataset.__ptnOrigDisplay;
                    }
                });

                if (enabled) {
                    body.style.setProperty("background", "#ffffff", "important");
                    body.style.setProperty("display", "flex", "important");
                    body.style.setProperty("align-items", "center", "important");
                    body.style.setProperty("justify-content", "center", "important");
                    body.style.setProperty("min-height", "100vh", "important");

                    let wrapper = qr.parentElement;
                    while (wrapper && wrapper.parentElement && wrapper.parentElement !== body) {
                        wrapper = wrapper.parentElement;
                    }

                    if (wrapper) {
                        wrapper.style.setProperty("display", "flex", "important");
                        wrapper.style.setProperty("align-items", "center", "important");
                        wrapper.style.setProperty("justify-content", "center", "important");
                        wrapper.style.setProperty("width", "100vw", "important");
                        wrapper.style.setProperty("height", "100vh", "important");
                        wrapper.style.setProperty("background", "#ffffff", "important");
                    }

                    qr.style.setProperty("display", "block", "important");
                    qr.style.setProperty("visibility", "visible", "important");
                    qr.style.setProperty("opacity", "1", "important");
                } else {
                    body.style.removeProperty("background");
                    body.style.removeProperty("display");
                    body.style.removeProperty("align-items");
                    body.style.removeProperty("justify-content");
                    body.style.removeProperty("min-height");
                }
            }

            function start() {
                applyQrOnlyMode();

                const obs = new MutationObserver(() => {
                    applyQrOnlyMode();
                });

                obs.observe(document.documentElement || document.body, {
                    childList: true,
                    subtree: true
                });

                setInterval(applyQrOnlyMode, 1500);
            }

            if (document.readyState === "loading") {
                document.addEventListener("DOMContentLoaded", start, { once: true });
            } else {
                start();
            }
        })();
        """

        script = QWebEngineScript()
        script.setName("wa_qr_only_mode")
        script.setSourceCode(script_source)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        profile.scripts().insert(script)
    
    def open_contact_manager(self):
        dlg = ContactManagerDialog(self)
        dlg.exec()
    
    def update_proxy_label(self):
        if not hasattr(self, "proxy_label"):
            return

        if self.proxy_info.get("enabled"):
            username = self.proxy_info.get("username", "")
            auth_text = f" as {username}" if username else ""
            self.proxy_label.setText(
                f"  Proxy: {self.proxy_info.get('type')} "
                f"{self.proxy_info.get('host')}:{self.proxy_info.get('port')}{auth_text}  "
            )
        else:
            self.proxy_label.setText("  Proxy: DIRECT  ")

    def reload_current_tab(self):
        current = self.tab_widget.currentWidget()
        if isinstance(current, QWebEngineView):
            current.reload()
        elif isinstance(current, ApiSheetTab):
            if callable(current.refresh_callback):
                current.refresh_callback(current)

    def go_home_current_tab(self):
        current_view = self.tab_widget.currentWidget()
        for tab in self.tab_views:
            if tab["view"] == current_view:
                current_view.setUrl(QUrl(tab["home"]))
                break

    def create_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready", 3000)

    def setup_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        icon = QIcon.fromTheme("web-browser")
        if icon.isNull():
            pixmap = QPixmap(16, 16)
            pixmap.fill(Qt.GlobalColor.blue)
            icon = QIcon(pixmap)
        self.tray_icon.setIcon(icon)
        self.tray_icon.setVisible(True)
        tray_menu = QMenu()
        show_action = tray_menu.addAction("Show Window")
        show_action.triggered.connect(self.show)
        quit_action = tray_menu.addAction("Quit")
        quit_action.triggered.connect(QApplication.quit)
        self.tray_icon.setContextMenu(tray_menu)

    def show_tray_message(self, title, message):
        self.tray_icon.showMessage(title, message, QSystemTrayIcon.MessageIcon.Information, 3000)

    # ---------- Disclaimer ----------
    def show_startup_disclaimer(self):
        dlg = QDialog(self, Qt.WindowType.WindowStaysOnTopHint)
        dlg.setWindowTitle("Disclaimer")
        dlg.setModal(True)
        dlg.setFixedSize(500, 200)

        layout = QVBoxLayout(dlg)

        message = QLabel(
            "This application is made by PT Pendanaan Teknologi Nusa.\n\n"
            "All actions performed within this browser are recorded and monitored.\n"
            "Any malicious activities will be subject to legal liability and may be prosecuted.\n\n"
            "You will be redirected to the target sites in 3 seconds."
        )
        message.setWordWrap(True)
        layout.addWidget(message)

        self.disclaimer_timer = QTimer()
        self.disclaimer_timer.setSingleShot(True)
        self.disclaimer_timer.timeout.connect(dlg.accept)
        self.disclaimer_timer.start(3000)

        dlg.exec()

        for tab in self.tab_views:
            tab["view"].setUrl(QUrl(tab["home"]))

    # ---------- Download handling ----------
    def handle_download(self, download):
        url = download.url().toString()
        path = download.url().path()
        ext = os.path.splitext(path)[1].lower()
        if ext in ALLOWED_DOWNLOAD_EXTENSIONS:
            downloads_dir = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
            if not os.path.exists(downloads_dir):
                os.makedirs(downloads_dir)
            base_name = os.path.basename(path)
            if not base_name:
                base_name = f"download{ext}"
            file_path = os.path.join(downloads_dir, base_name)
            counter = 1
            orig_path = file_path
            while os.path.exists(file_path):
                name, ext = os.path.splitext(orig_path)
                file_path = f"{name}_{counter}{ext}"
                counter += 1

            download.setPath(file_path)
            download.accept()
            self.status_bar.showMessage(f"Downloading {base_name}...", 3000)
            self.show_tray_message("Download started", base_name)
        else:
            download.cancel()
            QMessageBox.warning(self, "Download Blocked",
                                f"Files of type {ext} are not allowed.\nAllowed: {', '.join(ALLOWED_DOWNLOAD_EXTENSIONS)}")
            self.status_bar.showMessage(f"Blocked download: {ext} not allowed", 3000)

    def clear_manual_send_log(self):
        if not self.require_admin_password():
            QMessageBox.warning(self, "Error", "Incorrect password.")
            return

        reply = QMessageBox.question(
            self,
            "Clear Manual Send Log",
            "Clear all saved manual-send logs, including message content?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        clear_manual_send_log_file()
        QMessageBox.information(self, "Cleared", "Manual send log cleared.")
    
    # ---------- History and Admin ----------
    def show_history(self):
        if not self.require_admin_password():
            QMessageBox.warning(self, "Error", "Incorrect password.")
            return

        hist = load_history()
        dlg = QDialog(self)
        dlg.setWindowTitle("Full History")
        dlg.setGeometry(200, 200, 900, 600)
        layout = QVBoxLayout(dlg)

        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(json.dumps(make_timestamps_display_friendly(hist), indent=2, ensure_ascii=False))
        layout.addWidget(text)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        layout.addWidget(close_btn)

        dlg.exec()


    def show_network_log(self):
        if not self.require_admin_password():
            QMessageBox.warning(self, "Error", "Incorrect password.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Network Log")
        dlg.setGeometry(200, 200, 1200, 800)

        layout = QVBoxLayout(dlg)

        top = QHBoxLayout()
        hide_proxy_chk = QCheckBox("Hide proxied traffic")
        proxied_only_chk = QCheckBox("Show proxied traffic only")
        refresh_btn = QPushButton("Refresh")
        top.addWidget(hide_proxy_chk)
        top.addWidget(proxied_only_chk)
        top.addStretch()
        top.addWidget(refresh_btn)
        layout.addLayout(top)

        info = QLabel(
            "Note: 'via_proxy' means proxy was enabled in the browser when the request was made. "
            "It is a browser-side snapshot, not packet capture."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        text = QTextEdit()
        text.setReadOnly(True)
        layout.addWidget(text)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        layout.addWidget(close_btn)

        def render():
            logs = load_network_log()
            filtered = []

            for entry in logs:
                via_proxy = bool(entry.get("via_proxy"))

                if hide_proxy_chk.isChecked() and via_proxy:
                    continue

                if proxied_only_chk.isChecked() and not via_proxy:
                    continue

                filtered.append(entry)

            text.setPlainText(json.dumps(make_timestamps_display_friendly(filtered), indent=2, ensure_ascii=False))

        hide_proxy_chk.toggled.connect(render)
        proxied_only_chk.toggled.connect(render)
        refresh_btn.clicked.connect(render)

        render()
        dlg.exec()

    def show_manual_send_log(self):
        if not self.require_admin_password():
            QMessageBox.warning(self, "Error", "Incorrect password.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("WhatsApp History Log")
        dlg.setGeometry(220, 220, 1350, 780)

        layout = QVBoxLayout(dlg)

        info = QLabel(
            "This log stores manual, bulk, and synced WhatsApp histories with sender, recipient, full content, timestamp, attachment flag, trigger, send type, status, and bad-word masking info."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        top_filter = QHBoxLayout()
        top_filter.addWidget(QLabel("Filter:"))

        filter_combo = QComboBox(self)
        filter_combo.addItem("All histories", "all")
        filter_combo.addItem("Sent histories", "sent")
        filter_combo.addItem("Receive histories", "receive")
        filter_combo.addItem("Bad words only", "bad")
        top_filter.addWidget(filter_combo)

        top_filter.addStretch()
        layout.addLayout(top_filter)

        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)

        log_table = QTableWidget(0, 10, self)
        prepare_plain_table_widget(
            log_table,
            ["Timestamp", "Direction", "From", "To", "Preview", "Status", "Trigger", "Type", "Bad Words", "Reply Speed"],
            stretch_last=False
        )
        log_table.setColumnWidth(0, 150)
        log_table.setColumnWidth(1, 100)
        log_table.setColumnWidth(2, 170)
        log_table.setColumnWidth(3, 170)
        log_table.setColumnWidth(4, 300)
        log_table.setColumnWidth(5, 90)
        log_table.setColumnWidth(6, 110)
        log_table.setColumnWidth(7, 110)
        log_table.setColumnWidth(8, 120)
        log_table.setColumnWidth(9, 120)
        splitter.addWidget(log_table)

        detail_label = QLabel("Full Message Content")
        detail_label.setStyleSheet("font-weight:700;")
        detail_box = QTextEdit(self)
        detail_box.setReadOnly(True)

        detail_wrap = QWidget()
        detail_layout = QVBoxLayout(detail_wrap)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.addWidget(detail_label)
        detail_layout.addWidget(detail_box)
        splitter.addWidget(detail_wrap)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        btn_row = QHBoxLayout()
        conversation_btn = QPushButton("Conversations")
        export_btn = QPushButton("Export Excel")
        refresh_btn = QPushButton("Refresh")
        close_btn = QPushButton("Close")
        btn_row.addStretch()
        btn_row.addWidget(conversation_btn)
        btn_row.addWidget(export_btn)
        btn_row.addWidget(refresh_btn)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

        current_rows = []

        def render():
            nonlocal current_rows
            logs, _ = self.repair_whatsapp_history_records(quiet=True)
            rows = build_whatsapp_history_rows(logs)
            mode = filter_combo.currentData()

            filtered = []
            for row in rows:
                send_type = str(row.get("send_type", "")).strip().lower()
                bad_word_count = int(row.get("bad_word_count") or 0)

                if mode == "sent":
                    if not is_whatsapp_outgoing_history_send_type(send_type):
                        continue
                elif mode == "receive":
                    if not is_whatsapp_incoming_history_send_type(send_type):
                        continue
                elif mode == "bad":
                    if bad_word_count <= 0:
                        continue

                filtered.append(row)

            filtered.sort(key=lambda row: (row.get("sort_key"), row.get("index", 0)), reverse=True)
            current_rows = filtered

            log_table.setRowCount(len(current_rows))
            for row_index, row in enumerate(current_rows):
                send_type = str(row.get("send_type") or "").strip().lower()
                if send_type == "sync_incoming":
                    direction_text = "SYNC IN"
                elif send_type == "incoming_reply":
                    direction_text = "IN"
                elif send_type == "sync_outgoing":
                    direction_text = "SYNC OUT"
                elif send_type == "bulk_auto":
                    direction_text = "BULK"
                else:
                    direction_text = "OUT"

                row_values = [
                    row.get("timestamp_display") or "-",
                    direction_text,
                    row.get("from_text") or "-",
                    row.get("to_text") or "-",
                    row.get("preview") or "-",
                    str(row.get("status") or "-").upper(),
                    str(row.get("trigger") or "-"),
                    send_type or "-",
                    str(int(row.get("bad_word_count") or 0)),
                    row.get("reply_speed_hms") or "-"
                ]
                for col, value in enumerate(row_values):
                    user_data = row if col == 0 else None
                    log_table.setItem(row_index, col, make_table_item(value, user_data=user_data))

            if log_table.rowCount() > 0:
                select_first_table_row(log_table)
                update_detail()
            else:
                detail_box.clear()

        def update_detail():
            row_index = log_table.currentRow()
            if row_index < 0:
                detail_box.clear()
                return

            current_item = log_table.item(row_index, 0)
            row = current_item.data(Qt.ItemDataRole.UserRole) if current_item else {}
            detail_box.setPlainText(build_whatsapp_history_detail_text(row))

        def export_current_rows():
            self.export_whatsapp_history_rows_to_excel(current_rows)

        def open_conversations():
            self.open_whatsapp_conversation_browser(current_rows)

        log_table.itemSelectionChanged.connect(update_detail)
        conversation_btn.clicked.connect(open_conversations)
        export_btn.clicked.connect(export_current_rows)
        refresh_btn.clicked.connect(render)
        close_btn.clicked.connect(dlg.accept)
        filter_combo.currentIndexChanged.connect(render)

        render()
        dlg.exec()

    def admin_clear(self):
        pwd, ok = QInputDialog.getText(
            self,
            "Admin Login",
            "Enter Password:",
            QLineEdit.EchoMode.Password
        )
        if ok and pwd == ADMIN_PASSWORD:
            with open(HISTORY_FILE, "wb") as f:
                f.write(encrypt_data([]))

            with open(NETWORK_LOG_FILE, "wb") as f:
                f.write(encrypt_data([]))

            with open(LAST_BLAST_FILE, "wb") as f:
                f.write(encrypt_data({
                    "recipients": [],
                    "numbers": [],
                    "message": "",
                    "attachment_path": "",
                    "updated_at": ""
                }))

            with open(MANUAL_SEND_LOG_FILE, "wb") as f:
                f.write(encrypt_data([]))

            clear_bad_word_counter()
            clear_activity_stats()

            QMessageBox.information(
                self,
                "Success",
                "History, network logs, last blast data, and manual send metadata logs cleared."
            )
            self.show_tray_message("Admin", "Logs cleared.")
        elif ok:
            QMessageBox.warning(self, "Error", "Incorrect password.")
            self.show_tray_message("Admin", "Failed login attempt.")

class ApiPickerDialog(QDialog):
    def __init__(self, apis, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Detected Collection APIs")
        self.setGeometry(200, 200, 1000, 500)
        self.selected_index = None
        self.apis = apis

        layout = QVBoxLayout(self)

        info = QLabel("Select one captured API response to open it as a data sheet.")
        info.setWordWrap(True)
        layout.addWidget(info)

        self.api_table = QTableWidget(0, 4, self)
        prepare_plain_table_widget(self.api_table, ["Method", "Status", "Captured At", "URL"], stretch_last=False)
        self.api_table.setColumnWidth(0, 90)
        self.api_table.setColumnWidth(1, 80)
        self.api_table.setColumnWidth(2, 150)
        self.api_table.setColumnWidth(3, 620)
        layout.addWidget(self.api_table)

        self.api_table.setRowCount(len(apis))
        for row, item in enumerate(apis):
            self.api_table.setItem(row, 0, make_table_item(str(item.get("method", "") or "API"), user_data=row))
            self.api_table.setItem(row, 1, make_table_item(str(item.get("status", "") or "-")))
            self.api_table.setItem(row, 2, make_table_item(format_user_datetime_text(item.get("ts", ""), default="-")))
            self.api_table.setItem(row, 3, make_table_item(str(item.get("url", "") or "")))

        if self.api_table.rowCount() > 0:
            select_first_table_row(self.api_table)
        self.api_table.itemDoubleClicked.connect(lambda *_: self.accept_selection())

        btns = QHBoxLayout()
        open_btn = QPushButton("Open as Table")
        cancel_btn = QPushButton("Cancel")
        open_btn.clicked.connect(self.accept_selection)
        cancel_btn.clicked.connect(self.reject)
        btns.addStretch()
        btns.addWidget(open_btn)
        btns.addWidget(cancel_btn)
        layout.addLayout(btns)

    def accept_selection(self):
        row = self.api_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Select API", "Please select one API.")
            return
        item = self.api_table.item(row, 0)
        self.selected_index = int(item.data(Qt.ItemDataRole.UserRole) or 0) if item else 0
        self.accept()

# --------------------------
# Main
# --------------------------
if __name__ == "__main__":
    if hasattr(QApplication, "setHighDpiScaleFactorRoundingPolicy"):
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.Round
        )

    app = QApplication(sys.argv)
    app.setApplicationName("Locked Browser")
    app.setQuitOnLastWindowClosed(False)

    if not TAB_CONFIG:
        QMessageBox.critical(None, "Configuration Error", "No tabs configured.")
        sys.exit(1)

    window = LockedBrowser()
    window.show()
    sys.exit(app.exec())
