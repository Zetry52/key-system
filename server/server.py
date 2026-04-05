import argparse
import hashlib
import html
import json
import os
import secrets
import threading
import time
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen


DATA_FILE = Path(__file__).with_name("licenses.json")
CONFIG_FILE = Path(__file__).with_name("config.json")
USERS_FILE = Path(__file__).with_name("telegram_users.json")
SESSION_COOKIE = "ks_admin_session"


def default_config() -> dict:
    return {
        "admin_username": "admin",
        "admin_password": "changeme",
        "telegram_token": "",
        "telegram_admin_chat_ids": [],
        "telegram_last_update_id": 0,
        "support_username": "",
        "bot_info_text": "Key system bot",
        "user_sticker_id": "",
        "admin_sticker_id": "",
    }


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso_utc(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def default_db() -> dict:
    return {"licenses": [], "sessions": {}, "auth_logs": [], "admin_device_lock": {}}


def default_users() -> dict:
    return {"users": {}}


def load_db() -> dict:
    if not DATA_FILE.exists():
        return default_db()
    db = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    db.setdefault("licenses", [])
    db.setdefault("sessions", {})
    db.setdefault("auth_logs", [])
    db.setdefault("admin_device_lock", {})
    return db


def save_db(db: dict) -> None:
    DATA_FILE.write_text(json.dumps(db, indent=2), encoding="utf-8")


def load_users() -> dict:
    if not USERS_FILE.exists():
        return default_users()
    data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
    data.setdefault("users", {})
    return data


def save_users(data: dict) -> None:
    USERS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        return default_config()
    config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    defaults = default_config()
    for key, value in defaults.items():
        config.setdefault(key, value)
    return config


def save_config(config: dict) -> None:
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")


def ensure_config() -> dict:
    config = load_config()
    save_config(config)
    return config


def find_license(db: dict, license_key: str) -> dict | None:
    for item in db.get("licenses", []):
        if item["license_key"] == license_key:
            return item
    return None


def normalize_status(item: dict) -> str:
    if item.get("status"):
        return item["status"]
    return "active" if item.get("enabled", True) else "frozen"


def append_auth_log(db: dict, license_key: str, product: str, hwid: str, ip: str, success: bool, message: str) -> None:
    db.setdefault("auth_logs", []).append({
        "timestamp": iso_utc(now_utc()),
        "license_key": license_key,
        "product": product,
        "hwid": hwid,
        "ip": ip,
        "success": success,
        "message": message,
    })
    db["auth_logs"] = db["auth_logs"][-300:]


def validate_license(license_key: str, hwid: str, product: str, ip: str) -> dict:
    db = load_db()
    item = find_license(db, license_key)
    if not item:
        result = {"success": False, "message": "License not found"}
        append_auth_log(db, license_key, product, hwid, ip, False, result["message"])
        save_db(db)
        return result

    if item.get("product") != product:
        result = {"success": False, "message": "Wrong product"}
        append_auth_log(db, license_key, product, hwid, ip, False, result["message"])
        save_db(db)
        return result

    status = normalize_status(item)
    if status == "frozen":
        result = {"success": False, "message": "License frozen"}
        append_auth_log(db, license_key, product, hwid, ip, False, result["message"])
        save_db(db)
        return result
    if status != "active":
        result = {"success": False, "message": f"License status is {status}"}
        append_auth_log(db, license_key, product, hwid, ip, False, result["message"])
        save_db(db)
        return result

    expires_at = parse_iso_utc(item["expires_at"])
    if now_utc() > expires_at:
        item["status"] = "expired"
        result = {"success": False, "message": "License expired", "expires_at": item["expires_at"]}
        append_auth_log(db, license_key, product, hwid, ip, False, result["message"])
        save_db(db)
        return result

    bound_hwid = item.get("hwid", "")
    if bound_hwid and bound_hwid != hwid:
        result = {"success": False, "message": "HWID mismatch"}
        append_auth_log(db, license_key, product, hwid, ip, False, result["message"])
        save_db(db)
        return result

    if not bound_hwid:
        item["hwid"] = hwid

    item["max_users"] = 1
    item["last_seen_at"] = iso_utc(now_utc())
    item["last_ip"] = ip
    append_auth_log(db, license_key, product, hwid, ip, True, "License valid")
    save_db(db)

    remaining_seconds = max(0, int((expires_at - now_utc()).total_seconds()))
    return {
        "success": True,
        "message": "License valid",
        "name": item.get("name", ""),
        "expires_at": item["expires_at"],
        "days_left": remaining_seconds // 86400,
        "bound_hwid": item.get("hwid", ""),
        "status": "active",
        "max_users": 1,
        "notes": item.get("notes", ""),
        "last_ip": item.get("last_ip", ""),
    }


def create_license_record(key: str, name: str, days: int, product: str, notes: str) -> dict:
    db = load_db()
    if find_license(db, key):
        raise ValueError("License already exists")

    item = {
        "license_key": key,
        "name": name,
        "product": product,
        "expires_at": iso_utc(now_utc() + timedelta(days=days)),
        "status": "active",
        "hwid": "",
        "notes": notes or "",
        "created_at": iso_utc(now_utc()),
        "last_seen_at": "",
        "max_users": 1,
    }
    db.setdefault("licenses", []).append(item)
    save_db(db)
    return item


def freeze_license_record(key: str) -> dict:
    db = load_db()
    item = find_license(db, key)
    if not item:
        raise ValueError("License not found")
    item["status"] = "frozen"
    save_db(db)
    return deepcopy(item)


def unfreeze_license_record(key: str) -> dict:
    db = load_db()
    item = find_license(db, key)
    if not item:
        raise ValueError("License not found")
    item["status"] = "active"
    save_db(db)
    return deepcopy(item)


def extend_license_record(key: str, days: int) -> dict:
    db = load_db()
    item = find_license(db, key)
    if not item:
        raise ValueError("License not found")
    base = parse_iso_utc(item["expires_at"])
    if now_utc() > base:
        base = now_utc()
    item["expires_at"] = iso_utc(base + timedelta(days=days))
    item["status"] = "active"
    save_db(db)
    return deepcopy(item)


def reset_hwid_record(key: str) -> dict:
    db = load_db()
    item = find_license(db, key)
    if not item:
        raise ValueError("License not found")
    item["hwid"] = ""
    save_db(db)
    return deepcopy(item)


def show_license_record(key: str) -> dict:
    db = load_db()
    item = find_license(db, key)
    if not item:
        raise ValueError("License not found")
    return deepcopy(item)


def search_license_records(query: str, limit: int = 20) -> list[dict]:
    q = query.strip().lower()
    if not q:
        return list_license_records(limit)
    db = load_db()
    matches = []
    for item in reversed(db.get("licenses", [])):
        haystack = " ".join([
            str(item.get("license_key", "")),
            str(item.get("name", "")),
            str(item.get("product", "")),
            str(item.get("status", "")),
            str(item.get("hwid", "")),
            str(item.get("notes", "")),
        ]).lower()
        if q in haystack:
            matches.append(deepcopy(item))
        if len(matches) >= limit:
            break
    return matches


def delete_license_record(key: str) -> None:
    db = load_db()
    before = len(db.get("licenses", []))
    db["licenses"] = [item for item in db.get("licenses", []) if item.get("license_key") != key]
    if len(db["licenses"]) == before:
        raise ValueError("License not found")
    save_db(db)


def list_license_records(limit: int = 20) -> list[dict]:
    db = load_db()
    items = list(reversed(db.get("licenses", [])))
    return [deepcopy(item) for item in items[:limit]]


def days_left_for_item(item: dict) -> int:
    expires_at = parse_iso_utc(item["expires_at"])
    if now_utc() > expires_at:
        return 0
    return max(0, int((expires_at - now_utc()).total_seconds()) // 86400)


def set_license_days_left(key: str, days: int) -> dict:
    db = load_db()
    item = find_license(db, key)
    if not item:
        raise ValueError("License not found")
    item["expires_at"] = iso_utc(now_utc() + timedelta(days=max(0, days)))
    item["status"] = "active" if days > 0 else "expired"
    save_db(db)
    return deepcopy(item)


def update_license_record(key: str, *, name: str | None = None, product: str | None = None, notes: str | None = None) -> dict:
    db = load_db()
    item = find_license(db, key)
    if not item:
        raise ValueError("License not found")
    if name is not None:
        item["name"] = name
    if product is not None:
        item["product"] = product
    if notes is not None:
        item["notes"] = notes
    save_db(db)
    return deepcopy(item)


def format_license_line(item: dict) -> str:
    return (
        f"{item.get('license_key', '-')}"
        f" | {item.get('status', '-')}"
        f" | {item.get('product', '-')}"
        f" | left {days_left_for_item(item)}d"
    )


def format_license_details(item: dict) -> str:
    return (
        f"🔑 Key: {item.get('license_key', '-')}\n"
        f"👤 Name: {item.get('name', '-')}\n"
        f"📦 Product: {item.get('product', '-')}\n"
        f"📌 Status: {item.get('status', '-')}\n"
        f"📅 Expires: {item.get('expires_at', '-')}\n"
        f"⏳ Days Left: {days_left_for_item(item)}\n"
        f"🖥 HWID: {item.get('hwid') or '-'}\n"
        f"🌐 Last IP: {item.get('last_ip') or '-'}\n"
        f"🕒 Last Seen: {item.get('last_seen_at') or '-'}\n"
        f"📝 Notes: {item.get('notes') or '-'}"
    )


def display_status(item: dict) -> str:
    status = normalize_status(item)
    expires_at = item.get("expires_at", "")
    if status == "active" and expires_at:
        try:
            if now_utc() > parse_iso_utc(expires_at):
                return "expired"
        except Exception:
            return "expired"
    return status


def format_admin_datetime(value: str) -> str:
    if not value:
        return "-"
    try:
        return parse_iso_utc(value).strftime("%d.%m.%Y %H:%M UTC")
    except Exception:
        return value


def render_license_card_html(item: dict) -> str:
    status = display_status(item)
    key_value = item.get("license_key", "")
    return f"""
<article class="license-card">
  <div class="license-head">
    <div>
      <div class="license-key">{html.escape(key_value)}</div>
      <div class="license-caption">{html.escape(item.get("name", "") or "Unnamed")} · {html.escape(item.get("product", "") or "No product")}</div>
    </div>
    <span class="pill {html.escape(status)}">{html.escape(status.title())}</span>
  </div>
  <div class="license-highlights">
    <div class="spot-chip">
      <span>Days left</span>
      <strong>{days_left_for_item(item)}</strong>
    </div>
    <div class="spot-chip">
      <span>HWID</span>
      <strong>{html.escape(item.get("hwid", "") or "Open")}</strong>
    </div>
    <div class="spot-chip">
      <span>Last IP</span>
      <strong>{html.escape(item.get("last_ip", "") or "-")}</strong>
    </div>
  </div>
  <div class="license-meta-grid">
    <div class="meta-card">
      <span>Created</span>
      <strong>{html.escape(format_admin_datetime(item.get("created_at", "")))}</strong>
    </div>
    <div class="meta-card">
      <span>Expires</span>
      <strong>{html.escape(format_admin_datetime(item.get("expires_at", "")))}</strong>
    </div>
    <div class="meta-card">
      <span>Last seen</span>
      <strong>{html.escape(format_admin_datetime(item.get("last_seen_at", "")))}</strong>
    </div>
    <div class="meta-card">
      <span>Notes</span>
      <strong>{html.escape(item.get("notes", "") or "No notes")}</strong>
    </div>
  </div>
  <div class="license-actions">
    <form method="post" action="/admin/action" class="inline">
      <input type="hidden" name="action" value="freeze">
      <input type="hidden" name="key" value="{html.escape(key_value)}">
      <button class="btn warn small" type="submit">Freeze</button>
    </form>
    <form method="post" action="/admin/action" class="inline">
      <input type="hidden" name="action" value="unfreeze">
      <input type="hidden" name="key" value="{html.escape(key_value)}">
      <button class="btn small" type="submit">Unfreeze</button>
    </form>
    <form method="post" action="/admin/action" class="inline">
      <input type="hidden" name="action" value="reset_hwid">
      <input type="hidden" name="key" value="{html.escape(key_value)}">
      <button class="btn alt small" type="submit">Reset HWID</button>
    </form>
    <form method="post" action="/admin/action" class="inline">
      <input type="hidden" name="action" value="delete">
      <input type="hidden" name="key" value="{html.escape(key_value)}">
      <button class="btn bad small" type="submit">Delete</button>
    </form>
  </div>
</article>"""


def render_auth_log_card_html(log: dict) -> str:
    status = "ok" if log.get("success") else "fail"
    status_label = "OK" if log.get("success") else "FAIL"
    return (
        f'<div class="log-item {status}">'
        f'<div class="log-top"><span class="log-pill {status}">{status_label}</span>'
        f'<span>{html.escape(format_admin_datetime(log.get("timestamp", "")))}</span></div>'
        f'<div class="log-body">'
        f'<strong>{html.escape(log.get("license_key", "-"))}</strong>'
        f'<span>{html.escape(log.get("message", "-"))}</span>'
        f'</div>'
        f'<div class="log-meta">{html.escape(log.get("ip", "-"))} · {html.escape(log.get("hwid", "-"))}</div>'
        f'</div>'
    )


BTN_PROFILE = "👤 Профиль"
BTN_SUPPORT = "🛠 Поддержка"
BTN_MY_KEY = "🔑 Мой ключ"
BTN_INFO = "ℹ️ Информация"
BTN_CANCEL = "↩️ Отмена"

BTN_ADMIN_CREATE = "🔑 Создать ключ"
BTN_ADMIN_LIST = "📋 Список ключей"
BTN_ADMIN_SHOW = "🔎 Показать ключ"
BTN_ADMIN_FREEZE = "🧊 Заморозить"
BTN_ADMIN_UNFREEZE = "🟢 Разморозить"
BTN_ADMIN_EXTEND = "➕ Продлить"
BTN_ADMIN_RESET = "♻️ Сбросить HWID"
BTN_ADMIN_DELETE = "🗑 Удалить"
BTN_ADMIN_STATS = "📊 Статистика"
BTN_ADMIN_EXIT = "🚪 Выйти из админки"

TELEGRAM_CHAT_STATES: dict[int, dict] = {}


def is_single_admin(config: dict, chat_id: int) -> bool:
    admin_ids = [str(item) for item in config.get("telegram_admin_chat_ids", [])]
    return bool(admin_ids) and str(chat_id) == admin_ids[0]


def cb(data: str) -> str:
    return data[:64]


def telegram_user_keyboard() -> dict:
    return {
        "inline_keyboard": [
            [{"text": BTN_PROFILE, "callback_data": cb("user:profile")}, {"text": BTN_MY_KEY, "callback_data": cb("user:key")}],
            [{"text": BTN_SUPPORT, "callback_data": cb("user:support")}, {"text": BTN_INFO, "callback_data": cb("user:info")}],
        ]
    }


def telegram_admin_keyboard() -> dict:
    return {
        "inline_keyboard": [
            [{"text": BTN_ADMIN_CREATE, "callback_data": cb("admin:create")}, {"text": BTN_ADMIN_LIST, "callback_data": cb("admin:list")}],
            [{"text": BTN_ADMIN_SHOW, "callback_data": cb("admin:find")}, {"text": BTN_ADMIN_STATS, "callback_data": cb("admin:stats")}],
            [{"text": BTN_ADMIN_EXIT, "callback_data": cb("admin:exit")}],
        ]
    }


def telegram_cancel_keyboard(admin: bool) -> dict:
    return {
        "inline_keyboard": [[{"text": BTN_CANCEL, "callback_data": cb("admin:exit" if admin else "user:menu")}]]
    }


def get_or_create_telegram_user(chat_id: int, username: str, full_name: str) -> dict:
    data = load_users()
    users = data.setdefault("users", {})
    user = users.setdefault(str(chat_id), {
        "chat_id": chat_id,
        "username": username or "",
        "full_name": full_name or "",
        "license_key": "",
        "created_at": iso_utc(now_utc()),
    })
    user["username"] = username or user.get("username", "")
    user["full_name"] = full_name or user.get("full_name", "")
    users[str(chat_id)] = user
    save_users(data)
    return user


def update_telegram_user_license(chat_id: int, license_key: str) -> None:
    data = load_users()
    users = data.setdefault("users", {})
    for existing_chat_id, existing_user in users.items():
        if str(existing_chat_id) != str(chat_id) and str(existing_user.get("license_key", "")).strip() == license_key:
            raise ValueError("Этот ключ уже привязан к другому Telegram аккаунту")
    user = users.setdefault(str(chat_id), {
        "chat_id": chat_id,
        "username": "",
        "full_name": "",
        "license_key": "",
        "created_at": iso_utc(now_utc()),
    })
    user["license_key"] = license_key
    users[str(chat_id)] = user
    save_users(data)


def get_telegram_user(chat_id: int) -> dict:
    data = load_users()
    return data.setdefault("users", {}).get(str(chat_id), {})


def telegram_support_text(config: dict) -> str:
    support_username = str(config.get("support_username", "")).strip()
    if support_username:
        return f"🛠 Поддержка\n\nПишите: @{support_username}"
    return "🛠 Поддержка пока не настроена"


def telegram_info_text(config: dict) -> str:
    return "ℹ️ Информация\n\n" + (str(config.get("bot_info_text", "")).strip() or "Key system bot")


def telegram_user_welcome_text() -> str:
    return "👋 Привет.\n\nВыберите нужный раздел ниже."


def telegram_admin_welcome_text() -> str:
    return "👑 Админ-панель открыта.\n\nВыберите действие ниже."


def telegram_profile_text(chat_id: int) -> str:
    user = get_telegram_user(chat_id)
    license_key = user.get("license_key", "")
    lines = [
        "👤 Профиль",
        "",
        f"🆔 ID: {chat_id}",
        f"📨 Username: @{user.get('username')}" if user.get("username") else "📨 Username: -",
        f"🙍 Name: {user.get('full_name') or '-'}",
        f"🔑 Key: {license_key or '-'}",
    ]
    if license_key:
        try:
            item = show_license_record(license_key)
            lines.append(f"📌 Status: {item.get('status', '-')}")
            lines.append(f"📅 Expires: {item.get('expires_at', '-')}")
        except ValueError:
            lines.append("⚠️ Status: key not found")
    return "\n".join(lines)


def telegram_my_key_text(chat_id: int) -> str:
    user = get_telegram_user(chat_id)
    license_key = user.get("license_key", "")
    if not license_key:
        return "🔑 Ключ не привязан.\n\nНажмите '🔑 Мой ключ' ещё раз и отправьте свой ключ."
    item = show_license_record(license_key)
    return "🔐 Ваш ключ\n\n" + format_license_details(item)


def telegram_stats_text() -> str:
    db = load_db()
    items = db.get("licenses", [])
    total = len(items)
    active = 0
    frozen = 0
    expired = 0
    for item in items:
        status = normalize_status(item)
        if status == "active" and now_utc() > parse_iso_utc(item["expires_at"]):
            status = "expired"
        if status == "active":
            active += 1
        elif status == "frozen":
            frozen += 1
        elif status == "expired":
            expired += 1
    return (
        f"📊 Статистика\n\n"
        f"🔑 Всего ключей: {total}\n"
        f"🟢 Активных: {active}\n"
        f"🧊 Замороженных: {frozen}\n"
        f"⌛ Истекших: {expired}\n"
        f"🧾 Логов: {len(db.get('auth_logs', []))}"
    )


def license_list_keyboard(items: list[dict], mode: str) -> dict:
    rows = []
    for item in items[:12]:
        rows.append([{"text": item.get("license_key", "-"), "callback_data": cb(f"{mode}:key:{item.get('license_key', '')}")}])
    rows.append([{"text": "🔎 Найти вручную", "callback_data": cb(f"{mode}:manual")}])
    if mode == "admin":
        rows.append([{"text": "⬅️ Назад", "callback_data": cb("admin:menu")}])
    else:
        rows.append([{"text": "⬅️ Назад", "callback_data": cb("user:menu")}])
    return {"inline_keyboard": rows}


def admin_key_actions_keyboard(key: str) -> dict:
    return {
        "inline_keyboard": [
            [{"text": BTN_ADMIN_FREEZE, "callback_data": cb(f"admin:freeze:{key}")}, {"text": BTN_ADMIN_UNFREEZE, "callback_data": cb(f"admin:unfreeze:{key}")}],
            [{"text": BTN_ADMIN_EXTEND, "callback_data": cb(f"admin:extend:{key}")}, {"text": BTN_ADMIN_RESET, "callback_data": cb(f"admin:reset:{key}")}],
            [{"text": "✏️ Редактировать", "callback_data": cb(f"admin:edit:{key}")}, {"text": BTN_ADMIN_DELETE, "callback_data": cb(f"admin:delete:{key}")}],
            [{"text": "⬅️ Назад к списку", "callback_data": cb("admin:list")}],
        ]
    }


def admin_edit_keyboard(key: str) -> dict:
    return {
        "inline_keyboard": [
            [{"text": "✏️ Имя", "callback_data": cb(f"admin:edit_name:{key}")}, {"text": "📦 Product", "callback_data": cb(f"admin:edit_product:{key}")}],
            [{"text": "📝 Notes", "callback_data": cb(f"admin:edit_notes:{key}")}, {"text": "📅 Дней осталось", "callback_data": cb(f"admin:edit_days:{key}")}],
            [{"text": "⬅️ К карточке ключа", "callback_data": cb(f"admin:key:{key}")}],
        ]
    }


def start_telegram_action(chat_id: int, action: str, admin: bool, key: str = "") -> dict:
    TELEGRAM_CHAT_STATES[chat_id] = {"action": action, "step": "start", "data": {}, "admin": admin}
    if key:
        TELEGRAM_CHAT_STATES[chat_id]["data"]["key"] = key
    prompts = {
        "bind_my_key": "Отправьте свой ключ",
        "admin_create": "Введите key",
        "admin_manual_show": "Введите key для поиска",
        "admin_extend": "Введите количество дней",
        "admin_edit_name": "Введите новое имя",
        "admin_edit_product": "Введите новый product",
        "admin_edit_notes": "Введите новые notes",
        "admin_edit_days": "Введите сколько дней должно остаться",
    }
    return {"text": prompts[action], "reply_markup": telegram_cancel_keyboard(admin)}


def finish_telegram_action(chat_id: int) -> None:
    TELEGRAM_CHAT_STATES.pop(chat_id, None)


def main_keyboard_for(chat_id: int) -> dict:
    state = TELEGRAM_CHAT_STATES.get(chat_id)
    if state and state.get("admin"):
        return telegram_admin_keyboard()
    return telegram_user_keyboard()


def process_telegram_state(chat_id: int, text: str) -> dict | None:
    state = TELEGRAM_CHAT_STATES.get(chat_id)
    if not state:
        return None

    if text == BTN_CANCEL:
        admin = bool(state.get("admin"))
        finish_telegram_action(chat_id)
        return {"text": "↩️ Действие отменено", "reply_markup": telegram_admin_keyboard() if admin else telegram_user_keyboard()}

    action = state["action"]
    step = state["step"]
    data = state["data"]

    try:
        if action == "bind_my_key":
            item = show_license_record(text)
            update_telegram_user_license(chat_id, item["license_key"])
            finish_telegram_action(chat_id)
            return {"text": "✅ Ключ привязан\n\n" + format_license_details(item), "reply_markup": telegram_user_keyboard()}

        if action == "admin_create":
            if step == "start":
                data["key"] = text
                state["step"] = "name"
                return {"text": "Введите name", "reply_markup": telegram_cancel_keyboard(True)}
            if step == "name":
                data["name"] = text
                state["step"] = "product"
                return {"text": "Введите product", "reply_markup": telegram_cancel_keyboard(True)}
            if step == "product":
                data["product"] = text
                state["step"] = "days"
                return {"text": "Введите days", "reply_markup": telegram_cancel_keyboard(True)}
            if step == "days":
                data["days"] = int(text)
                state["step"] = "notes"
                return {"text": "Введите notes или '-' для пропуска", "reply_markup": telegram_cancel_keyboard(True)}
            if step == "notes":
                notes = "" if text == "-" else text
                item = create_license_record(data["key"], data["name"], data["days"], data["product"], notes)
                finish_telegram_action(chat_id)
                return {"text": "✅ Ключ создан\n\n" + format_license_details(item), "reply_markup": admin_key_actions_keyboard(item['license_key'])}

        if action == "admin_manual_show":
            item = show_license_record(text)
            finish_telegram_action(chat_id)
            return {"text": "🔎 Информация о ключе\n\n" + format_license_details(item), "reply_markup": admin_key_actions_keyboard(item["license_key"])}

        if action == "admin_extend":
            item = extend_license_record(data["key"], int(text))
            finish_telegram_action(chat_id)
            return {"text": "✅ Ключ продлен\n\n" + format_license_details(item), "reply_markup": admin_key_actions_keyboard(item["license_key"])}

        if action == "admin_edit_name":
            item = update_license_record(data["key"], name=text)
            finish_telegram_action(chat_id)
            return {"text": "✏️ Имя обновлено\n\n" + format_license_details(item), "reply_markup": admin_edit_keyboard(item["license_key"])}

        if action == "admin_edit_product":
            item = update_license_record(data["key"], product=text)
            finish_telegram_action(chat_id)
            return {"text": "📦 Product обновлен\n\n" + format_license_details(item), "reply_markup": admin_edit_keyboard(item["license_key"])}

        if action == "admin_edit_notes":
            item = update_license_record(data["key"], notes="" if text == "-" else text)
            finish_telegram_action(chat_id)
            return {"text": "📝 Notes обновлены\n\n" + format_license_details(item), "reply_markup": admin_edit_keyboard(item["license_key"])}

        if action == "admin_edit_days":
            item = set_license_days_left(data["key"], int(text))
            finish_telegram_action(chat_id)
            return {"text": "📅 Срок обновлен\n\n" + format_license_details(item), "reply_markup": admin_edit_keyboard(item["license_key"])}
    except ValueError as exc:
        admin = bool(state.get("admin"))
        finish_telegram_action(chat_id)
        return {"text": f"⚠️ {exc}", "reply_markup": telegram_admin_keyboard() if admin else telegram_user_keyboard()}
    except Exception as exc:
        admin = bool(state.get("admin"))
        finish_telegram_action(chat_id)
        return {"text": f"❌ Error: {exc}", "reply_markup": telegram_admin_keyboard() if admin else telegram_user_keyboard()}

    admin = bool(state.get("admin"))
    finish_telegram_action(chat_id)
    return {"text": "❓ Неизвестное состояние", "reply_markup": telegram_admin_keyboard() if admin else telegram_user_keyboard()}


def telegram_api(config: dict, method: str, payload: dict) -> dict:
    token = str(config.get("telegram_token", "")).strip()
    if not token:
        raise RuntimeError("telegram_token is empty in config.json")

    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url=f"https://api.telegram.org/bot{token}/{method}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=35) as response:
        return json.loads(response.read().decode("utf-8"))


def telegram_send_message(config: dict, chat_id: int, text: str, reply_markup: dict | None = None) -> None:
    payload = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": True,
    }
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    telegram_api(config, "sendMessage", payload)


def telegram_send_sticker(config: dict, chat_id: int, sticker: str) -> None:
    if not sticker:
        return
    telegram_api(config, "sendSticker", {
        "chat_id": chat_id,
        "sticker": sticker,
    })


def telegram_answer_callback(config: dict, callback_id: str) -> None:
    telegram_api(config, "answerCallbackQuery", {"callback_query_id": callback_id})


def default_sticker_for_reply(config: dict, chat_id: int, reply: dict) -> str:
    sticker = str(reply.get("sticker", "")).strip()
    if sticker:
        return sticker
    if is_single_admin(config, chat_id):
        return str(config.get("admin_sticker_id", "")).strip()
    return str(config.get("user_sticker_id", "")).strip()


def is_telegram_admin(config: dict, chat_id: int) -> bool:
    return is_single_admin(config, chat_id)


def save_telegram_update_offset(update_id: int) -> None:
    config = load_config()
    config["telegram_last_update_id"] = update_id
    save_config(config)


def bind_telegram_admin(chat_id: int) -> None:
    config = load_config()
    chat_ids = {str(item) for item in config.get("telegram_admin_chat_ids", [])}
    chat_ids.add(str(chat_id))
    config["telegram_admin_chat_ids"] = sorted(chat_ids)
    save_config(config)


def handle_telegram_callback(chat_id: int, username: str, full_name: str, data: str) -> dict:
    config = load_config()
    get_or_create_telegram_user(chat_id, username, full_name)

    if data == "user:menu":
        finish_telegram_action(chat_id)
        return {"text": telegram_user_welcome_text(), "reply_markup": telegram_user_keyboard()}
    if data == "user:profile":
        return {"text": telegram_profile_text(chat_id), "reply_markup": telegram_user_keyboard()}
    if data == "user:support":
        return {"text": telegram_support_text(config), "reply_markup": telegram_user_keyboard()}
    if data == "user:info":
        return {"text": telegram_info_text(config), "reply_markup": telegram_user_keyboard()}
    if data == "user:key":
        user = get_telegram_user(chat_id)
        if user.get("license_key"):
            try:
                return {"text": telegram_my_key_text(chat_id), "reply_markup": telegram_user_keyboard()}
            except ValueError:
                return start_telegram_action(chat_id, "bind_my_key", False)
        return start_telegram_action(chat_id, "bind_my_key", False)

    if not is_single_admin(config, chat_id):
        return {"text": "⛔ Нет доступа", "reply_markup": telegram_user_keyboard()}

    if data == "admin:menu":
        finish_telegram_action(chat_id)
        return {"text": telegram_admin_welcome_text(), "reply_markup": telegram_admin_keyboard()}
    if data == "admin:exit":
        finish_telegram_action(chat_id)
        return {"text": "🚪 Вы вышли из админки", "reply_markup": telegram_user_keyboard()}
    if data == "admin:create":
        return start_telegram_action(chat_id, "admin_create", True)
    if data == "admin:list":
        items = list_license_records(20)
        return {"text": "📭 Ключей нет" if not items else "📋 Список ключей", "reply_markup": telegram_admin_keyboard() if not items else license_list_keyboard(items, "admin")}
    if data == "admin:find" or data == "admin:manual":
        return start_telegram_action(chat_id, "admin_manual_show", True)
    if data == "admin:stats":
        return {"text": telegram_stats_text(), "reply_markup": telegram_admin_keyboard()}
    if data.startswith("admin:key:"):
        key = data.split(":", 2)[2]
        item = show_license_record(key)
        return {"text": "🔎 Информация о ключе\n\n" + format_license_details(item), "reply_markup": admin_key_actions_keyboard(key)}
    if data.startswith("admin:freeze:"):
        key = data.split(":", 2)[2]
        item = freeze_license_record(key)
        return {"text": "🧊 Ключ заморожен\n\n" + format_license_details(item), "reply_markup": admin_key_actions_keyboard(key)}
    if data.startswith("admin:unfreeze:"):
        key = data.split(":", 2)[2]
        item = unfreeze_license_record(key)
        return {"text": "🟢 Ключ разморожен\n\n" + format_license_details(item), "reply_markup": admin_key_actions_keyboard(key)}
    if data.startswith("admin:reset:"):
        key = data.split(":", 2)[2]
        item = reset_hwid_record(key)
        return {"text": "♻️ HWID сброшен\n\n" + format_license_details(item), "reply_markup": admin_key_actions_keyboard(key)}
    if data.startswith("admin:delete:"):
        key = data.split(":", 2)[2]
        delete_license_record(key)
        items = list_license_records(20)
        return {"text": f"🗑 Ключ удален: {key}", "reply_markup": telegram_admin_keyboard() if not items else license_list_keyboard(items, "admin")}
    if data.startswith("admin:extend:"):
        key = data.split(":", 2)[2]
        return start_telegram_action(chat_id, "admin_extend", True, key)
    if data.startswith("admin:edit:"):
        key = data.split(":", 2)[2]
        item = show_license_record(key)
        return {"text": "✏️ Редактирование ключа\n\n" + format_license_details(item), "reply_markup": admin_edit_keyboard(key)}
    if data.startswith("admin:edit_name:"):
        return start_telegram_action(chat_id, "admin_edit_name", True, data.split(":", 2)[2])
    if data.startswith("admin:edit_product:"):
        return start_telegram_action(chat_id, "admin_edit_product", True, data.split(":", 2)[2])
    if data.startswith("admin:edit_notes:"):
        return start_telegram_action(chat_id, "admin_edit_notes", True, data.split(":", 2)[2])
    if data.startswith("admin:edit_days:"):
        return start_telegram_action(chat_id, "admin_edit_days", True, data.split(":", 2)[2])

    return {"text": "❓ Неизвестная кнопка", "reply_markup": main_keyboard_for(chat_id)}


def handle_telegram_command(chat_id: int, username: str, full_name: str, text: str) -> dict:
    config = load_config()
    get_or_create_telegram_user(chat_id, username, full_name)
    parts = text.strip().split()
    if not parts:
        return {"text": "Пустое сообщение", "reply_markup": telegram_user_keyboard()}

    state_reply = process_telegram_state(chat_id, text)
    if state_reply is not None:
        return state_reply

    command = parts[0].split("@", 1)[0].lower()

    if command == "/start":
        return {
            "text": telegram_user_welcome_text(),
            "reply_markup": telegram_user_keyboard(),
            "sticker": str(config.get("user_sticker_id", "")).strip(),
        }

    if command == "/help":
        return {
            "text": "❓ Помощь\n\nДоступно: Профиль, Поддержка, Мой ключ, Информация.\nДля админа: /admin",
            "reply_markup": telegram_user_keyboard(),
        }

    if text == BTN_PROFILE:
        return {"text": telegram_profile_text(chat_id), "reply_markup": telegram_user_keyboard()}

    if text == BTN_SUPPORT:
        return {"text": telegram_support_text(config), "reply_markup": telegram_user_keyboard()}

    if text == BTN_INFO:
        return {"text": telegram_info_text(config), "reply_markup": telegram_user_keyboard()}

    if text == BTN_MY_KEY:
        user = get_telegram_user(chat_id)
        if user.get("license_key"):
            try:
                return {"text": telegram_my_key_text(chat_id), "reply_markup": telegram_user_keyboard()}
            except ValueError:
                return start_telegram_action(chat_id, "bind_my_key", False)
        return start_telegram_action(chat_id, "bind_my_key", False)

    if command == "/admin":
        if not is_single_admin(config, chat_id):
            return {"text": "⛔ Нет доступа", "reply_markup": telegram_user_keyboard()}
        finish_telegram_action(chat_id)
        return {"text": telegram_admin_welcome_text(), "reply_markup": telegram_admin_keyboard(), "sticker": str(config.get("admin_sticker_id", "")).strip()}

    if text == BTN_ADMIN_EXIT:
        finish_telegram_action(chat_id)
        return {"text": "🚪 Вы вышли из админки", "reply_markup": telegram_user_keyboard()}

    if not is_single_admin(config, chat_id):
        return {"text": "📌 Используйте меню ниже", "reply_markup": telegram_user_keyboard()}

    try:
        if command == "/list":
            limit = 10
            if len(parts) >= 2:
                limit = max(1, min(50, int(parts[1])))
            items = list_license_records(limit)
            if not items:
                return {"text": "📭 Ключей нет", "reply_markup": telegram_admin_keyboard()}
            return {"text": "📋 Список ключей", "reply_markup": license_list_keyboard(items, "admin")}

        if command == "/show":
            if len(parts) != 2:
                return {"text": "Usage: /show <key>", "reply_markup": telegram_admin_keyboard()}
            item = show_license_record(parts[1])
            return {"text": "🔎 Информация о ключе\n\n" + format_license_details(item), "reply_markup": admin_key_actions_keyboard(item["license_key"])}

        if command == "/create":
            if len(parts) < 5:
                return {"text": "Usage: /create <key> <name> <days> <product> [notes]", "reply_markup": telegram_admin_keyboard()}
            notes = " ".join(parts[5:]) if len(parts) > 5 else ""
            item = create_license_record(parts[1], parts[2], int(parts[3]), parts[4], notes)
            return {"text": "✅ Created\n\n" + format_license_details(item), "reply_markup": admin_key_actions_keyboard(item["license_key"])}

        if command == "/freeze":
            if len(parts) != 2:
                return {"text": "Usage: /freeze <key>", "reply_markup": telegram_admin_keyboard()}
            item = freeze_license_record(parts[1])
            return {"text": "🧊 Frozen\n\n" + format_license_details(item), "reply_markup": admin_key_actions_keyboard(item["license_key"])}

        if command == "/unfreeze":
            if len(parts) != 2:
                return {"text": "Usage: /unfreeze <key>", "reply_markup": telegram_admin_keyboard()}
            item = unfreeze_license_record(parts[1])
            return {"text": "🟢 Unfrozen\n\n" + format_license_details(item), "reply_markup": admin_key_actions_keyboard(item["license_key"])}

        if command == "/extend":
            if len(parts) != 3:
                return {"text": "Usage: /extend <key> <days>", "reply_markup": telegram_admin_keyboard()}
            item = extend_license_record(parts[1], int(parts[2]))
            return {"text": "➕ Extended\n\n" + format_license_details(item), "reply_markup": admin_key_actions_keyboard(item["license_key"])}

        if command == "/reset_hwid":
            if len(parts) != 2:
                return {"text": "Usage: /reset_hwid <key>", "reply_markup": telegram_admin_keyboard()}
            item = reset_hwid_record(parts[1])
            return {"text": "♻️ HWID reset\n\n" + format_license_details(item), "reply_markup": admin_key_actions_keyboard(item["license_key"])}

        if command == "/delete":
            if len(parts) != 2:
                return {"text": "Usage: /delete <key>", "reply_markup": telegram_admin_keyboard()}
            delete_license_record(parts[1])
            return {"text": f"🗑 Deleted {parts[1]}", "reply_markup": telegram_admin_keyboard()}
    except ValueError as exc:
        return {"text": f"⚠️ {exc}", "reply_markup": telegram_admin_keyboard()}
    except Exception as exc:
        return {"text": f"❌ Error: {exc}", "reply_markup": telegram_admin_keyboard()}

    return {"text": "❓ Неизвестная команда", "reply_markup": main_keyboard_for(chat_id)}


def telegram_poll_once() -> None:
    config = load_config()
    offset = int(config.get("telegram_last_update_id", 0)) + 1
    result = telegram_api(config, "getUpdates", {
        "offset": offset,
        "timeout": 25,
        "allowed_updates": ["message", "callback_query"],
    })
    for update in result.get("result", []):
        update_id = int(update.get("update_id", 0))
        save_telegram_update_offset(update_id)
        reply = None
        chat_id = None

        message = update.get("message") or {}
        if message:
            chat = message.get("chat") or {}
            chat_id = chat.get("id")
            username = str(message.get("from", {}).get("username", "") or "")
            first_name = str(message.get("from", {}).get("first_name", "") or "")
            last_name = str(message.get("from", {}).get("last_name", "") or "")
            full_name = (first_name + " " + last_name).strip()
            text = str(message.get("text", "")).strip()
            if chat_id and text:
                reply = handle_telegram_command(int(chat_id), username, full_name, text)

        callback_query = update.get("callback_query") or {}
        if callback_query:
            callback_id = str(callback_query.get("id", ""))
            message = callback_query.get("message") or {}
            chat_id = (message.get("chat") or {}).get("id")
            from_user = callback_query.get("from") or {}
            username = str(from_user.get("username", "") or "")
            first_name = str(from_user.get("first_name", "") or "")
            last_name = str(from_user.get("last_name", "") or "")
            full_name = (first_name + " " + last_name).strip()
            data = str(callback_query.get("data", "")).strip()
            if callback_id:
                try:
                    telegram_answer_callback(load_config(), callback_id)
                except Exception as exc:
                    print(f"Telegram callback ack error: {exc}")
            if chat_id and data:
                reply = handle_telegram_callback(int(chat_id), username, full_name, data)

        if not chat_id or not reply:
            continue
        try:
            sticker = default_sticker_for_reply(load_config(), int(chat_id), reply)
            if sticker:
                telegram_send_sticker(load_config(), int(chat_id), sticker)
            telegram_send_message(load_config(), int(chat_id), reply["text"], reply.get("reply_markup"))
        except Exception as exc:
            print(f"Telegram send error: {exc}")


def run_telegram_bot_forever() -> None:
    print("Telegram bot polling started")
    while True:
        try:
            telegram_poll_once()
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, RuntimeError) as exc:
            print(f"Telegram bot error: {exc}")
            time.sleep(5)
        except Exception as exc:
            print(f"Telegram bot unexpected error: {exc}")
            time.sleep(5)


def html_page(title: str, body: str) -> bytes:
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    :root {{
      --bg0: #f7f9ff;
      --bg1: #eef3ff;
      --panel: rgba(255,255,255,0.86);
      --panel2: rgba(255,255,255,0.96);
      --line: rgba(31,51,122,0.10);
      --ink: #17203b;
      --muted: #6e7897;
      --accent: #4b63ff;
      --accent2: #7ecbff;
      --good: #16b364;
      --warn: #f59e0b;
      --bad: #ef4444;
      --shadow: 0 24px 70px rgba(71,89,149,0.16);
      --glass-blur: blur(18px);
      --r: 24px;
      --cursor-x: 50%;
      --cursor-y: 50%;
      --cursor-size: 280px;
      --cursor-glow: rgba(75,99,255,0.12);
    }}
    * {{ box-sizing: border-box; }}
    html, body {{ height: 100%; }}
    body {{
      margin: 0;
      font-family: "Segoe UI Variable Text", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(620px 420px at 8% 5%, rgba(75,99,255,0.16), transparent 60%),
        radial-gradient(780px 520px at 92% 10%, rgba(126,203,255,0.16), transparent 64%),
        linear-gradient(180deg, #fbfcff 0%, #eef3ff 54%, #f8faff 100%);
      overflow-x: hidden;
      opacity: 0;
      transform: translateY(8px);
      transition: opacity .36s ease, transform .36s ease;
    }}
    body.page-loaded {{
      opacity: 1;
      transform: none;
    }}
    body.page-leaving {{
      opacity: 0;
      transform: translateY(6px);
      filter: saturate(.95);
    }}
    body::before {{
      content: "";
      position: fixed;
      inset: 0;
      background: radial-gradient(circle at var(--cursor-x) var(--cursor-y), var(--cursor-glow), transparent calc(var(--cursor-size) * 0.9));
      pointer-events: none;
      z-index: 0;
      transition: background .12s linear;
    }}
    body::after {{
      content: "";
      position: fixed;
      inset: 0;
      background:
        linear-gradient(180deg, rgba(255,255,255,0.52), rgba(255,255,255,0.14)),
        repeating-linear-gradient(90deg, rgba(75,99,255,0.02) 0, rgba(75,99,255,0.02) 1px, transparent 1px, transparent 120px);
      pointer-events: none;
      z-index: 0;
    }}
    a {{ color: inherit; text-decoration: none; }}
    .app {{
      position: relative;
      z-index: 1;
      display: grid;
      grid-template-columns: 280px 1fr;
      min-height: 100vh;
    }}
    .sidebar {{
      padding: 22px 18px;
      border-right: 1px solid var(--line);
      background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.01));
      -webkit-backdrop-filter: var(--glass-blur);
      backdrop-filter: var(--glass-blur);
      position: sticky;
      top: 0;
      height: 100vh;
      overflow: hidden;
      isolation: isolate;
    }}
    .sidebar::before,
    .card::before,
    .topbar::before,
    .kpi::before,
    .btn::before,
    input::before,
    select::before,
    textarea::before {{
      content: "";
      position: absolute;
      inset: -80px;
      background: radial-gradient(circle at var(--cursor-x) var(--cursor-y), rgba(155,225,255,0.18), transparent 38%);
      pointer-events: none;
      opacity: .75;
      z-index: 0;
    }}
    .brand,
    .nav a,
    .topbar,
    .card,
    .kpi,
    input,
    select,
    textarea,
    .btn, button, input[type="submit"] {{
      position: relative;
      overflow: hidden;
      isolation: isolate;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 12px;
      border-radius: var(--r);
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.09);
      box-shadow: 0 10px 30px rgba(0,0,0,0.25);
      margin-bottom: 16px;
      -webkit-backdrop-filter: var(--glass-blur);
      backdrop-filter: var(--glass-blur);
    }}
    .logo {{
      width: 44px; height: 44px;
      border-radius: 14px;
      background: radial-gradient(circle at top left, var(--accent2), var(--accent));
      box-shadow: 0 0 22px rgba(40,140,255,0.45), 0 12px 28px rgba(31,87,255,0.28);
    }}
    .brand h1 {{
      font-size: 16px;
      margin: 0;
      letter-spacing: 0.02em;
    }}
    .brand p {{
      margin: 2px 0 0;
      color: var(--muted);
      font-size: 12px;
    }}
    .nav {{
      display: grid;
      gap: 8px;
      margin-top: 14px;
    }}
    .nav a {{
      text-decoration: none;
      padding: 11px 12px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,0.08);
      background: rgba(255,255,255,0.035);
      transition: transform .16s ease, background .16s ease, border-color .16s ease, box-shadow .16s ease;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      -webkit-backdrop-filter: blur(12px);
      backdrop-filter: blur(12px);
    }}
    .nav a:hover {{
      transform: translateY(-1px);
      background: rgba(255,255,255,0.07);
      border-color: rgba(93,154,255,0.32);
      box-shadow: 0 0 0 1px rgba(159,211,255,0.12), 0 10px 24px rgba(0,0,0,0.3);
    }}
    .nav .active {{
      background: linear-gradient(90deg, rgba(31,87,255,0.30), rgba(0,214,255,0.16));
      border-color: rgba(98,156,255,0.42);
      box-shadow: 0 0 0 1px rgba(130,198,255,0.24), 0 12px 30px rgba(0,132,255,0.22);
    }}
    .nav small {{ color: var(--muted); }}
    .nav .label {{ font-weight: 700; }}
    .nav .hint {{ font-size: 11px; color: var(--muted); }}
    .wrap {{ min-height: 100vh; }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .actions form {{ margin: 0; }}
    .section-title {{ margin: 0 0 12px; }}
    .content {{
      padding: 24px 22px 42px;
      position: relative;
      z-index: 1;
    }}
    .topbar {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      margin-bottom: 16px;
      padding: 10px 12px;
      border-radius: 16px;
      border: 1px solid rgba(255,255,255,0.1);
      background: rgba(255,255,255,0.03);
      -webkit-backdrop-filter: var(--glass-blur);
      backdrop-filter: var(--glass-blur);
    }}
    .title h2 {{
      margin: 0;
      font-size: 18px;
      letter-spacing: 0.01em;
    }}
    .title .muted {{
      margin-top: 4px;
      color: var(--muted);
      font-size: 12px;
    }}
    .card {{
      background: linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02));
      border: 1px solid rgba(255,255,255,0.12);
      border-radius: var(--r);
      box-shadow: var(--shadow);
      padding: 16px;
      -webkit-backdrop-filter: var(--glass-blur);
      backdrop-filter: var(--glass-blur);
      animation: panelIn .35s ease both;
    }}
    .grid {{
      display: grid;
      gap: 14px;
    }}
    .grid.cols3 {{
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }}
    .kpi {{
      padding: 14px;
      border-radius: 16px;
      border: 1px solid rgba(255,255,255,0.12);
      background: linear-gradient(180deg, rgba(255,255,255,0.07), rgba(255,255,255,0.03));
      -webkit-backdrop-filter: blur(10px);
      backdrop-filter: blur(10px);
      animation: panelIn .35s ease both;
    }}
    .kpi b {{ font-size: 20px; display: block; }}
    .kpi span {{ color: var(--muted); font-size: 12px; }}
    .flash {{
      padding: 12px 12px;
      border-radius: 14px;
      border: 1px solid rgba(56,138,255,0.36);
      background: rgba(56,138,255,0.14);
      margin-bottom: 14px;
      -webkit-backdrop-filter: blur(10px);
      backdrop-filter: blur(10px);
      animation: panelIn .35s ease both;
    }}
    .row {{
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }}
    input, select, textarea {{
      width: 100%;
      border: 1px solid rgba(255,255,255,0.11);
      border-radius: 14px;
      padding: 10px 12px;
      background: rgba(8,14,30,0.55);
      color: var(--ink);
      outline: none;
      transition: border-color .16s ease, box-shadow .16s ease, background .16s ease;
      -webkit-backdrop-filter: blur(10px);
      backdrop-filter: blur(10px);
    }}
    input:focus, select:focus, textarea:focus {{
      border-color: rgba(121,184,255,0.5);
      box-shadow: 0 0 0 3px rgba(80,154,255,0.16);
      background: rgba(8,16,34,0.7);
    }}
    textarea {{ min-height: 94px; resize: vertical; }}
    input::placeholder, textarea::placeholder {{ color: rgba(255,255,255,0.45); }}
    .btn, button, input[type="submit"] {{
      cursor: pointer;
      border: 1px solid rgba(255,255,255,0.14);
      background: rgba(255,255,255,0.06);
      color: var(--ink);
      padding: 10px 12px;
      border-radius: 14px;
      font-weight: 700;
      letter-spacing: 0.01em;
      transition: transform .16s ease, background .16s ease, border-color .16s ease, box-shadow .16s ease, filter .16s ease;
      user-select: none;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      -webkit-backdrop-filter: blur(10px);
      backdrop-filter: blur(10px);
      box-shadow: 0 0 0 rgba(138,205,255,0), inset 0 0 0 rgba(255,255,255,0);
      z-index: 1;
    }}
    .btn::after, button::after, input[type="submit"]::after {{
      content: "";
      position: absolute;
      top: 0;
      left: -120%;
      width: 120%;
      height: 100%;
      background: linear-gradient(90deg, rgba(255,255,255,0), rgba(255,255,255,0.35), rgba(255,255,255,0));
      pointer-events: none;
      z-index: -1;
      opacity: 0;
    }}
    .btn:hover, button:hover, input[type="submit"]:hover {{
      transform: translateY(-1px);
      background: rgba(255,255,255,0.11);
      border-color: rgba(111,176,255,0.36);
      box-shadow: 0 0 22px rgba(79,154,255,0.28), inset 0 0 18px rgba(255,255,255,0.03);
    }}
    .btn.primary, button.primary, input[type="submit"].primary {{
      background: linear-gradient(90deg, rgba(31,87,255,0.75), rgba(0,214,255,0.45));
      border-color: rgba(85,164,255,0.42);
    }}
    .btn.good, button.good, input[type="submit"].good {{
      background: rgba(38,208,124,0.16);
      border-color: rgba(38,208,124,0.35);
    }}
    .btn.warn, button.warn, input[type="submit"].warn {{
      background: rgba(255,176,32,0.15);
      border-color: rgba(255,176,32,0.35);
    }}
    .btn.alt, button.alt, input[type="submit"].alt {{
      background: rgba(140,161,255,0.16);
      border-color: rgba(140,161,255,0.35);
    }}
    .btn.bad, button.bad, input[type="submit"].bad {{
      background: rgba(255,77,109,0.16);
      border-color: rgba(255,77,109,0.35);
    }}
    .btn.small, button.small, input[type="submit"].small {{
      padding: 8px 10px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 700;
    }}
    .btn.press-wave, button.press-wave, input[type="submit"].press-wave {{
      animation: pressWave .55s ease;
      filter: grayscale(1) contrast(1.1);
      box-shadow: 0 0 26px rgba(185,228,255,0.58), 0 0 46px rgba(98,174,255,0.24);
    }}
    .btn.press-wave::after, button.press-wave::after, input[type="submit"].press-wave::after {{
      animation: sweepFill .55s ease;
      opacity: 1;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th, td {{
      padding: 10px 10px;
      border-bottom: 1px solid rgba(255,255,255,0.08);
      vertical-align: top;
    }}
    th {{
      color: rgba(255,255,255,0.55);
      font-weight: 800;
      letter-spacing: 0.08em;
      font-size: 11px;
      text-transform: uppercase;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 10px;
      border-radius: 999px;
      font-weight: 800;
      font-size: 12px;
      border: 1px solid rgba(255,255,255,0.14);
      background: rgba(255,255,255,0.05);
      -webkit-backdrop-filter: blur(8px);
      backdrop-filter: blur(8px);
    }}
    .pill::before {{
      content: "";
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: rgba(255,255,255,0.45);
      box-shadow: 0 0 0 3px rgba(255,255,255,0.08);
    }}
    .pill.active {{ border-color: rgba(38,208,124,0.35); background: rgba(38,208,124,0.10); }}
    .pill.active::before {{ background: var(--good); box-shadow: 0 0 0 3px rgba(38,208,124,0.18); }}
    .pill.frozen {{ border-color: rgba(255,176,32,0.35); background: rgba(255,176,32,0.10); }}
    .pill.frozen::before {{ background: var(--warn); box-shadow: 0 0 0 3px rgba(255,176,32,0.18); }}
    .pill.banned {{ border-color: rgba(255,77,109,0.35); background: rgba(255,77,109,0.10); }}
    .pill.banned::before {{ background: var(--bad); box-shadow: 0 0 0 3px rgba(255,77,109,0.18); }}
    .pill.expired {{ border-color: rgba(255,255,255,0.18); background: rgba(255,255,255,0.03); color: rgba(255,255,255,0.60); }}
    .pill.expired::before {{ background: rgba(255,255,255,0.35); }}
    .split {{
      display: grid;
      grid-template-columns: 1fr 380px;
      gap: 14px;
      align-items: start;
    }}
    .stack {{ display: grid; gap: 10px; }}
    .inline {{ display: inline; }}
    .muted {{ color: var(--muted); }}
    .code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
      padding: 2px 6px;
      border-radius: 10px;
      border: 1px solid rgba(255,255,255,0.10);
      background: rgba(0,0,0,0.22);
      -webkit-backdrop-filter: blur(8px);
      backdrop-filter: blur(8px);
    }}
    .footer {{
      margin-top: 14px;
      color: rgba(255,255,255,0.50);
      font-size: 12px;
    }}
    .login {{
      max-width: 520px;
      margin: 10vh auto 0;
      padding: 18px;
      animation: panelIn .36s ease both;
    }}
    .wrap {{
      min-height: 100vh;
      padding: 26px;
      position: relative;
      z-index: 1;
    }}
    .eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: #4b63ff;
      background: rgba(75,99,255,0.08);
      border: 1px solid rgba(75,99,255,0.12);
    }}
    .eyebrow.inverse {{
      color: rgba(239,244,255,0.9);
      background: rgba(255,255,255,0.08);
      border-color: rgba(255,255,255,0.14);
    }}
    input, select, textarea {{
      border: 1px solid rgba(39,61,135,0.12);
      background: rgba(255,255,255,0.92);
      color: var(--ink);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.72), 0 10px 26px rgba(92,114,180,0.08);
      -webkit-backdrop-filter: blur(12px);
      backdrop-filter: blur(12px);
    }}
    input:focus, select:focus, textarea:focus {{
      border-color: rgba(75,99,255,0.34);
      box-shadow: 0 0 0 4px rgba(75,99,255,0.10), 0 16px 34px rgba(92,114,180,0.10);
      background: rgba(255,255,255,0.98);
    }}
    input::placeholder, textarea::placeholder {{
      color: #9aa6c7;
    }}
    .btn, button, input[type="submit"] {{
      border: 1px solid rgba(75,99,255,0.12);
      background: linear-gradient(180deg, #ffffff 0%, #eef3ff 100%);
      color: #24345f;
      box-shadow: 0 14px 30px rgba(75,99,255,0.12);
    }}
    .btn:hover, button:hover, input[type="submit"]:hover {{
      background: linear-gradient(180deg, #ffffff 0%, #e6eeff 100%);
      border-color: rgba(75,99,255,0.24);
      box-shadow: 0 18px 36px rgba(75,99,255,0.16);
    }}
    .btn.primary, button.primary, input[type="submit"].primary {{
      color: #ffffff;
      background: linear-gradient(135deg, #4b63ff 0%, #6d7cff 55%, #93dbff 100%);
      border-color: transparent;
      box-shadow: 0 20px 40px rgba(75,99,255,0.26);
    }}
    .btn.good, button.good, input[type="submit"].good {{
      color: #0f5a32;
      background: linear-gradient(180deg, #f0fff7 0%, #d8fbe8 100%);
      border-color: rgba(22,179,100,0.22);
    }}
    .btn.warn, button.warn, input[type="submit"].warn {{
      color: #7f4d12;
      background: linear-gradient(180deg, #fff8eb 0%, #ffe7bb 100%);
      border-color: rgba(245,158,11,0.22);
    }}
    .btn.alt, button.alt, input[type="submit"].alt {{
      color: #30436b;
      background: linear-gradient(180deg, #f3f5ff 0%, #e0e6ff 100%);
      border-color: rgba(124,144,255,0.24);
    }}
    .btn.bad, button.bad, input[type="submit"].bad {{
      color: #8b2442;
      background: linear-gradient(180deg, #fff0f4 0%, #ffd9e3 100%);
      border-color: rgba(239,68,68,0.20);
    }}
    .flash {{
      background: linear-gradient(135deg, rgba(75,99,255,0.12), rgba(126,203,255,0.14));
      border: 1px solid rgba(75,99,255,0.16);
      color: #22345e;
      box-shadow: 0 16px 30px rgba(75,99,255,0.10);
    }}
    .field-label {{
      display: block;
      margin-bottom: 8px;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.04em;
      color: #4e5b7f;
      text-transform: uppercase;
    }}
    .dashboard-shell {{
      display: grid;
      grid-template-columns: 260px minmax(0, 1fr);
      gap: 24px;
      min-height: calc(100vh - 52px);
    }}
    .dashboard-sidebar {{
      position: sticky;
      top: 26px;
      height: calc(100vh - 52px);
      display: grid;
      align-content: start;
      gap: 18px;
      padding: 20px;
      border-radius: 30px;
      border: 1px solid rgba(39,61,135,0.10);
      background: rgba(255,255,255,0.76);
      box-shadow: var(--shadow);
      -webkit-backdrop-filter: blur(20px);
      backdrop-filter: blur(20px);
    }}
    .sidebar-brand {{
      display: flex;
      align-items: center;
      gap: 14px;
      padding: 6px 4px 12px;
    }}
    .brand-mark {{
      width: 52px;
      height: 52px;
      border-radius: 18px;
      background: linear-gradient(145deg, #4b63ff 0%, #7ed0ff 100%);
      box-shadow: 0 18px 40px rgba(75,99,255,0.26);
      position: relative;
    }}
    .brand-mark::before,
    .brand-mark::after {{
      content: "";
      position: absolute;
      bottom: 12px;
      width: 6px;
      border-radius: 999px;
      background: rgba(255,255,255,0.92);
    }}
    .brand-mark::before {{
      left: 15px;
      height: 26px;
      box-shadow: 12px 8px 0 0 rgba(255,255,255,0.72), 24px -2px 0 0 rgba(255,255,255,0.42);
    }}
    .brand-mark::after {{
      left: 27px;
      height: 20px;
      opacity: 0;
    }}
    .sidebar-brand h1 {{
      margin: 0;
      font-size: 18px;
      line-height: 1.1;
    }}
    .sidebar-brand p {{
      margin: 6px 0 0;
      color: var(--muted);
      font-size: 13px;
    }}
    .sidebar-group {{
      display: grid;
      gap: 10px;
    }}
    .group-title {{
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: #8a95b4;
      padding: 0 6px;
    }}
    .menu-link {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      padding: 14px 16px;
      border-radius: 20px;
      border: 1px solid rgba(75,99,255,0.08);
      background: rgba(255,255,255,0.72);
      box-shadow: 0 12px 24px rgba(75,99,255,0.06);
      transition: transform .16s ease, box-shadow .16s ease, border-color .16s ease;
    }}
    .menu-link:hover {{
      transform: translateY(-1px);
      border-color: rgba(75,99,255,0.16);
      box-shadow: 0 16px 28px rgba(75,99,255,0.10);
    }}
    .menu-link.active {{
      color: #ffffff;
      border-color: transparent;
      background: linear-gradient(135deg, #4b63ff 0%, #6d7cff 52%, #86d2ff 100%);
      box-shadow: 0 18px 36px rgba(75,99,255,0.22);
    }}
    .menu-link strong {{
      display: block;
      font-size: 14px;
    }}
    .menu-link small {{
      display: block;
      margin-top: 4px;
      color: #8190b7;
      font-size: 12px;
    }}
    .menu-link.active small {{
      color: rgba(255,255,255,0.76);
    }}
    .menu-index {{
      width: 34px;
      height: 34px;
      border-radius: 12px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 12px;
      color: #4b63ff;
      background: rgba(75,99,255,0.10);
    }}
    .menu-link.active .menu-index {{
      color: #ffffff;
      background: rgba(255,255,255,0.14);
    }}
    .sidebar-note {{
      margin-top: auto;
      padding: 18px;
      border-radius: 22px;
      background: linear-gradient(180deg, rgba(75,99,255,0.10), rgba(126,203,255,0.10));
      border: 1px solid rgba(75,99,255,0.12);
      box-shadow: 0 18px 38px rgba(75,99,255,0.10);
    }}
    .sidebar-note strong {{
      display: block;
      margin: 12px 0 4px;
      font-size: 14px;
    }}
    .sidebar-note p {{
      margin: 0;
      color: #5a688f;
      font-size: 13px;
      line-height: 1.55;
    }}
    .dashboard-main {{
      display: grid;
      align-content: start;
      gap: 18px;
    }}
    .dashboard-topbar {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 18px;
      padding: 8px 4px 0;
    }}
    .dashboard-heading h1 {{
      margin: 10px 0 8px;
      font-size: clamp(30px, 4vw, 42px);
      line-height: 1.02;
      letter-spacing: -0.04em;
    }}
    .dashboard-heading p {{
      margin: 0;
      color: #667394;
      font-size: 15px;
      max-width: 620px;
    }}
    .dashboard-actions {{
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }}
    .key-search {{
      display: flex;
      align-items: center;
      gap: 10px;
      min-width: min(100%, 430px);
      padding: 8px;
      border-radius: 20px;
      border: 1px solid rgba(39,61,135,0.10);
      background: rgba(255,255,255,0.78);
      box-shadow: 0 16px 34px rgba(75,99,255,0.08);
      -webkit-backdrop-filter: blur(18px);
      backdrop-filter: blur(18px);
    }}
    .key-search input {{
      min-width: 260px;
      border: none;
      background: transparent;
      box-shadow: none;
      padding: 12px 14px;
    }}
    .key-search input:focus {{
      box-shadow: none;
      background: transparent;
    }}
    .hero-card {{
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(280px, 0.9fr);
      gap: 18px;
      padding: 24px;
      border-radius: 32px;
      border: 1px solid rgba(39,61,135,0.10);
      background:
        radial-gradient(circle at 100% 0%, rgba(126,203,255,0.24), transparent 30%),
        linear-gradient(135deg, rgba(255,255,255,0.94) 0%, rgba(240,244,255,0.90) 100%);
      box-shadow: var(--shadow);
      overflow: hidden;
      position: relative;
    }}
    .hero-card::after {{
      content: "";
      position: absolute;
      inset: auto -80px -120px auto;
      width: 260px;
      height: 260px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(75,99,255,0.20), transparent 68%);
      pointer-events: none;
    }}
    .hero-copy {{
      position: relative;
      z-index: 1;
    }}
    .hero-copy h2 {{
      margin: 18px 0 10px;
      font-size: clamp(28px, 3.6vw, 40px);
      line-height: 1.02;
      letter-spacing: -0.04em;
    }}
    .hero-copy p {{
      margin: 0;
      color: #657292;
      font-size: 15px;
      line-height: 1.7;
      max-width: 620px;
    }}
    .hero-preview {{
      display: grid;
      gap: 12px;
      position: relative;
      z-index: 1;
    }}
    .preview-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}
    .preview-card {{
      padding: 18px;
      border-radius: 22px;
      border: 1px solid rgba(255,255,255,0.22);
      background: linear-gradient(180deg, rgba(75,99,255,0.10), rgba(126,203,255,0.12));
      box-shadow: 0 18px 38px rgba(75,99,255,0.12);
    }}
    .preview-card strong {{
      display: block;
      margin-top: 10px;
      font-size: 24px;
      line-height: 1;
    }}
    .preview-card span {{
      font-size: 13px;
      color: #5b6790;
    }}
    .preview-wide {{
      display: grid;
      gap: 10px;
      padding: 20px;
      border-radius: 24px;
      background: linear-gradient(135deg, #223056 0%, #344a82 48%, #4b63ff 100%);
      color: #eef3ff;
      box-shadow: 0 28px 50px rgba(34,48,86,0.30);
    }}
    .preview-wide strong {{
      font-size: 18px;
    }}
    .preview-wide p {{
      margin: 0;
      font-size: 13px;
      line-height: 1.6;
      color: rgba(238,243,255,0.76);
    }}
    .stat-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 16px;
    }}
    .stat-card {{
      padding: 20px;
      border-radius: 24px;
      border: 1px solid rgba(39,61,135,0.10);
      background: rgba(255,255,255,0.90);
      box-shadow: 0 18px 36px rgba(75,99,255,0.08);
    }}
    .stat-card span {{
      display: block;
      font-size: 13px;
      color: #7180a5;
    }}
    .stat-card strong {{
      display: block;
      margin-top: 14px;
      font-size: 32px;
      line-height: 1;
      letter-spacing: -0.04em;
    }}
    .stat-card em {{
      display: inline-flex;
      align-items: center;
      margin-top: 12px;
      padding: 6px 10px;
      border-radius: 999px;
      font-style: normal;
      font-size: 12px;
      font-weight: 700;
      color: #4b63ff;
      background: rgba(75,99,255,0.08);
    }}
    .surface-grid {{
      display: grid;
      grid-template-columns: 1.2fr 1fr 1fr;
      gap: 16px;
    }}
    .surface-card {{
      padding: 22px;
      border-radius: 28px;
      border: 1px solid rgba(39,61,135,0.10);
      background: rgba(255,255,255,0.90);
      box-shadow: 0 18px 36px rgba(75,99,255,0.08);
      display: grid;
      align-content: start;
      gap: 14px;
    }}
    .surface-log {{
      grid-column: span 3;
    }}
    .section-heading h3 {{
      margin: 10px 0 6px;
      font-size: 24px;
      letter-spacing: -0.03em;
    }}
    .section-heading p {{
      margin: 0;
      color: #7080a4;
      font-size: 14px;
      line-height: 1.6;
    }}
    .form-grid {{
      display: grid;
      gap: 14px;
    }}
    .form-pair {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}
    .license-stage {{
      position: relative;
      overflow: hidden;
      padding: 24px;
      border-radius: 34px;
      border: 1px solid rgba(63,79,128,0.26);
      background:
        radial-gradient(circle at top right, rgba(79,102,255,0.26), transparent 24%),
        linear-gradient(180deg, #151924 0%, #0d1118 100%);
      box-shadow: 0 36px 80px rgba(15,23,56,0.32);
      color: #eff4ff;
    }}
    .license-stage::before {{
      content: "";
      position: absolute;
      inset: 0;
      background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0));
      pointer-events: none;
    }}
    .license-stage-head {{
      position: relative;
      z-index: 1;
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 18px;
      margin-bottom: 18px;
    }}
    .license-stage-head h2 {{
      margin: 12px 0 8px;
      font-size: 30px;
      letter-spacing: -0.04em;
      line-height: 1;
    }}
    .license-stage-head p {{
      margin: 0;
      color: rgba(218,226,255,0.70);
      font-size: 14px;
      line-height: 1.65;
      max-width: 620px;
    }}
    .license-stage-info {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      justify-content: flex-end;
    }}
    .stage-chip {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 9px 12px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,0.12);
      background: rgba(255,255,255,0.06);
      color: rgba(237,243,255,0.82);
      font-size: 12px;
      font-weight: 700;
    }}
    .license-grid {{
      position: relative;
      z-index: 1;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
    }}
    .license-card {{
      padding: 18px;
      border-radius: 24px;
      border: 1px solid rgba(255,255,255,0.10);
      background: linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.03));
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.04);
      display: grid;
      gap: 14px;
    }}
    .license-head {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
    }}
    .license-key {{
      font-size: 24px;
      font-weight: 800;
      letter-spacing: -0.04em;
      line-height: 1.05;
      word-break: break-word;
    }}
    .license-caption {{
      margin-top: 8px;
      font-size: 13px;
      color: rgba(216,224,255,0.70);
      line-height: 1.5;
    }}
    .license-highlights {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }}
    .spot-chip {{
      padding: 12px;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,0.08);
      background: rgba(255,255,255,0.05);
    }}
    .spot-chip span {{
      display: block;
      font-size: 12px;
      color: rgba(216,224,255,0.62);
    }}
    .spot-chip strong {{
      display: block;
      margin-top: 8px;
      font-size: 14px;
      line-height: 1.4;
      word-break: break-word;
    }}
    .license-meta-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }}
    .meta-card {{
      padding: 12px;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,0.08);
      background: rgba(7,11,19,0.28);
    }}
    .meta-card span {{
      display: block;
      font-size: 12px;
      color: rgba(216,224,255,0.62);
    }}
    .meta-card strong {{
      display: block;
      margin-top: 8px;
      font-size: 13px;
      line-height: 1.55;
      color: #f6f8ff;
      word-break: break-word;
    }}
    .license-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .license-stage .btn,
    .license-stage button,
    .license-stage input[type="submit"] {{
      color: #eef4ff;
      background: rgba(255,255,255,0.08);
      border-color: rgba(255,255,255,0.12);
      box-shadow: none;
    }}
    .license-stage .btn:hover,
    .license-stage button:hover,
    .license-stage input[type="submit"]:hover {{
      background: rgba(255,255,255,0.12);
      border-color: rgba(255,255,255,0.18);
      box-shadow: none;
    }}
    .license-stage .btn.primary,
    .license-stage button.primary,
    .license-stage input[type="submit"].primary {{
      background: linear-gradient(135deg, #4b63ff 0%, #7cc9ff 100%);
      color: #ffffff;
    }}
    .log-list {{
      display: grid;
      gap: 10px;
    }}
    .log-item {{
      padding: 16px;
      border-radius: 20px;
      border: 1px solid rgba(39,61,135,0.10);
      background: linear-gradient(180deg, #ffffff 0%, #f6f8ff 100%);
      box-shadow: 0 14px 26px rgba(75,99,255,0.06);
    }}
    .log-item.fail {{
      background: linear-gradient(180deg, #fff7f9 0%, #fff1f4 100%);
      border-color: rgba(239,68,68,0.12);
    }}
    .log-top {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      color: #7b87a9;
      font-size: 12px;
      font-weight: 700;
    }}
    .log-pill {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 60px;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}
    .log-pill.ok {{
      color: #0f6b3a;
      background: rgba(22,179,100,0.12);
    }}
    .log-pill.fail {{
      color: #b42318;
      background: rgba(239,68,68,0.12);
    }}
    .log-body {{
      display: grid;
      gap: 6px;
      margin-top: 12px;
    }}
    .log-body strong {{
      font-size: 15px;
      color: #202d52;
    }}
    .log-body span,
    .log-meta {{
      color: #6b789b;
      font-size: 13px;
      line-height: 1.55;
    }}
    .log-meta {{
      margin-top: 10px;
    }}
    .empty-state {{
      padding: 22px;
      border-radius: 24px;
      border: 1px dashed rgba(255,255,255,0.18);
      background: rgba(255,255,255,0.04);
      color: rgba(221,229,255,0.72);
      text-align: center;
      font-size: 14px;
      line-height: 1.7;
    }}
    .login-shell {{
      min-height: calc(100vh - 52px);
      display: grid;
      grid-template-columns: minmax(360px, 470px) minmax(0, 1fr);
      gap: 24px;
      align-items: stretch;
    }}
    .login-panel {{
      padding: 34px;
      border-radius: 34px;
      border: 1px solid rgba(39,61,135,0.10);
      background: rgba(255,255,255,0.92);
      box-shadow: var(--shadow);
      display: grid;
      align-content: start;
      gap: 20px;
      -webkit-backdrop-filter: blur(18px);
      backdrop-filter: blur(18px);
    }}
    .login-brand {{
      display: flex;
      align-items: center;
      gap: 14px;
    }}
    .login-brand h1 {{
      margin: 0;
      font-size: 18px;
      line-height: 1.1;
    }}
    .login-brand p {{
      margin: 6px 0 0;
      color: #7481a4;
      font-size: 13px;
    }}
    .login-copy h2 {{
      margin: 16px 0 10px;
      font-size: clamp(34px, 4vw, 48px);
      line-height: 0.98;
      letter-spacing: -0.05em;
    }}
    .login-copy p {{
      margin: 0;
      color: #667394;
      font-size: 15px;
      line-height: 1.7;
    }}
    .login-meta {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      flex-wrap: wrap;
      color: #7481a4;
      font-size: 13px;
    }}
    .login-meta strong {{
      color: #24345f;
    }}
    .showcase-panel {{
      position: relative;
      overflow: hidden;
      padding: 36px;
      border-radius: 34px;
      background: linear-gradient(135deg, #435cff 0%, #5d76ff 50%, #8bdcff 100%);
      color: #ffffff;
      box-shadow: 0 32px 80px rgba(75,99,255,0.34);
      display: grid;
      align-content: space-between;
      gap: 22px;
    }}
    .showcase-panel::before {{
      content: "";
      position: absolute;
      inset: auto auto -120px -80px;
      width: 280px;
      height: 280px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(255,255,255,0.26), transparent 70%);
      pointer-events: none;
    }}
    .showcase-panel::after {{
      content: "";
      position: absolute;
      top: 24px;
      right: 24px;
      width: 160px;
      height: 160px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(255,255,255,0.18), transparent 70%);
      pointer-events: none;
    }}
    .showcase-copy {{
      position: relative;
      z-index: 1;
      display: grid;
      gap: 14px;
      max-width: 540px;
    }}
    .showcase-copy h3 {{
      margin: 0;
      font-size: clamp(32px, 4.3vw, 52px);
      line-height: 0.96;
      letter-spacing: -0.05em;
    }}
    .showcase-copy p {{
      margin: 0;
      color: rgba(255,255,255,0.78);
      font-size: 15px;
      line-height: 1.75;
    }}
    .showcase-stack {{
      position: relative;
      z-index: 1;
      display: grid;
      gap: 14px;
    }}
    .showcase-stack .preview-card,
    .showcase-stack .preview-wide {{
      background: rgba(255,255,255,0.14);
      border-color: rgba(255,255,255,0.16);
      box-shadow: none;
      color: #ffffff;
    }}
    .showcase-stack .preview-card span,
    .showcase-stack .preview-wide p {{
      color: rgba(255,255,255,0.72);
    }}
    .showcase-stack .preview-grid {{
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }}
    .showcase-foot {{
      position: relative;
      z-index: 1;
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }}
    .showcase-foot span {{
      display: inline-flex;
      align-items: center;
      padding: 9px 12px;
      border-radius: 999px;
      background: rgba(255,255,255,0.14);
      color: rgba(255,255,255,0.84);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }}
    @media (max-width: 1320px) {{
      .stat-grid {{
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }}
      .surface-grid {{
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }}
      .surface-log {{
        grid-column: span 2;
      }}
      .hero-card {{
        grid-template-columns: 1fr;
      }}
    }}
    @media (max-width: 1180px) {{
      .dashboard-shell {{
        grid-template-columns: 1fr;
      }}
      .dashboard-sidebar {{
        position: relative;
        top: 0;
        height: auto;
      }}
      .login-shell {{
        grid-template-columns: 1fr;
      }}
    }}
    @media (max-width: 820px) {{
      .wrap {{
        padding: 18px;
      }}
      .dashboard-topbar,
      .dashboard-actions,
      .license-stage-head,
      .login-meta {{
        flex-direction: column;
        align-items: stretch;
      }}
      .key-search {{
        width: 100%;
        min-width: 0;
      }}
      .key-search input {{
        min-width: 0;
      }}
      .stat-grid,
      .surface-grid,
      .form-pair,
      .license-highlights,
      .license-meta-grid,
      .preview-grid,
      .showcase-stack .preview-grid {{
        grid-template-columns: 1fr;
      }}
      .surface-log {{
        grid-column: span 1;
      }}
      .login-panel,
      .showcase-panel,
      .license-stage,
      .hero-card,
      .surface-card {{
        padding: 20px;
      }}
    }}
    @keyframes sweepFill {{
      0% {{ left: -120%; opacity: 0; }}
      15% {{ opacity: .9; }}
      100% {{ left: 110%; opacity: 0; }}
    }}
    @keyframes pressWave {{
      0% {{ transform: scale(1); filter: grayscale(.2) contrast(1.02); }}
      35% {{ transform: scale(.985); filter: grayscale(1) contrast(1.15); }}
      100% {{ transform: scale(1); filter: grayscale(0) contrast(1); }}
    }}
    @keyframes panelIn {{
      0% {{ opacity: 0; transform: translateY(8px) scale(.995); }}
      100% {{ opacity: 1; transform: none; }}
    }}
    @media (max-width: 980px) {{
      :root {{ --cursor-size: 260px; }}
      .app {{ grid-template-columns: 1fr; }}
      .sidebar {{ position: relative; height: auto; border-right: none; border-bottom: 1px solid var(--line); }}
      .split {{ grid-template-columns: 1fr; }}
      .grid.cols3 {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">{body}</div>
<script>
(() => {{
  const root = document.documentElement;
  const body = document.body;

  const setCursorGlow = (x, y) => {{
    root.style.setProperty('--cursor-x', `${{x}}px`);
    root.style.setProperty('--cursor-y', `${{y}}px`);
  }};

  const onPointerMove = (event) => {{
    const p = event.touches ? event.touches[0] : event;
    setCursorGlow(p.clientX, p.clientY);
  }};

  document.addEventListener('mousemove', onPointerMove, {{ passive: true }});
  document.addEventListener('touchmove', onPointerMove, {{ passive: true }});

  requestAnimationFrame(() => body.classList.add('page-loaded'));

  const interactiveSelectors = '.btn, .menu-link, .nav a, button';
  document.querySelectorAll(interactiveSelectors).forEach((el) => {{
    el.addEventListener('click', () => {{
      el.classList.remove('press-wave');
      void el.offsetWidth;
      el.classList.add('press-wave');
      setTimeout(() => el.classList.remove('press-wave'), 560);
    }});
  }});

  document.querySelectorAll('a[href^="/admin"]').forEach((link) => {{
    link.addEventListener('click', (event) => {{
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.defaultPrevented) {{
        return;
      }}
      const href = link.getAttribute('href');
      if (!href || href === window.location.pathname + window.location.search) {{
        return;
      }}
      event.preventDefault();
      body.classList.add('page-leaving');
      setTimeout(() => {{
        window.location.href = href;
      }}, 170);
    }});
  }});
}})();
</script>
</body>
</html>"""
    return page.encode("utf-8")


class LicenseHandler(BaseHTTPRequestHandler):
    server_version = "KeySystemTemplate/2.0"

    def _send_bytes(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, payload: dict) -> None:
        self._send_bytes(code, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length)
            return json.loads(raw_body.decode("utf-8"))
        except Exception:
            return None

    def _read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        parsed = parse_qs(body, keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items()}

    def _get_session_token(self) -> str:
        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return ""
        jar = cookies.SimpleCookie()
        jar.load(cookie_header)
        morsel = jar.get(SESSION_COOKIE)
        return morsel.value if morsel else ""

    def _client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0] if self.client_address else ""

    def _client_agent_fingerprint(self) -> str:
        user_agent = self.headers.get("User-Agent", "").strip().lower()
        if not user_agent:
            return ""
        return hashlib.sha256(user_agent.encode("utf-8")).hexdigest()[:32]

    def _admin_lock_matches(self, db: dict) -> bool:
        return True

    def _is_authenticated(self) -> bool:
        token = self._get_session_token()
        if not token:
            return False
        db = load_db()
        session = db.get("sessions", {}).get(token)
        if not session:
            return False
        expires_at = session if isinstance(session, str) else session.get("expires_at", "")
        if not expires_at:
            return False
        try:
            if now_utc() > parse_iso_utc(expires_at):
                return False
        except Exception:
            return False
        return self._admin_lock_matches(db)

    def _require_auth(self) -> bool:
        if self._is_authenticated():
            return True
        self.send_response(302)
        self.send_header("Location", "/admin/login")
        self.end_headers()
        return False

    def _redirect(self, location: str, set_cookie: str | None = None) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()

    def _render_login(self, error: str = "") -> None:
        db = load_db()
        users_data = load_users()
        total_keys = len(db.get("licenses", []))
        linked_users = sum(1 for user in users_data.get("users", {}).values() if str(user.get("license_key", "")).strip())
        auth_logs = len(db.get("auth_logs", []))
        error_html = f'<div class="flash">{html.escape(error)}</div>' if error else ""
        body = f"""
<div class="login-shell">
  <section class="login-panel">
    <div class="login-brand">
      <div class="brand-mark"></div>
      <div>
        <h1>Key System</h1>
        <p>Admin control center</p>
      </div>
    </div>
    <div class="login-copy">
      <span class="eyebrow">Secure access</span>
      <h2>Sign in to manage every key</h2>
      <p>New dashboard layout is already connected to your local key database, Telegram users, autosave snapshots and the updated admin flow.</p>
    </div>
    {error_html}
    <form method="post" action="/admin/login" class="form-grid">
      <div>
        <label class="field-label" for="username">Username</label>
        <input id="username" name="username" placeholder="Enter your username" autocomplete="username" required>
      </div>
      <div>
        <label class="field-label" for="password">Password</label>
        <input id="password" name="password" type="password" placeholder="Enter your password" autocomplete="current-password" required>
      </div>
      <button class="btn primary" type="submit">Open admin panel</button>
    </form>
    <div class="login-meta">
      <span>Route: <strong>/admin</strong></span>
      <span>Session time: <strong>12 hours</strong></span>
    </div>
  </section>
  <aside class="showcase-panel">
    <div class="showcase-copy">
      <span class="eyebrow inverse">Dashboard preview</span>
      <h3>Light admin shell, dark key vault and fast controls.</h3>
      <p>The panel now matches the references closer: bright workspace on top, a focused dark block for license cards and clearer actions for each key.</p>
    </div>
    <div class="showcase-stack">
      <div class="preview-wide">
        <strong>Live data connected</strong>
        <p>Current login reads the same JSON files used by the server, with autosave snapshots stored beside the source.</p>
      </div>
      <div class="preview-grid">
        <div class="preview-card">
          <span>Stored keys</span>
          <strong>{total_keys}</strong>
        </div>
        <div class="preview-card">
          <span>Linked users</span>
          <strong>{linked_users}</strong>
        </div>
        <div class="preview-card">
          <span>Auth logs</span>
          <strong>{auth_logs}</strong>
        </div>
      </div>
    </div>
    <div class="showcase-foot">
      <span>Autosave</span>
      <span>Telegram</span>
      <span>Local host</span>
    </div>
  </aside>
</div>
"""
        self._send_bytes(200, html_page("Key System Login", body), "text/html; charset=utf-8")

    def _render_admin(self, query: str = "", flash: str = "") -> None:
        db = load_db()
        all_items = db.get("licenses", [])
        search = query.strip().lower()
        items = list(all_items)
        if search:
            filtered = []
            for item in all_items:
                blob = " ".join([
                    item.get("license_key", ""),
                    item.get("name", ""),
                    item.get("product", ""),
                    item.get("hwid", ""),
                    item.get("notes", ""),
                    normalize_status(item),
                ]).lower()
                if search in blob:
                    filtered.append(item)
            items = filtered

        active_count = 0
        frozen_count = 0
        expired_count = 0
        bound_hwid_count = 0
        for item in all_items:
            status = display_status(item)
            if status == "active":
                active_count += 1
            elif status == "frozen":
                frozen_count += 1
            elif status == "expired":
                expired_count += 1
            if item.get("hwid"):
                bound_hwid_count += 1

        users_data = load_users()
        linked_users = sum(1 for user in users_data.get("users", {}).values() if str(user.get("license_key", "")).strip())
        log_count = len(db.get("auth_logs", []))
        total_count = len(all_items)
        showing_count = len(items)
        cards_html = "".join(render_license_card_html(item) for item in items)
        if not cards_html:
            cards_html = '<div class="empty-state">No keys matched the current search. Try another query or create a new license from the forms above.</div>'

        flash_html = f'<div class="flash">{html.escape(flash)}</div>' if flash else ""
        body = f"""
<div class="dashboard-shell">
  <aside class="dashboard-sidebar">
    <div class="sidebar-brand">
      <div class="brand-mark"></div>
      <div>
        <h1>Key System</h1>
        <p>License admin dashboard</p>
      </div>
    </div>
    <div class="sidebar-group">
      <div class="group-title">Menu</div>
      <a class="menu-link active" href="#overview">
        <div><strong>Overview</strong><small>Dashboard summary</small></div>
        <span class="menu-index">01</span>
      </a>
      <a class="menu-link" href="#licenses">
        <div><strong>Key Vault</strong><small>Cards for every key</small></div>
        <span class="menu-index">02</span>
      </a>
      <a class="menu-link" href="#create">
        <div><strong>Create</strong><small>Generate a new license</small></div>
        <span class="menu-index">03</span>
      </a>
      <a class="menu-link" href="#extend">
        <div><strong>Extend</strong><small>Add more days</small></div>
        <span class="menu-index">04</span>
      </a>
      <a class="menu-link" href="#logs">
        <div><strong>Logs</strong><small>Recent validations</small></div>
        <span class="menu-index">05</span>
      </a>
    </div>
    <div class="sidebar-note">
      <span class="eyebrow">Live source</span>
      <strong>/api/validate</strong>
      <p>Keys are stored in the local JSON database with autosave snapshots beside the source, so changes stay in sync with the running panel.</p>
    </div>
  </aside>
  <main class="dashboard-main">
    <section id="overview" class="dashboard-topbar">
      <div class="dashboard-heading">
        <span class="eyebrow">Dashboard</span>
        <h1>Manage keys in the new panel</h1>
        <p>Bright workspace for admin actions, dark vault for license cards and clearer status blocks for every key, inspired by your references but branded for your own project.</p>
      </div>
      <div class="dashboard-actions">
        <form method="get" action="/admin" class="key-search">
          <input name="q" placeholder="Search by key, name, product, status, hwid or notes" value="{html.escape(query)}">
          <button class="btn primary" type="submit">Search</button>
        </form>
        <form method="post" action="/admin/logout">
          <button class="btn alt" type="submit">Logout</button>
        </form>
      </div>
    </section>
    {flash_html}
    <section class="hero-card">
      <div class="hero-copy">
        <span class="eyebrow">Overview</span>
        <h2>Control the whole key flow from one screen.</h2>
        <p>Search, create, extend, edit and moderate keys without leaving the page. Every license card includes status, HWID, last IP, dates, notes and direct actions like in the reference style you showed.</p>
      </div>
      <div class="hero-preview">
        <div class="preview-grid">
          <div class="preview-card">
            <span>Showing now</span>
            <strong>{showing_count}</strong>
          </div>
          <div class="preview-card">
            <span>Stored total</span>
            <strong>{total_count}</strong>
          </div>
        </div>
        <div class="preview-wide">
          <strong>Search state</strong>
          <p>{html.escape("Filter active: " + query if query else "No search filter applied. All stored keys are visible in the vault below.")}</p>
        </div>
      </div>
    </section>
    <section class="stat-grid">
      <article class="stat-card">
        <span>Total licenses</span>
        <strong>{total_count}</strong>
        <em>All stored records</em>
      </article>
      <article class="stat-card">
        <span>Active now</span>
        <strong>{active_count}</strong>
        <em>Ready for validation</em>
      </article>
      <article class="stat-card">
        <span>Frozen or expired</span>
        <strong>{frozen_count + expired_count}</strong>
        <em>{frozen_count} frozen / {expired_count} expired</em>
      </article>
      <article class="stat-card">
        <span>Linked users</span>
        <strong>{linked_users}</strong>
        <em>{bound_hwid_count} HWID bound</em>
      </article>
    </section>
    <section class="surface-grid">
      <article id="create" class="surface-card">
        <div class="section-heading">
          <span class="eyebrow">Create</span>
          <h3>Issue a new key</h3>
          <p>Add a brand new license with its own owner name, product and notes.</p>
        </div>
        <form method="post" action="/admin/create" class="form-grid">
          <div class="form-pair">
            <div>
              <label class="field-label" for="create-key">License key</label>
              <input id="create-key" name="license_key" placeholder="Zetry-User-001" required>
            </div>
            <div>
              <label class="field-label" for="create-days">Days</label>
              <input id="create-days" name="days" type="number" min="1" value="30" required>
            </div>
          </div>
          <div class="form-pair">
            <div>
              <label class="field-label" for="create-name">Name</label>
              <input id="create-name" name="name" placeholder="Client name" required>
            </div>
            <div>
              <label class="field-label" for="create-product">Product</label>
              <input id="create-product" name="product" placeholder="Product title" required>
            </div>
          </div>
          <div>
            <label class="field-label" for="create-notes">Notes</label>
            <textarea id="create-notes" name="notes" placeholder="Add internal notes for the key"></textarea>
          </div>
          <button class="btn primary" type="submit">Create</button>
        </form>
      </article>
      <article id="extend" class="surface-card">
        <div class="section-heading">
          <span class="eyebrow">Extend</span>
          <h3>Add more time</h3>
          <p>Extend an existing key without touching the rest of the record.</p>
        </div>
        <form method="post" action="/admin/action" class="form-grid">
          <input type="hidden" name="action" value="extend">
          <div>
            <label class="field-label" for="extend-key">License key</label>
            <input id="extend-key" name="key" placeholder="Existing key" required>
          </div>
          <div>
            <label class="field-label" for="extend-days">Days</label>
            <input id="extend-days" name="days" type="number" min="1" value="30" required>
          </div>
          <button class="btn primary" type="submit">Extend</button>
        </form>
      </article>
      <article id="edit" class="surface-card">
        <div class="section-heading">
          <span class="eyebrow">Edit</span>
          <h3>Update stored fields</h3>
          <p>Rename a key owner, change product, adjust notes or add days in one place.</p>
        </div>
        <form method="post" action="/admin/action" class="form-grid">
          <input type="hidden" name="action" value="edit">
          <div>
            <label class="field-label" for="edit-key">License key</label>
            <input id="edit-key" name="key" placeholder="Existing license key" required>
          </div>
          <div class="form-pair">
            <div>
              <label class="field-label" for="edit-name">Name</label>
              <input id="edit-name" name="name" placeholder="Updated name">
            </div>
            <div>
              <label class="field-label" for="edit-product">Product</label>
              <input id="edit-product" name="product" placeholder="Updated product">
            </div>
          </div>
          <div>
            <label class="field-label" for="edit-notes">Notes</label>
            <textarea id="edit-notes" name="notes" placeholder="Updated notes"></textarea>
          </div>
          <div>
            <label class="field-label" for="edit-days">Extra days</label>
            <input id="edit-days" name="days" type="number" min="0" value="0">
          </div>
          <button class="btn primary" type="submit">Save Changes</button>
        </form>
      </article>
      <article id="logs" class="surface-card surface-log">
        <div class="section-heading">
          <span class="eyebrow">Logs</span>
          <h3>Recent auth activity</h3>
          <p>{log_count} validation logs stored in the database. Latest events are shown as cards for quicker review.</p>
        </div>
        <div>
          {self._render_logs_html(db)}
        </div>
      </article>
    </section>
    <section id="licenses" class="license-stage">
      <div class="license-stage-head">
        <div>
          <span class="eyebrow inverse">Key vault</span>
          <h2>Every key in its own card</h2>
          <p>Each card shows status, owner, product, HWID, last IP, creation time, expiration, notes and direct moderation actions, closer to the layout style from your fifth reference.</p>
        </div>
        <div class="license-stage-info">
          <span class="stage-chip">Visible: {showing_count}</span>
          <span class="stage-chip">Active: {active_count}</span>
          <span class="stage-chip">Logs: {log_count}</span>
        </div>
      </div>
      <div class="license-grid">
        {cards_html}
      </div>
    </section>
  </main>
</div>
"""
        self._send_bytes(200, html_page("Key System Admin", body), "text/html; charset=utf-8")

    def _render_logs_html(self, db: dict) -> str:
        logs = list(reversed(db.get("auth_logs", [])[-12:]))
        if not logs:
            return '<div class="empty-state">No validation attempts yet. After users start checking licenses, recent activity will appear here.</div>'
        return '<div class="log-list">' + "".join(render_auth_log_card_html(log) for log in logs) + '</div>'

    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/api/health":
            self._send_json(200, {"success": True, "time": iso_utc(now_utc())})
            return

        if parsed.path == "/admin/login":
            self._render_login()
            return

        if parsed.path == "/admin":
            if not self._require_auth():
                return
            params = parse_qs(parsed.query)
            self._render_admin(query=params.get("q", [""])[0], flash=params.get("flash", [""])[0])
            return

        self._send_bytes(404, b"Not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        if self.path == "/api/validate":
            data = self._read_json()
            if not data:
                self._send_json(400, {"success": False, "message": "Invalid JSON"})
                return

            license_key = str(data.get("license_key", "")).strip()
            hwid = str(data.get("hwid", "")).strip()
            product = str(data.get("product", "")).strip()
            ip = self.client_address[0] if self.client_address else ""
            if not license_key or not hwid or not product:
                self._send_json(400, {"success": False, "message": "Missing required fields"})
                return

            result = validate_license(license_key, hwid, product, ip)
            self._send_json(200 if result.get("success") else 403, result)
            return

        if self.path == "/admin/login":
            form = self._read_form()
            config = ensure_config()
            if form.get("username") != config.get("admin_username") or form.get("password") != config.get("admin_password"):
                self._render_login("Invalid credentials")
                return

            db = load_db()
            db["admin_device_lock"] = {}
            token = secrets.token_hex(24)
            db.setdefault("sessions", {})[token] = {
                "expires_at": iso_utc(now_utc() + timedelta(hours=12)),
                "ip": self._client_ip(),
                "agent_fp": "",
            }
            save_db(db)
            self._redirect("/admin", f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax")
            return

        if self.path == "/admin/logout":
            db = load_db()
            token = self._get_session_token()
            if token:
                db.get("sessions", {}).pop(token, None)
                save_db(db)
            self._redirect("/admin/login", f"{SESSION_COOKIE}=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
            return

        if self.path == "/admin/create":
            if not self._require_auth():
                return
            form = self._read_form()
            key = form.get("license_key", "").strip()
            name = form.get("name", "").strip()
            product = form.get("product", "").strip()
            notes = form.get("notes", "").strip()
            try:
                days = max(1, int(form.get("days", "30").strip()))
            except ValueError:
                self._redirect("/admin?flash=Invalid+days")
                return

            db = load_db()
            if not key or not name or not product:
                self._redirect("/admin?flash=Missing+required+fields")
                return
            if find_license(db, key):
                self._redirect("/admin?flash=License+already+exists")
                return

            item = {
                "license_key": key,
                "name": name,
                "product": product,
                "expires_at": iso_utc(now_utc() + timedelta(days=days)),
                "status": "active",
                "hwid": "",
                "notes": notes,
                "created_at": iso_utc(now_utc()),
                "last_seen_at": "",
                "max_users": 1,
            }
            db.setdefault("licenses", []).append(item)
            save_db(db)
            self._redirect("/admin?flash=Key+created")
            return

        if self.path == "/admin/action":
            if not self._require_auth():
                return
            form = self._read_form()
            action = form.get("action", "").strip()
            key = form.get("key", "").strip()
            db = load_db()
            item = find_license(db, key)
            if not item:
                self._redirect("/admin?flash=License+not+found")
                return

            if action == "freeze":
                item["status"] = "frozen"
                save_db(db)
                self._redirect("/admin?flash=Key+frozen")
                return

            if action == "unfreeze":
                if now_utc() > parse_iso_utc(item["expires_at"]):
                    item["status"] = "expired"
                    save_db(db)
                    self._redirect("/admin?flash=Key+already+expired")
                    return
                item["status"] = "active"
                save_db(db)
                self._redirect("/admin?flash=Key+unfrozen")
                return

            if action == "reset_hwid":
                item["hwid"] = ""
                save_db(db)
                self._redirect("/admin?flash=HWID+reset")
                return

            if action == "extend":
                try:
                    days = max(1, int(form.get("days", "0").strip()))
                except ValueError:
                    self._redirect("/admin?flash=Invalid+days")
                    return
                base = parse_iso_utc(item["expires_at"])
                if now_utc() > base:
                    base = now_utc()
                item["expires_at"] = iso_utc(base + timedelta(days=days))
                item["status"] = "active"
                save_db(db)
                self._redirect("/admin?flash=Key+extended")
                return

            if action == "edit":
                new_name = form.get("name", "").strip()
                new_product = form.get("product", "").strip()
                new_notes = form.get("notes", "").strip()
                days_raw = form.get("days", "0").strip()

                if new_name:
                    item["name"] = new_name
                if new_product:
                    item["product"] = new_product
                item["notes"] = new_notes

                try:
                    days = int(days_raw)
                except ValueError:
                    self._redirect("/admin?flash=Invalid+days")
                    return

                if days > 0:
                    item["expires_at"] = iso_utc(now_utc() + timedelta(days=days))
                    if item.get("status") == "expired":
                        item["status"] = "active"

                save_db(db)
                self._redirect("/admin?flash=Key+updated")
                return

            if action == "delete":
                db["licenses"] = [license_item for license_item in db.get("licenses", []) if license_item.get("license_key") != key]
                save_db(db)
                self._redirect("/admin?flash=Key+deleted")
                return

            self._redirect("/admin?flash=Unknown+action")
            return

        self._send_bytes(404, b"Not found", "text/plain; charset=utf-8")


def command_serve(args: argparse.Namespace) -> None:
    ensure_config()
    if args.with_telegram:
        threading.Thread(target=run_telegram_bot_forever, daemon=True).start()
    server = ThreadingHTTPServer((args.host, args.port), LicenseHandler)
    print(f"Serving on http://{args.host}:{args.port}")
    print("Admin panel: /admin")
    server.serve_forever()


def command_create(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(create_license_record(args.key, args.name, args.days, args.product, args.notes), indent=2))
    except ValueError as exc:
        raise SystemExit(str(exc))


def command_list(_: argparse.Namespace) -> None:
    db = load_db()
    print(json.dumps(db.get("licenses", []), indent=2))


def command_freeze(args: argparse.Namespace) -> None:
    try:
        freeze_license_record(args.key)
        print(f"Frozen {args.key}")
    except ValueError as exc:
        raise SystemExit(str(exc))


def command_unfreeze(args: argparse.Namespace) -> None:
    try:
        unfreeze_license_record(args.key)
        print(f"Unfrozen {args.key}")
    except ValueError as exc:
        raise SystemExit(str(exc))


def command_extend(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(extend_license_record(args.key, args.days), indent=2))
    except ValueError as exc:
        raise SystemExit(str(exc))


def command_reset_hwid(args: argparse.Namespace) -> None:
    try:
        reset_hwid_record(args.key)
        print(f"Reset HWID for {args.key}")
    except ValueError as exc:
        raise SystemExit(str(exc))


def command_show(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(show_license_record(args.key), indent=2))
    except ValueError as exc:
        raise SystemExit(str(exc))


def command_delete(args: argparse.Namespace) -> None:
    try:
        delete_license_record(args.key)
        print(f"Deleted {args.key}")
    except ValueError as exc:
        raise SystemExit(str(exc))


def command_set_admin(args: argparse.Namespace) -> None:
    config = load_config()
    config["admin_username"] = args.username
    config["admin_password"] = args.password
    save_config(config)
    print("Admin credentials updated")


def command_set_telegram(args: argparse.Namespace) -> None:
    config = load_config()
    config["telegram_token"] = args.token
    save_config(config)
    print("Telegram token updated")


def command_bot(_: argparse.Namespace) -> None:
    ensure_config()
    run_telegram_bot_forever()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Simple self-hosted key system")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=int(os.environ.get("PORT", "10000")))
    serve.add_argument("--with-telegram", action="store_true")
    serve.set_defaults(func=command_serve)

    create = sub.add_parser("create")
    create.add_argument("--key", required=True)
    create.add_argument("--name", required=True)
    create.add_argument("--days", type=int, default=30)
    create.add_argument("--product", required=True)
    create.add_argument("--notes", default="")
    create.set_defaults(func=command_create)

    list_cmd = sub.add_parser("list")
    list_cmd.set_defaults(func=command_list)

    freeze = sub.add_parser("freeze")
    freeze.add_argument("--key", required=True)
    freeze.set_defaults(func=command_freeze)

    unfreeze = sub.add_parser("unfreeze")
    unfreeze.add_argument("--key", required=True)
    unfreeze.set_defaults(func=command_unfreeze)

    extend = sub.add_parser("extend")
    extend.add_argument("--key", required=True)
    extend.add_argument("--days", type=int, required=True)
    extend.set_defaults(func=command_extend)

    reset_hwid = sub.add_parser("reset-hwid")
    reset_hwid.add_argument("--key", required=True)
    reset_hwid.set_defaults(func=command_reset_hwid)

    show = sub.add_parser("show")
    show.add_argument("--key", required=True)
    show.set_defaults(func=command_show)

    delete = sub.add_parser("delete")
    delete.add_argument("--key", required=True)
    delete.set_defaults(func=command_delete)

    set_admin = sub.add_parser("set-admin")
    set_admin.add_argument("--username", required=True)
    set_admin.add_argument("--password", required=True)
    set_admin.set_defaults(func=command_set_admin)

    set_telegram = sub.add_parser("set-telegram")
    set_telegram.add_argument("--token", required=True)
    set_telegram.set_defaults(func=command_set_telegram)

    bot = sub.add_parser("bot")
    bot.set_defaults(func=command_bot)

    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)



