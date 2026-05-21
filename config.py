import os
import json
from dotenv import load_dotenv

load_dotenv()
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
BOT_TOKEN = os.getenv("BOT_TOKEN")

# Database
DB_NAME = "autobanbot.db"

# Moderation & Logging
LOG_CHANNEL_ID = 1488494230585479239 # Replace with actual channel ID for logs
SUPPORT_SERVER_LINK = "https://discord.gg/your-support-server" # Link DM'd to users upon mute/ban
TIMEOUT_DURATION_1ST = 10 * 60 # 10 minutes timeout in seconds
TIMEOUT_DURATION_2ND = 60 * 60 # 1 hour timeout in seconds
TIMEOUT_DURATION_3RD = 24 * 60 * 60 # 24 hours timeout in seconds

# Heuristics Configuration
MAX_MESSAGES_PER_MINUTE = 10
MAX_REPEATED_TEXT_RATIO = 0.8  # 80% similarity considered spam
NEW_ACCOUNT_AGE_THRESHOLD_HOURS = 24 # Users newer than this might be suspicious
TRUST_LEVEL_HIGH_MSG_COUNT = 1000
TRUST_LEVEL_HIGH_DAYS = 30
SPAM_REPEAT_WINDOW = 5          # Number of recent messages to check for repetition
SPAM_REPEAT_THRESHOLD = 3       # Min duplicate messages in window to count as spam
SPAM_TRUST_EXEMPT_SCORE = 70    # Requires 70 trust to bypass spam warning
NEW_DOMAIN_TRUST_EXEMPT_SCORE = 50 # Requires 50 trust to bypass infant domain check
WHITELISTED_DOMAINS = ["yourwebsite.com", "github.com", "google.com"] # Add your sites here
RAID_VELOCITY_THRESHOLD = 5 # Joins per minute to trigger an alert

# API Integrations
API_NINJAS_KEY = "0mK1OEChUCRqub0d40C6ifzzraBLmMpYYMreRA9c"
NEW_DOMAIN_AGE_THRESHOLD_DAYS = 17

# Phishing
SUSPICIOUS_DOMAINS = ["nitro-gift", "steam-communit", "discord-gift", "free-nitro"] # Example heuristics


try:
    with open('suspicous-domain.json', 'r', encoding='utf-8') as f:
        SUSPICIOUS_DOMAINS_SET = set(json.load(f))
except FileNotFoundError:
    print("Warning: suspicous-domain.json not found!")
    SUSPICIOUS_DOMAINS_SET = set()


try:
    with open('suspicous-links.json', 'r', encoding='utf-8') as f:
        SUSPICIOUS_LINKS_SET = set(json.load(f))
except FileNotFoundError:
    print("Warning: suspicous-links.json not found!")
    SUSPICIOUS_LINKS_SET = set()

try:
    with open('protected_brands.json', 'r', encoding='utf-8') as f:
        PROTECTED_BRANDS = json.load(f)
except FileNotFoundError:
    print("Warning: protected_brands.json not found!")
    PROTECTED_BRANDS = []
    
# Advanced Detection
ENABLE_QR_SCANNING = True
ENABLE_ENTROPY_ANALYSIS = True
DOMAIN_ENTROPY_THRESHOLD = 3.5  # Lowered to 3.5 to catch standard 12-char DGA strings
DOMAIN_ENTROPY_MIN_LENGTH = 10  # Only check long domains to avoid false flags

# Feature Toggles
ENABLE_SAFE_BROWSING = True
ENABLE_PHISHING_DETECTION = True
ENABLE_DOMAIN_AGE_DETECTION = True
