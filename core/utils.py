import re
from difflib import SequenceMatcher
from datetime import datetime
import config
from urllib.parse import urlparse
import aiohttp
import time
import math
from collections import Counter

try:
    import cv2
    import numpy as np
    CV_AVAILABLE = True
except ImportError:
    CV_AVAILABLE = False

async def check_safe_browsing(url: str) -> bool:
    api_key = getattr(config, "GOOGLE_SAFE_BROWSING_API_KEY", None)
    if not api_key or api_key == "your_real_key_here":
        return False
        
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "autobanbot",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "SOCIAL_ENGINEERING",
                "MALWARE",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(endpoint, json=payload, timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if "matches" in data and len(data["matches"]) > 0:
                        print(f"[Log] Google Safe Browsing flagged URL: {url}")
                        return True
                else:
                    print(f"[Log] Google Safe Browsing API returned {resp.status}")
    except Exception as e:
        print(f"[Log] Google Safe Browsing check failed for {url}: {e}")
        
    return False

def normalize_domain(domain):

    replacements = {
        'і': 'i', 'ǃ': '!', 'ⅼ': 'l', 'о': 'o', 'а': 'a', 'е': 'e', 'с': 'c', 'р': 'p', 'у': 'y'
    }
    normalized = domain.lower()
    for char, replacement in replacements.items():
        normalized = normalized.replace(char, replacement)
    return normalized

def analyze_urgency(content):
    if not content:
        return False
        
    content_lower = content.lower()
    urgency_words = [
        "free", "nitro", "last chance", "giveaway", 
        "click now", "@everyone", "claim", "gift", 
        "limited time"
    ]
    
    matches = sum(1 for word in urgency_words if word in content_lower)
    return matches >= 1

# Check for phishing links
async def check_phishing(content):
    # Regex to find URLs and raw domains 
    url_pattern = r'\b(?:https?://)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{2,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    found_urls = re.findall(url_pattern, content)
    
    if not found_urls:
        return False, None
    
    # Target heavily-phished domains dynamically loaded from config
    protected_brands = getattr(config, "PROTECTED_BRANDS", [])
    
    for url in found_urls:
        # Parse the domain/netloc
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if not domain:
                domain = url.lower() # fallback
        except:
            domain = url.lower()

        # Strip "www." if present
        if domain.startswith("www."):
            domain = domain[4:]
            
        # Exact match against the massive JSON lists using O(1) sets
        if domain in config.SUSPICIOUS_LINKS_SET or url in config.SUSPICIOUS_LINKS_SET:
            return True, url
            
        normalized_dom = normalize_domain(domain)
        
        # NLP Urgency Analysis
        has_urgency = analyze_urgency(content)
        
        # Base fuzzy match threshold
        fuzzy_threshold = 0.82
        
        # Lower threshold even further if social engineering urgency is detected
        if has_urgency:
            fuzzy_threshold -= 0.10  # Drops to 0.65 or 0.72 making the bot hyper-sensitive
            print(f"[Log] Urgency detected in message. Lowering fuzzy threshold to {fuzzy_threshold:.2f}")

        # Catch brands hiding on platforms like pages.dev or vercel.app
        platform_tlds = ["pages.dev", "vercel.app", "github.io", "herokuapp.com", "firebaseapp.com"]
        if any(domain.endswith(tld) for tld in platform_tlds):
            matched_tld = next(tld for tld in platform_tlds if domain.endswith(tld))
            subdomain_part = domain.split(f".{matched_tld}")[0]
            for brand in protected_brands:
                brand_name = brand.split('.')[0]
                # Exact match
                if brand_name in subdomain_part:
                    print(f"[Log] Suspicious subdomain detected: {domain} contains brand '{brand_name}'")
                    return True, url
                # Fuzzy match (Lower threshold for subdomains)
                ratio = SequenceMatcher(None, subdomain_part, brand_name).ratio()
                if ratio > 0.6: # ladxoer vs ledger is 0.61
                    print(f"[Log] Fuzzy subdomain detected: {subdomain_part} looks like {brand_name} (ratio: {ratio:.2f})")
                    return True, url

        if domain in config.SUSPICIOUS_DOMAINS_SET or normalized_dom in config.SUSPICIOUS_DOMAINS_SET:
            return True, url

        # 2. Check against known heuristic patterns config
        for suspicious in config.SUSPICIOUS_DOMAINS:
            if suspicious in url.lower() or suspicious in normalized_dom:
                return True, url
        
        # 3. Fuzzy Matching (Typosquatting)
        for brand in protected_brands:
            # Check original domain
            ratio = SequenceMatcher(None, domain, brand).ratio()
            # Check normalized domain catches dіscord.com
            norm_ratio = SequenceMatcher(None, normalized_dom, brand).ratio()
            
            if (ratio > fuzzy_threshold or norm_ratio > fuzzy_threshold) and domain != brand:
                print(f"[Log] Spoofing detected: {domain} looks like {brand} (ratio: {max(ratio, norm_ratio):.2f})")
                return True, url
                
    return False, None

_RDAP_BOOTSTRAP = None

async def _get_rdap_base_url(tld):
    global _RDAP_BOOTSTRAP
    if not _RDAP_BOOTSTRAP:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://data.iana.org/rdap/dns.json", timeout=5) as res:
                    if res.status == 200:
                        _RDAP_BOOTSTRAP = await res.json()
        except:
            pass
            
    if not _RDAP_BOOTSTRAP:
        return None
        
    for service in _RDAP_BOOTSTRAP.get("services", []):
        if tld in service[0]:
            return service[1][0]
    return None

async def check_domain_age(content):
    url_pattern = r'\b(?:https?://)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{2,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    urls = re.findall(url_pattern, content)
    
    if not urls:
        return False, None, None

    if not getattr(config, "ENABLE_DOMAIN_AGE_DETECTION", False):
        return False, None, None

    threshold = getattr(config, "NEW_DOMAIN_AGE_THRESHOLD_DAYS", 30)
    
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if not domain:
                domain = url.lower()
        except:
            domain = url.lower()

        # Strip "www." if present
        if domain.startswith("www."):
            domain = domain[4:]

        # Whitelist Check
        if any(white in domain for white in getattr(config, "WHITELISTED_DOMAINS", [])):
            print(f"[Log] Domain {domain} is whitelisted. Skipping age check.")
            continue

        # Look up RDAP server for this TLD
        tld = domain.split('.')[-1]
        rdap_base = await _get_rdap_base_url(tld)
        
        if not rdap_base:
            print(f"[Log] Domain {domain} (.{tld}) has no public RDAP server. Skipping.")
            continue

        # Query Official RDAP
        rdap_url = f"{rdap_base.rstrip('/')}/domain/{domain}"
        headers = {"Accept": "application/rdap+json"}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(rdap_url, headers=headers, timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        events = data.get("events", [])
                        
                        creation_date = None
                        for event in events:
                            if event.get("eventAction") in ["registration", "creation"]:
                                creation_date = event.get("eventDate")
                                break
                                
                        if creation_date and len(creation_date) >= 10:
                            try:
                                # Parse YYYY-MM-DD from ISO string
                                year, month, day = int(creation_date[0:4]), int(creation_date[5:7]), int(creation_date[8:10])
                                reg_date = datetime(year, month, day)
                                now = datetime.now()
                                age_days = (now - reg_date).days
                                
                                if age_days < threshold:
                                    print(f"[Log] Domain {domain} flagged! Age: {age_days} days.")
                                    return True, domain, age_days
                            except Exception as e:
                                print(f"[Log] RDAP date parsing failed for {creation_date}: {e}")
                                return True, domain, -2
                        else:
                            # Zero Tolerance: No creation date found
                            print(f"[Log] Domain {domain} has NO registration date in RDAP. Flagging as suspicious.")
                            return True, domain, -2
                    elif response.status == 404:
                        print(f"[Log] RDAP 404 Not Found for {domain}. Flagging as suspicious (unregistered).")
                        return True, domain, -1
                    else:
                        print(f"[Log] RDAP returned {response.status} for {domain}. Flagging as untrackable.")
                        return True, domain, -3
        except Exception as e:
            print(f"[Log] RDAP check failed for {domain}: {e}. Flagging as untrackable.")
            return True, domain, -4

    return False, None, None



# Spam detection
def detect_repeated_spam(messages, threshold=None, ratio=None):

    if threshold is None:
        threshold = config.SPAM_REPEAT_THRESHOLD
    if ratio is None:
        ratio = config.MAX_REPEATED_TEXT_RATIO

    if len(messages) < threshold:
        return False, []

    stripped_messages = [m.strip() for m in messages]

    spam_indices = set()
    n = len(stripped_messages)
    
    for i in range(n):
        if not stripped_messages[i]:
            continue
            
        # Group messages similar to messages[i]
        similar_to_i = [i]
        for j in range(n):
            if i == j:
                continue
            if not stripped_messages[j]:
                continue
            if SequenceMatcher(None, stripped_messages[i], stripped_messages[j]).ratio() >= ratio:
                similar_to_i.append(j)
                
        # If this single message is similar to (threshold - 1) other messages, it's a spam cluster
        if len(similar_to_i) >= threshold:
            spam_indices.update(similar_to_i)
            
    if spam_indices:
        return True, sorted(list(spam_indices))

    return False, []

# Trust Factor Calculation
def calculate_trust_score(user_data, member):
    if not user_data:
        return 0
    
    message_count = user_data[2]
    first_seen_str = user_data[4]
    
    # Check if first_seen is a string or datetime object
    if isinstance(first_seen_str, str):
        # Handle cases where microsecond might be missing
        try:
             first_seen = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
             first_seen = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S")
    else:
        first_seen = first_seen_str

    days_known = (datetime.now() - first_seen).days
    
    score = 0
    # Heuristic: Long time member
    if days_known > config.TRUST_LEVEL_HIGH_DAYS:
        score += 50
    elif days_known > 7:
        score += 20
        
    # High activity
    if message_count > config.TRUST_LEVEL_HIGH_MSG_COUNT:
        score += 50
    elif message_count > 100:
        score += 20
        
    # Account age
    account_age_days = (datetime.now(member.created_at.tzinfo) - member.created_at).days
    if account_age_days > 365:
        score += 20
        
    return min(score, 100) # Cap at 100

def extract_urls_from_image(image_bytes):
    if not CV_AVAILABLE:
        print("[Log] QR scanning skipped: opencv-python-headless or numpy not installed.")
        return []

    try:
        # Convert bytes to numpy array
        nparr = np.frombuffer(image_bytes, np.uint8)
        # Decode image
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            return []

        # Initialize QR Code detector
        detector = cv2.QRCodeDetector()
        
        # Detect and decode
        retval, decoded_info, points, straight_qrcode = detector.detectAndDecodeMulti(img)
        
        if retval:
            # Filter out empty results and return unique URLs
            found_urls = list(set([info for info in decoded_info if info and info.strip()]))
            if found_urls:
                print(f"[Log] Extracted URLs from QR code: {found_urls}")
            return found_urls
            
    except Exception as e:
        print(f"[Log] Error scanning QR code: {e}")
        
    return []

def calculate_entropy(text):
    if not text:
        return 0.0
        
    # Count how many times each character appears
    char_counts = Counter(text)
    total_chars = len(text)
    
    entropy_score = 0.0
    for count in char_counts.values():
        # Calculate the probability of this character
        probability = float(count) / total_chars
        # Use the Shannon entropy formula
        entropy_score -= probability * math.log2(probability)
        
    return entropy_score

async def check_domain_entropy(content):

    if not getattr(config, "ENABLE_ENTROPY_ANALYSIS", False):
        return False, None
        
    url_pattern = r'\b(?:https?://)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{2,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    found_urls = re.findall(url_pattern, content)
    
    threshold = getattr(config, "DOMAIN_ENTROPY_THRESHOLD", 3.6)
    min_length = getattr(config, "DOMAIN_ENTROPY_MIN_LENGTH", 10)
    
    # NLP Urgency Analysis lowers entropy threshold
    if analyze_urgency(content):
        threshold -= 0.4 # Makes bot stricter if bait words are present
        print(f"[Log] Urgency detected. Lowering DGA entropy threshold to {threshold:.2f}")
    
    for url in found_urls:
        try:
            parsed = urlparse(url)
            full_domain = parsed.netloc.lower()
            if not full_domain:
                full_domain = url.lower()
                
            # Strip the TLD so it doesn't mess up the math
            core_domain = full_domain.split('.')[0]
        except:
            core_domain = url.lower()
            
        # Ignore short names they aren't long enough to be random
        if len(core_domain) < min_length:
            continue
            
        # Check if it looks like a keyboard smash
        score = calculate_entropy(core_domain)
        if score > threshold:
            print(f"[Log] [!] DGA Warning: Domain '{core_domain}' looks randomly generated! (Score: {score:.2f})")
            return True, full_domain
            
    return False, None
