import sqlite3
import datetime
from config import DB_NAME

def get_connection():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = get_connection()
    c = conn.cursor()
    
    # Users table for Trust Factor
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    guild_id INTEGER,
                    message_count INTEGER DEFAULT 0,
                    trust_score INTEGER DEFAULT 0,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP
                )''')

    # Logs table
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    guild_id INTEGER,
                    action_type TEXT,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS spam_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    guild_id INTEGER,
                    channel_id INTEGER,
                    message_content TEXT,
                    spam_type TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS user_strikes (
                    user_id INTEGER,
                    guild_id INTEGER,
                    strike_count INTEGER DEFAULT 0,
                    last_strike TIMESTAMP,
                    PRIMARY KEY(user_id, guild_id)
                )''')
                
    # Add column for legacy DB Support
    try:
        c.execute("ALTER TABLE user_strikes ADD COLUMN last_strike TIMESTAMP")
    except sqlite3.OperationalError:
        pass # Column already exists
    
    conn.commit()
    conn.close()

def update_user_stats(user_id, guild_id):
    conn = get_connection()
    c = conn.cursor()
    now = datetime.datetime.now()
    
    c.execute("SELECT message_count, first_seen FROM users WHERE user_id = ? AND guild_id = ?", (user_id, guild_id))
    row = c.fetchone()
    
    if row:
        new_count = row[0] + 1
        c.execute("UPDATE users SET message_count = ?, last_seen = ? WHERE user_id = ? AND guild_id = ?", 
                  (new_count, now, user_id, guild_id))
    else:
        c.execute("INSERT INTO users (user_id, guild_id, message_count, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                  (user_id, guild_id, 1, now, now))
        
    conn.commit()
    conn.close()

def log_action(user_id, guild_id, action_type, details):
    conn = get_connection()
    c = conn.cursor()
    c.execute("INSERT INTO logs (user_id, guild_id, action_type, details) VALUES (?, ?, ?, ?)",
              (user_id, guild_id, action_type, details))
    conn.commit()
    conn.close()

def store_spam_message(user_id, guild_id, channel_id, content, spam_type):
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO spam_messages (user_id, guild_id, channel_id, message_content, spam_type) VALUES (?, ?, ?, ?, ?)",
        (user_id, guild_id, channel_id, content, spam_type)
    )
    conn.commit()
    conn.close()

def get_user_data(user_id, guild_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE user_id = ? AND guild_id = ?", (user_id, guild_id))
    row = c.fetchone()
    conn.close()
    return row

def add_user_strike(user_id, guild_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT strike_count, last_strike FROM user_strikes WHERE user_id = ? AND guild_id = ?", (user_id, guild_id))
    row = c.fetchone()
    
    now = datetime.datetime.now()
    
    if row is not None:
        strike_count = row[0]
        last_strike_str = row[1]
        
        # Calculate how many hours have passed since the last strike
        should_reset = False
        if last_strike_str:
            try:
                if isinstance(last_strike_str, str):
                    if '.' in last_strike_str:
                        last_strike = datetime.datetime.strptime(last_strike_str, "%Y-%m-%d %H:%M:%S.%f")
                    else:
                        last_strike = datetime.datetime.strptime(last_strike_str, "%Y-%m-%d %H:%M:%S")
                else:
                    last_strike = last_strike_str
                    
                import config
                decay_hours = getattr(config, "STRIKE_DECAY_HOURS", 24)
                
                # If the time difference is greater than the decay hours, reset strikes
                if (now - last_strike).total_seconds() > decay_hours * 3600:
                    should_reset = True
            except Exception as e:
                print(f"[Log] Error parsing last_strike timestamp: {e}")
                
        if should_reset:
            new_strikes = 1
            print(f"[Log] User {user_id}'s strikes decayed. Resetting to 1.")
        else:
            new_strikes = strike_count + 1
            
        c.execute("UPDATE user_strikes SET strike_count = ?, last_strike = ? WHERE user_id = ? AND guild_id = ?", (new_strikes, now, user_id, guild_id))
    else:
        new_strikes = 1
        c.execute("INSERT INTO user_strikes (user_id, guild_id, strike_count, last_strike) VALUES (?, ?, ?, ?)", (user_id, guild_id, new_strikes, now))
        
    conn.commit()
    conn.close()
    return new_strikes

