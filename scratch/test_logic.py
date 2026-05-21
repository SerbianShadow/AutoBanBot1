import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config

print(f"NEW_DOMAIN_TRUST_EXEMPT_SCORE: {getattr(config, 'NEW_DOMAIN_TRUST_EXEMPT_SCORE', 50)}")
print(f"SPAM_TRUST_EXEMPT_SCORE: {getattr(config, 'SPAM_TRUST_EXEMPT_SCORE', 70)}")
