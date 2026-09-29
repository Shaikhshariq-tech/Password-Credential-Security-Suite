"""
Application configuration for the Password & Credential Security Suite.
"""

from pathlib import Path


# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Input/output directories
INPUT_DIR = BASE_DIR / "input"
WORDLIST_DIR = BASE_DIR / "wordlists"
REPORT_DIR = BASE_DIR / "reports"

# Supported hashing algorithms for controlled laboratory testing
SUPPORTED_HASH_ALGORITHMS = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha512": "SHA-512",
}

# Maximum number of candidates generated during a single
# laboratory attack simulation.
MAX_SIMULATION_ATTEMPTS = 1_000_000

# Default assumed rate used only for educational crack-time estimates.
DEFAULT_ATTEMPTS_PER_SECOND = 1_000_000

# Character sets used by the brute-force simulator.
LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

# Ensure required directories exist.
INPUT_DIR.mkdir(parents=True, exist_ok=True)
WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)