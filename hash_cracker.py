import subprocess
import os
import time
from password_strength import PasswordStats # type: ignore

# Configuration
HASH_FILE = 'hashes.txt'  # File with hashes (e.g., MD5: 5d41402abc4b2a76b9719d911017c592)
WORDLIST = 'rockyou.txt'  # Path to wordlist
HASH_TYPE = '0'  # Hashcat mode: 0=MD5, 1000=NTLM, etc. (check hashcat --help)
OUTPUT_FILE = 'cracked.txt'
TOOL = 'hashcat'  # 'hashcat' or 'john'

def crack_hashes():
    if TOOL == 'hashcat':
        # Hashcat command: hashcat -m <mode> -a 0 <hashfile> <wordlist> -o <output>
        cmd = [
            'hashcat', '-m', HASH_TYPE, '-a', '0', HASH_FILE, WORDLIST, '-o', OUTPUT_FILE,
            '--force'  # Force CPU if no GPU
        ]
    elif TOOL == 'john':
        # John the Ripper: john --wordlist=<wordlist> <hashfile>
        cmd = ['john', '--wordlist=' + WORDLIST, HASH_FILE]
        # Note: John outputs to <hashfile>.john.pot; we'll parse that
    
    try:
        print(f"Starting {TOOL} cracking...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)  # 1-hour timeout
        print("Cracking completed.")
        if TOOL == 'hashcat':
            return parse_hashcat_output()
        elif TOOL == 'john':
            return parse_john_output()
    except subprocess.TimeoutExpired:
        print("Cracking timed out.")
        return {}
    except FileNotFoundError:
        print(f"{TOOL} not found. Install and add to PATH.")
        return {}

def parse_hashcat_output():
    cracked = {}
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    cracked[parts[0]] = parts[1]  # hash:password
    return cracked

def parse_john_output():
    cracked = {}
    pot_file = HASH_FILE + '.john.pot'
    if os.path.exists(pot_file):
        with open(pot_file, 'r') as f:
            for line in f:
                parts = line.strip().split('$')
                if len(parts) >= 2:
                    # Simplified parsing; adjust for hash format
                    cracked[parts[0]] = parts[-1]  # hash:password
    return cracked

def analyze_password_strength(password):
    stats = PasswordStats(password)
    strength = stats.strength()  # 0-1 score
    feedback = []
    if len(password) < 8:
        feedback.append("Too short (<8 chars)")
    if not any(c.isupper() for c in password):
        feedback.append("No uppercase")
    if not any(c.islower() for c in password):
        feedback.append("No lowercase")
    if not any(c.isdigit() for c in password):
        feedback.append("No digits")
    if not any(c in '!@#$%^&*()' for c in password):
        feedback.append("No special chars")
    return strength, feedback

def main():
    cracked_passwords = crack_hashes()
    if not cracked_passwords:
        print("No passwords cracked.")
        return
    
    print("Cracked Passwords and Analysis:")
    for hash_val, password in cracked_passwords.items():
        strength, feedback = analyze_password_strength(password)
        print(f"Hash: {hash_val}")
        print(f"Password: {password}")
        print(f"Strength Score: {strength:.2f} (0=weak, 1=strong)")
        if feedback:
            print(f"Issues: {', '.join(feedback)}")
        print("-" * 40)

if __name__ == "__main__":
    main()
