#!/usr/bin/env python3
"""
Email Hasher Script

This script takes an email address as a command line argument,
hashes it using the SHA-256 algorithm, and writes the hash to a file.

Usage:
    python email_hasher.py <email_address>

Example:
    python email_hasher.py example@email.com
"""

import sys
import hashlib

def hash_email(email):
    bytes_1 = email.encode('utf-8') 
    sha = hashlib.sha256(bytes_1)
    return sha.hexdigest()

def write_hash_to_file(hash_value, filename="hash.email"):
    with open(filename, 'w') as f:
      f.write(hash_value)   
    
def main():
    if len(sys.argv) != 2:
        print("Usage: python email_hasher.py <email_address>")
        sys.exit(1)

    email = sys.argv[1]
    hash = hash_email(email)
    
    write_hash_to_file(hash)

if __name__ == "__main__":
    main()