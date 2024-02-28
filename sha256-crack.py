# Importing necessary libraries
import sys
import argparse
import hashlib
import logging

# Function to crack a SHA256 password hash
def crack_password_hash(reqd_hash, pass_file):
    attempts = 0
    # Open the password list file
    with open(pass_file, 'r', encoding='latin-1') as pass_list:
        # Iterate through each password in the list
        for password in pass_list:
            password = password.strip("\n").encode('latin-1')  # Remove newline and encode password
            pass_hash = hashlib.sha256(password).hexdigest()  # Calculate SHA256 hash of the password
            # Check if the calculated hash matches the required hash
            if pass_hash == reqd_hash:
                return password.decode('latin-1'), attempts  # Return the cracked password and attempts made
            attempts += 1  # Increment attempt counter
    return None, attempts  # Return None if password not found

# Main function
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Password Hash Cracker")
    parser.add_argument("hash", help="SHA256 hash to crack")
    parser.add_argument("--wordlist", "-w", default="/usr/share/wordlists/rockyou.txt", help="Password wordlist file")
    args = parser.parse_args()

    reqd_hash = args.hash
    pass_file = args.wordlist

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    logger = logging.getLogger(__name__)

    logger.info("Attempting to crack hash: %s", reqd_hash)
    # Call the crack_password_hash function to attempt cracking
    password, attempts = crack_password_hash(reqd_hash, pass_file)
    if password:
        logger.info("Password hash found after %d attempts! %s hashes to %s", attempts, password, reqd_hash)
    else:
        logger.info("Password hash not found!")

# Entry point
if __name__ == "__main__":
    main()
