# Python 201

## Decorators

* Decorators - used to wrap another function to extend behavior of wrapped function without modifying it.

```py
from datetime import datetime
import time

def logger(func):
    """
    Decorator function to log the execution time of another function.
    """
    def wrapper():
        """
        Wrapper function to extend behavior of the wrapped function without modifying it.
        """
        print("-" * 50)
        # Print timestamp before the function is called
        print("Execution started at {}".format(datetime.today().strftime("%H:%M:%S")))
        

        func()  # Call the wrapped function
        # Print timestamp after the function is called
        print("Execution completed at {}".format(datetime.today().strftime("%H:%M:%S")))
        print("-" * 50)
    return wrapper

@logger
def demo_function():
    """
    Sample function to demonstrate the usage of the logger decorator.
    """
    print("Executing a task")
    time.sleep(3)  # Simulate a time-consuming task
    print("Task completed")

demo_function()

# Output:
# --------------------------------------------------
# Execution started at HH:MM:SS
# Executing a task
# Task completed
# Execution completed at HH:MM:SS
# --------------------------------------------------

logger(demo_funtion())
```

* We can also pass arguments to decorators.

```py
from datetime import datetime
import time

def logger_args(func):
    """
    Decorator function to log the execution time of another function with arguments.
    """
    def wrapper(*args, **kwargs):
        """
        Wrapper function to extend behavior of the wrapped function without modifying it.
        """
        print("-" * 50)
        print("Execution started at {}".format(datetime.today().strftime("%H:%M:%S")))

        func(*args, **kwargs)  # Pass the arguments to the wrapped function

        print("Execution completed at {}".format(datetime.today().strftime("%H:%M:%S")))
        print("-" * 50)
    return wrapper

@logger_args
def demo_function_args(sleep_time):
    """
    Sample function to demonstrate the usage of the logger_args decorator with arguments.
    """
    print("Executing task")
    time.sleep(sleep_time)  # Simulate a time-consuming task
    print("Completed task")

# Call the wrapped function with different sleep times
demo_function_args(1)
demo_function_args(2)
demo_function_args(3)

# Output:
# --------------------------------------------------
# Execution started at HH:MM:SS
# Executing task
# Completed task
# Execution completed at HH:MM:SS
# --------------------------------------------------
# --------------------------------------------------
# Execution started at HH:MM:SS
# Executing task
# Completed task
# Execution completed at HH:MM:SS
# --------------------------------------------------
# --------------------------------------------------
# Execution started at HH:MM:SS
# Executing task
# Completed task
# Execution completed at HH:MM:SS
# --------------------------------------------------
```

## Generators

* Generator - function that returns an iterator using the keyword ```yield``` instead of ```return```.

* While ```return``` exits the function, ```yield``` pauses the function and saves the state of variables.

* When the generator function is called, it does not execute the function body immediately; it returns a generator object that can be iterated over to produce the values.

```py
def gen_demo():
    """
    Generator function to demonstrate the usage of generators.
    """
    n = 1
    yield n  # Yield the initial value of n

    n += 1
    yield n  # Yield the updated value of n

    n += 1
    yield n  # Yield the updated value of n

# Create a generator object
test = gen_demo()
# Prints generator object's address
print(test)


# Retrieve and print values from the generator using next()
print(next(test))  # Output: 1
print(next(test))  # Output: 2
print(next(test))  # Output: 3

# If we call next() once more, it will raise a StopIteration error

# Create another generator object
test2 = gen_demo()

# Iterate over the generator using a for loop
for a in test2:
    print(a)
    # Output:
    # 1
    # 2
    # 3
```

* We can also create generator functions with loops.

```py
def xor_static_key(a):
    """
    Generator function to perform XOR operation with a static key on each character of the input string.
    """
    key = 0x5
    for i in a:
        yield chr(ord(i) ^ key)

# Create a generator object by calling xor_static_key function
# and passing the input string "test"
for i in xor_static_key("test"):
    print(i)
    # Output:
    # Characters of "test" XORed with the static key 0x5

```

* Similar to lambda functions, anonymous generators are supported.

```py
# Create a generator expression to perform XOR operation with a static key on each character of the input string
xor_static_key_demo = (chr(ord(i) ^ 0x5) for i in "test")
# Parentheses are used to define a generator expression instead of square brackets for a list comprehension

# Prints the generator object
print(xor_static_key_demo)

# Iterate over the generator object and print each yielded value
for i in xor_static_key_demo:
    print(i)
    # Output:
    # Characters of "test" XORed with the static key 0x5
```

## Serialization

* Data serialization is the process of converting structured data to a format that allows storage of data.

* Serialization can be reversed to recover its original structure; it's called deserialization.

```py
# Import the pickle module, a library for object serialization
import pickle

# Define a dictionary with some data
hackers = {"neut": 1, "geohot": 100, "neo": 1000}

for key, value in hackers.items():
  print(key, value)

# Serialize the dictionary using pickle.dumps() and print the serialized data
serialized = pickle.dumps(hackers)

# Prints the serialized data in binary format
print(serialized)

# Deserialize the serialized data using pickle.loads() and print the deserialized data
hackers_v2 = pickle.loads(serialized)

# Prints the deserialized data, which is the original dictionary
print(hackers_v2)

for key, value in hackers_v2.items():
  print(key, value)

# Save the serialized version of the dictionary to a file
# "wb" mode refers to write binary mode
with open("hackers.pickle", "wb") as handle:
    pickle.dump(hackers, handle)

# Load the serialized file by deserializing it
# "rb" mode refers to read binary mode
with open("hackers.pickle", "rb") as handle:
    hackers_v3 = pickle.load(handle)

# Prints the dictionary loaded from the serialized file, which is the same as the original dictionary
print(hackers_v3)
```

## Closures

* Closure - nested function that allows to access variables of outer function, even after outer function is closed.

* Usually, in nested functions, the inner function has access to variables defined in the outer function.

* Example without closures:

```py
def print_out(a):
    """
    Outer function that defines a variable 'a' and an inner function 'print_in' that prints the value of 'a'.
    """
    print("Outer: {}".format(a))

    def print_in():
        """
        Inner function that prints the value of 'a'.
        """
        print("\tInner: {}".format(a))
  
    print_in()  # Call the inner function

print_out("test")

# This prints both Outer and Inner messages.
# This demonstrates nested functions.
```

* Example using closures:

```py
def print_out(a):
    """
    Outer function that defines a variable 'a' and an inner function 'print_in' that prints the value of 'a'.
    """
    print("Outer: {}".format(a))

    def print_in():
        """
        Inner function that prints the value of 'a'.
        """
        print("\tInner: {}".format(a))
  
    return print_in
    # Here, we are not calling the closure function (inner function) directly

test2 = print_out("test")

# If we call print_out("test"),
# only the Outer function message is printed.

# Even if we delete the function here, the closure function will work.
del print_out

test2()
# Prints both Outer and Inner functions.
# It remembers the value, even after executing and deleting the function.
``
