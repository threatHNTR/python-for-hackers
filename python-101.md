# Python 101

## Intro

* Python2 is EOL; Python3 stores strings as unicode by default (not ascii).

* In Python, indentation is used to indicate code blocks.

* Backslashes "\" can be used to interpret multiple lines as a single line.

## Variables & Data Types:

```python
# Define a variable 'name' and assign it the string value "hunt"
name = "hunt"

# Define a variable 'name_length' and assign it the integer value 4
name_length = 4

# Print the type of the variable 'name'
print(type(name))
# Output: <class 'str'>

# Print the type of the variable 'name_length'
print(type(name_length))
# Output: <class 'int'>

# Convert the string "4" to an integer and assign it to the variable 'name_len'
name_len = int("4")

# Print the type of the variable 'name_len'
print(type(name_len))
# Output: <class 'int'>

# Define a list of strings
name_list = ["a", "b", "c"]

# Unpack the list into separate variables 'name1', 'name2', and 'name3'
name1, name2, name3 = name_list

# Print the values of the variables 'name1', 'name2', and 'name3'
print(name1, name2, name3)
# Output: a b c

# Additional comment: There are other data types available in Python besides strings and integers.
```

## Numbers:

```python
# Define an integer variable 't1_int' and assign it the value 1
t1_int = 1

# Define a floating-point variable 't1_float' and assign it the value 1.0
t1_float = 1.0

# Define a complex number variable 't1_complex' and assign it the value 3.14j
t1_complex = 3.14j

# Define a hexadecimal variable 't1_hex' and assign it the value 0xa (which is equivalent to 10 in decimal)
t1_hex = 0xa
print(t1_hex)
# Output: 10
print(type(t1_hex))
# Output: <class 'int'>

# Define an octal variable 't1_octal' and assign it the value 0o10 (which is equivalent to 8 in decimal)
t1_octal = 0o10
print(t1_octal)
# Output: 8
print(type(t1_octal))
# Output: <class 'int'>

# Perform addition with different number formats: decimal, hexadecimal, and octal
print(1 + 0x1 + 0o1)
# Output: 3

# Helper functions demonstration

# Calculate the absolute value of 4 and -4
print(abs(4), abs(-4))
# Output: 4 4

# Round floating-point numbers to the nearest integer
print(round(8.4), round(8.5), round(8.6))
# Output: 8 8 9

# Convert decimal integer 8 to binary and hexadecimal
print(bin(8), hex(8))
# Output: 0b1000 0x8
```

## Strings:

```python
# Define a string variable 'string1' and assign it the value "A String!"
string1 = "A String!"

# Define a multi-line string variable 'string2'
string2 = """multi-line
quote
!"""

# Define a string 'string3' containing an escaped character (\") and a newline (\n)
string3 = "I\"m an escaped character\nNewline"

# Repeat the character 'a' ten times and assign it to 'string4'
string4 = "a" * 10
print(len(string4))
# Output: 10

# We can use built-in functions for strings.

# Functions can be chained as well.

# Print the concatenation of a string and the length of 'string4'
print("String4 is " + str(len(string4)) + " characters long!")

# Using format placeholder to insert the length of 'string4' into the string
print("String4 is {} characters long!".format(len(string4)))
```

## Booleans & Operators:

```python
# Define a boolean variable 'not_valid' and set it to False
not_valid = False

# Check if 'not_valid' is equal to True
print(not_valid == True)
# Output: False

# Check if 'not_valid' is not equal to True
print(not_valid != True)
# Output: True

# Check if 'not_valid' is not False
print(not not_valid)
# Output: True

# Check if the comparison of 10 less than 9 is equal to True
print((10 < 9) == True)
# Output: False

# Check if 10 is less than 9
print(10 < 9)
# Output: False

# Check the boolean value of 0
print(bool(0))
# Output: False

# Check the boolean value of 1
print(bool(1))
# Output: True

# Define variables 'x' and 'y' with integer values
x = 13
y = 5

# Print the binary representation of 'x'
print(bin(x))
# Output: 0b1101

# Remove the '0b' prefix from the binary representation of 'x' and ensure it is 4 digits long, padding with 0s if necessary
print(bin(x)[2:].rjust(4, "0"))
# Output: 1101
# Explanation: The binary representation of 13 is '1101', and it's already 4 digits long.

# Perform bitwise AND operation between 'x' and 'y'
print(x & y)
# Output: 5
# Explanation: Bitwise AND of 13 (binary 1101) and 5 (binary 0101) results in 5 (binary 0101).

```

## Tuples:

```python
# Define an immutable tuple 'items' containing strings
items = ("item1", "item2", "item3")

# Create a tuple 'repeated' containing the string "again" repeated four times
repeated = ("again",) * 4

# Create a tuple 'mixed' containing a mix of string, integer, and another tuple
mixed = ("A", 1, ("B", 0))

# Combine the tuples 'items' and 'repeated' into a new tuple 'combined'
combined = items + repeated

# Print whether "item2" is present in the tuple 'items'
print("item2" in items)
# Output: True

# Find the index of "item3" in the tuple 'items'
print(items.index("item3"))
# Output: 2

# Access the first element of the tuple 'items'
print(items[0])
# Output: item1

# Slicing the tuple 'items' to retrieve elements from index 0 to index 1 (exclusive)
print(items[0:2])
# Output: ('item1', 'item2')

```

## Lists:

```python
# Define a list 'list1' containing elements of various types
list1 = ["A", "B", 1, 2.0, ["P"], [], list(), ("A")]

# Access the first element of 'list1'
print(list1[0])
# Output: A

# Access the first element of the sublist within 'list1'
print(list1[4][0])
# Output: P

# Update the first element of 'list1' to "a"
list1[0] = "a"
print(list1)
# Output: ['a', 'B', 1, 2.0, ['P'], [], [], 'A']

# Delete the first element of 'list1'
del list1[0]

# Insert "A" at the beginning of 'list1'
list1.insert(0, "A")

# Append "last" to the end of 'list1'
list1.append("last")

# Demonstration of some built-in functions for lists:
# max, min, index, count, pop, extend

# Create a new list 'list2' that refers to the same data as 'list1'
list2 = list1

# Create a shallow copy of 'list1' and assign it to 'list3'
list3 = list1.copy()

# Convert the list of strings 'list4' to a list of floats 'list5'
list4 = ["1", "2", "3"]
list5 = list(map(float, list4))
# Output: [1.0, 2.0, 3.0]
# Explanation: Converts each element of 'list4' from string to float.

```

## Dictionaries:

```python
# Define a dictionary 'dict1' with key-value pairs
dict1 = {"a": 1, "b": 2, "c": 3}

# Find the length of the dictionary
print(len(dict1))
# Output: 3

# Access the value associated with key "a" in 'dict1'
print(dict1["a"])
# Output: 1

# Another way to access the value associated with key "a" in 'dict1'
print(dict1.get("a"))
# Output: 1

# Retrieve all keys of 'dict1'
print(dict1.keys())
# Output: dict_keys(['a', 'b', 'c'])

# Retrieve all values of 'dict1'
print(dict1.values())
# Output: dict_values([1, 2, 3])

# Retrieve all key-value pairs of 'dict1'
print(dict1.items())
# Output: dict_items([('a', 1), ('b', 2), ('c', 3)])

# Add a new key-value pair "d": 4 to 'dict1'
dict1["d"] = 4
print(dict1)
# Output: {'a': 1, 'b': 2, 'c': 3, 'd': 4}

# Modify the value associated with key "a"
dict1["a"] = -1

# Update the value associated with key "a" back to 1
dict1.update({"a": 1})

# Add a nested dictionary as the value associated with key "c"
dict1["c"] = {"a": 1, "b": 2}

# Create an empty dictionary 'dict2'
dict2 = {}
```

## Sets:

```python
# Define a set 'set1' containing unique elements
set1 = {"a", "b", "c"}
print(set1)
# Output: The order of elements may vary: {'c', 'b', 'a'}

# Define a set 'set2' containing duplicate elements
set2 = {"a", "a", "a"}
print(set2)
# Output: {'a'} (since sets do not allow duplicates)

# Find the length of 'set2'
print(len(set2))
# Output: 1

# Create a set 'set3' using the set constructor with mixed types
set3 = set(("b", 1, False))

# Add "d" to 'set1'
set1.add("d")

# Update 'set3' with elements from 'set2'
set3.update(set2)

# Create a list 'list1'
list1 = ["a", "b", "c"]

# Create a set 'set4' containing integers and update it with elements from 'list1'
set4 = {4, 5, 6}
set4.update(list1)
print(set4)
# Output: {4, 5, 6, 'b', 'a', 'c'}

# Demonstration of set operations:
# - Union
# - Intersection
# - Difference
# - Symmetric Difference

# Demonstration of set methods:
# - remove
# - discard
# - pop (removes and returns an arbitrary element)
```

## Conditionals:

```python
# This code demonstrates the usage of conditional statements in Python

# Check if the condition is True, then print "true"
if True:
    print("true")
# Output: true

# Check if the condition is False, then the print statement will not be executed
if False:
    print("false")
# No output

# Demonstration of if-elif-else ladder
# Since the first condition is not met, it moves to the next condition
# The condition 1 <= 1 is met, so "1 <= 1" is printed
# The subsequent conditions are not evaluated because once a condition is met, the corresponding block is executed and the rest are skipped
if 1 < 1:
    print("1 < 1")
elif 1 <= 1:
    print("1 <= 1")
# Output: 1 <= 1

# Additional comments:
# - Comparisons can be combined using logical operators such as and, or, and not.
```

## Loops:

```python
# Demonstration of a while loop
a = 1
while a < 5:
    a += 1
    print(a)

# Output:
# 2
# 3
# 4
# 5

# Demonstration of a for loop
for i in [0, 1, 2, 3, 4]:
    print(i + 6)

# Output:
# 6
# 7
# 8
# 9
# 10

# Nested for loops
for i in range(3):
    for j in range(3):
        print(i, j)

# Output:
# 0 0
# 0 1
# 0 2
# 1 0
# 1 1
# 1 2
# 2 0
# 2 1
# 2 2

# Demonstration of a for loop with break statement
for i in range(5):
    if i == 2:
        break
    print(i)

# Output:
# 0
# 1

# Demonstration of a for loop with continue statement
for i in range(5):
    if i == 2:
        continue
    print(i)

# Output:
# 0
# 1
# 3
# 4

# Iterating over characters in a string
for c in "string":
    print(c)

# Output:
# s
# t
# r
# i
# n
# g

# Iterating over key-value pairs in a dictionary using the items() method
for k, v in {"a": 1, "b": 2, "c": 3}.items():
    print(k, v)

# Output:
# a 1
# b 2
# c 3
```

## Reading & Writing Files:

```python
# Open a file named 'top-100.txt' in read mode
f = open('top-100.txt')

# Read and print the entire content of the file
print(f.read())

# Reading lines after the file has been read will result in an empty array because the pointer is at the end of the file
arrayOfLines = f.readlines()
print(f.readlines())  # Empty array

# Move the file pointer back to the beginning of the file
f.seek(0)

# Read and print all lines of the file using readlines() method
print(f.readlines())

# Move the file pointer back to the beginning of the file
f.seek(0)

# Iterate through each line of the file and print them, stripping any leading or trailing whitespaces
for line in f:
    print(line.strip())

# Close the file
f.close()

# Open a file named 'test.txt' in write mode
f = open("test.txt", "w")

# Write "test line!" to the file
f.write("test line!")

# Close the file
f.close()
# Note: Using "a" instead of "w" will open the file in append mode

# For larger files, it's recommended to use the with statement to automatically close the file when done
# Open a file named 'rockyou.txt' in read mode with specified encoding
with open('rockyou.txt', encoding='latin-1') as f:
    # Iterate through each line of the file
    for line in f:
        # Perform necessary operations
        pass  # Placeholder for operations
```

## User input:

```python
# Prompt the user to input something and store it in the variable 'test'
test = input()

# Print the value stored in 'test'
print(test)
# Output: Prints the input provided by the user

# Prompt the user to input a number with a message and store it in the variable 'n'
n = input("Enter a number:")

# Print the value stored in 'n'
print(n)
# Output: Prints the number entered by the user

# Continuously prompt the user to input an IP address until "exit" is entered
while True:
    test = input("Enter IP: ")  # Prompt the user to input an IP address
    print(">>> {}".format(test))  # Print the input provided by the user
    if test == "exit":  # Check if the input is "exit"
        break  # Exit the loop if "exit" is entered
    else:
        print("checking..")  # If input is not "exit", continue checking
```

## Exceptions & Error Handling:

```python
# Try-except block to handle file opening errors
try:
    f = open("doesnotexistfilename")
except:
    print("File does not exist")

# Try-except block with specific exception handling
try:
    f = open("randomfile")
except FileNotFoundError:
    print("File does not exist")
except Exception as e:
    print(e)
finally:
    print("This always gets printed")

# Check conditions and raise exceptions if they are not met
n = 100
if n == 0:
    raise Exception("n cannot be 0")
if type(n) is not int:
    raise Exception("n must be an integer")
print(1/n)

# Assertions to verify conditions during runtime
n = 1
assert(n != 0)  # Triggers AssertionError if n is 0
print(1/n)
```

## Comprehensions:

```python
# Original list
list1 = ['a', 'b', 'c']

# List comprehension to create a new list 'list2' with the same elements as 'list1'
list2 = [x for x in list1]

# List comprehension to create a new list 'list3' containing only the element 'a' from 'list1'
list3 = [x for x in list1 if x == 'a']

# List comprehension to create a list 'list4' containing numbers from 0 to 4
list4 = [x for x in range(5)]

# List comprehension to create a list 'list5' containing hexadecimal representations of numbers from 0 to 4
list5 = [hex(x) for x in range(5)]

# List comprehension with conditional expression to create a list 'list6'
# If x > 0, the hexadecimal representation of x is added; otherwise, 'X' is added
list6 = [hex(x) if x > 0 else "X" for x in range(5)]

# List comprehension to create a list 'list7' containing numbers from 0 to 4 that are equal to 0 or 1
list7 = [x for x in range(5) if x == 0 or x == 1]

# Original list of lists
list8 = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]

# List comprehension to flatten the nested list 'list8' into a single list 'list9'
list9 = [y for x in list8 for y in x]
# Output: [1, 2, 3, 4, 5, 6, 7, 8, 9]

# Set comprehension to create a set 'set1' containing doubled values of numbers from 0 to 4
set1 = {x + x for x in range(5)}
# Output: {0, 2, 4, 6, 8}

# List comprehension to create a list 'list10' containing characters from the string "stringtext"
list10 = [c for c in "stringtext"]

# Joining the characters in 'list10' to form a string 'texthere'
texthere = "".join(list10)
# Output: 'stringtext'
```

## Functions & Code Reuse:

```python
# Define a function named 'function1' that prints "function hello"
def function1():
    print("function hello")

# Call the function 'function1'
function1()
# Output: function hello

# Define a function named 'function2' that returns the string "hello!"
def function2():
    return "hello!"

# Call the function 'function2' and store the returned value in 'func2'
func2 = function2()
print(func2)
# Output: hello!

# Define a function named 'function3' that accepts a parameter 's' and prints it with formatting
def function3(s):
    print("\t{}".format(s))

# Call the function 'function3' with the argument "param"
function3("param")

# Define a function named 'function4' that accepts two parameters 's1' and 's2' and prints them
def function4(s1, s2):
    print("{} {}".format(s1, s2))

# Call the function 'function4' with two arguments
function4("check", "this")

# Define a function named 'function5' with a default parameter 's1' set to "default"
def function5(s1="default"):
    print(s1)

# Call the function 'function5' without providing any arguments
function5()

# Define a function named 'function6' that accepts one required parameter 's1' and any number of additional arguments
def function6(s1, *more):
    print("{} {}".format(s1, " ".join([s for s in more])))

# Call the function 'function6' with multiple arguments
function6("func6", "arg1", "arg2", "arg3")

# Define a function named 'function7' that accepts any number of keyword arguments and prints them
def function7(**ks):
    for a in ks:
        print(a, ks[a])

# Call the function 'function7' with keyword arguments
function7(a="1", b="2", c="3")

# Global and function scope example
v = 100

# Define a function named 'function8' that modifies the global variable 'v'
def function8():
    global v
    v += 1
    print(v)

# Call the function 'function8' which modifies the global variable 'v'
function8()
# Output: 101

# The value of the global variable 'v' has been modified
print(v)
# Output: 101

# Functions can call other functions
def function9():
    function1()

function9()
# Output: function hello

# Recursion example
def function10(x):
    print(x)
    if x > 0:
        function10(x-1)

function10(5)
# Output:
# 5
# 4
# 3
# 2
# 1
# 0
```

## Lambdas:

```python
# Single line anonymous function using lambda
add4 = lambda x: x + 4
print(add4(10))
# Output: 14

add = lambda x, y: x + y
print(add(10, 4))
# Output: 14

print((lambda x, y: x * y)(2, 3))
# Output: 6

# Lambda function to check if a number is even
is_even = lambda x: x % 2 == 0

# Lambda function to split a string into blocks of given size
blocks = lambda x, y: [x[i:i+y] for i in range(0, len(x), y)]
print(blocks("string", 2))
# Output: ['st', 'ri', 'ng']

# Lambda function to convert characters to ASCII values using ord()
to_ord = lambda x: [ord(i) for i in x]
print(to_ord("ABCD"))
# Output: [65, 66, 67, 68]
```
