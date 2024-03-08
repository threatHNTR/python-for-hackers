# Object Oriented Programming

## Intro

* Object Oriented Programming groups variables & methods

* Structures software into reusable blueprints (classes)

* Blueprint templates can create objects (instantiation)

* Classes contain data (attributes)

* Class contains functions (methods)

* Advantages of Object Oriented Programming:

  * Model & group complex data in reusable way
  * Leverage existing structures (inheritance)
  * Enables class-specific behavior (polymorphism)
  * Secure & protect attributes & methods (encapsulation)
  * Extendible & modular (overloading)

## Classes and Objects

```py
# Class documentation
# Class attributes, methods, and usage

class Person:
  'Person base class'
  # Above line is a class documentation string 

  # Class attribute
  # Shared by all objects
  wants_to_hack = True

  # Instance initialization method
  # Method which takes self argument as a reference to the object
  # Invoked automatically whenever object initiated
  def __init__(self, name, age):
    self.name = name
    self.age = age
  
  # User-defined method
  def print_name(self):
    print("My name is {}".format(self.name))

  def print_age(self):
    print("My age is {}".format(self.age))
  
  def birthday(self):
    self.age += 1

# Create instances of class
bob = Person("bob", 30)
alice = Person("alice", 20)
hunter = Person("hunter", 35)

# Print objects
print(bob)
print(alice)
print(hunter)
# Prints Person objects

# Print attribute values of objects
print(bob.name)
print(alice.age)
print(hunter.age)

# Class-specific functions
# Check if the object has the attribute mentioned
print(hasattr(hunter, "age"))
print(hasattr(hunter, "asd"))

# Returns attribute value for object
print(getattr(hunter, "name"))

# Set attribute for object, creates attribute if it does not exist
setattr(hunter, "house", 2)
print(getattr(hunter, "house"))

# Deletes attribute
# If we try to access it now, we get AttributeError
delattr(hunter, "house")

# User-defined methods
# Each object calls the function with their own attributes
hunter.print_name()
alice.print_age()

# Modify object attributes
hunter.age = 34
hunter.print_age()  # Print modified age
hunter.birthday()   # Increase age by 1
hunter.print_age()  # Print age after birthday

# Check class attributes
print(Person.wants_to_hack)
print(alice.wants_to_hack)
# Both print True

# Special built-in attributes for all classes
# Prints namespace dictionary
print(Person.__dict__)

# Prints "Person base class", the class documentation string
print(Person.__doc__)

# Del to delete the attributes, objects, or classes

# bob.print_name() throws AttributeError after deleting the attribute
del bob.name

# Delete the class
# alice.name still exists but cannot create a new object now
del Person
print(alice.name)
```

## Inheritance

* Inheritance is used to create a new class derived from a parent class by avoiding redundancy.

```py
# Base or parent class
class Person:
    'Person base class'

    # Class attribute shared by all objects
    wants_to_hack = True

    # Instance initialization method
    def __init__(self, name, age):
        self.name = name
        self.age = age

    # User-defined method to print name
    def print_name(self):
        print("My name is {}".format(self.name))

    # User-defined method to print age
    def print_age(self):
        print("My age is {}".format(self.age))

    # User-defined method to increment age
    def birthday(self):
        self.age += 1

# Derived or child class
class Hacker(Person):
    def __init__(self, name, age, cves):
        super().__init__(name, age)
        # Call the parent class's __init__ method to initialize inherited attributes
        self.cves = cves
  
    # Override parent class's method to print name
    def print_name(self):
        print("My name is {} and I have {} CVEs".format(self.name, self.cves))
  
    # New method specific to Hacker class to return total CVEs
    def total_cves(self):
        return self.cves

# Create instances of Person and Hacker classes
bob = Person("bob", 30)
alice = Hacker("alice", 20, 5)

# Print names of instances
bob.print_name()
alice.print_name()
# Different outputs as Hacker class overrides print_name method

# Increment age of both instances
bob.birthday()
alice.birthday()

# Print ages of both instances
bob.print_age()
# 31
alice.print_age()
# 21

# Print total CVEs of alice
print(alice.total_cves())
# 5
# Attempting to call total_cves() on bob throws AttributeError as it's not defined for Person class

# Check subclass relationship
print(issubclass(Hacker, Person))
# True
print(issubclass(Person, Hacker))
# False

# Check instance relationship
print(isinstance(bob, Person))
# True
print(isinstance(bob, Hacker))
# False
print(isinstance(alice, Person))
# True
print(isinstance(alice, Hacker))
# True

```

## Encapsulation

* Encapsulation - restricting access using OOP.

```py
# Base class demonstrating encapsulation
class Person:
    'Person base class'

    # Class attribute shared by all objects
    wants_to_hack = True

    def __init__(self, name, age):
        self.name = name
        self.__age = age
        # Double underscores added to protect the variable

    # Getter method to access the private attribute __age
    def get_age(self):
        return self.__age
  
    # Setter method to modify the private attribute __age
    def set_age(self, age):
        self.__age = age

    # User-defined method to print name
    def print_name(self):
        print("My name is {}".format(self.name))

    # User-defined method to print age
    def print_age(self):
        print("My age is {}".format(self.__age))
  
    # User-defined method to increment age
    def birthday(self):
        self.__age += 1

# Create an instance of the Person class
bob = Person("bob", 30)

# Attempting to directly access private attribute __age throws AttributeError
# print(bob.age)  # Throws AttributeError
# print(bob.__age)  # Throws AttributeError

# Use getter method to access private attribute __age
print(bob.get_age())
# 30

# Use setter method to modify private attribute __age
bob.set_age(31)
print(bob.get_age())
# 31

# Call the birthday method to increment age
bob.birthday()
print(bob.get_age())
# 32

# Print all attributes and values, including the private ones
# Shows that the private attribute is named as _Person__age
# Demonstrates that encapsulation is not reliable for security
print(bob.__dict__)

# Directly modifying private attribute __age using name mangling
# Demonstrates that encapsulation can be bypassed, but it's not recommended
bob._Person__age = 50
print(bob.get_age())
# 50
```

## Polymorphism

* Polymorphism - using a common interface multiple times, like using the same function with different types of arguments.

```py
# Base class demonstrating polymorphism
class Person:
    'Person base class'

    # Class attribute shared by all objects
    wants_to_hack = True

    def __init__(self, name, age):
        self.name = name
        self.age = age
  
    # User-defined method to print name
    def print_name(self):
        print("My name is {}".format(self.name))

    # User-defined method to print age
    def print_age(self):
        print("My age is {}".format(self.age))
  
    # User-defined method to increment age
    def birthday(self):
        self.age += 1

# Derived class demonstrating polymorphism
class Hacker(Person):
    def __init__(self, name, age, cves):
        super().__init__(name, age)
        self.cves = cves
  
    # Override parent class's method to print name
    def print_name(self):
        print("My name is {} and I have {} CVEs".format(self.name, self.cves))
  
    # New method specific to Hacker class to return total CVEs
    def total_cves(self):
        return self.cves

# Create instances of Person and Hacker classes
bob = Person("bob", 30)
alice = Hacker("alice", 25, 10)

# Create a list containing both Person and Hacker instances
people = [bob, alice]

# Iterate through the list and call the print_name method for each object
# Demonstrate polymorphism as the same method produces different outputs based on the object type
for person in people:
    person.print_name()
    print(type(person))

# Define a function to perform actions on objects, demonstrating polymorphism
def obj_dump(object):
    object.print_name()
    print(object.age)
    object.birthday()
    print(object.age)
    print(object.__class__.__name__)

# Call the obj_dump function for both Person and Hacker objects
obj_dump(bob)
obj_dump(alice)
```

## Operator Overloading

* Operator Overloading - defining how operators behave for custom classes.

```py
# Base class demonstrating operator overloading
class Person:
    'Person base class'

    # Class attribute shared by all objects
    wants_to_hack = True

    def __init__(self, name, age):
        self.name = name
        self.age = age
  
    # User-defined method to print name
    def print_name(self):
        print("My name is {}".format(self.name))

    # User-defined method to print age
    def print_age(self):
        print("My age is {}".format(self.age))
  
    # User-defined method to increment age
    def birthday(self):
        self.age += 1

    # Inbuilt function for printing class object
    # Inbuilt functions are denoted by underscores before and after the name
    def __str__(self):
        return "My name is {} and I am {} years old".format(self.name, self.age)
  
    # User-defined method to implement addition operation for objects of this class
    # Returns the sum of ages of two objects
    def __add__(self, other):
        # 'other' refers to another instance of the class
        return self.age + other.age

# Create instances of the Person class
bob = Person("bob", 30)
alice = Person("alice", 25)

# Print the objects, demonstrating the use of __str__ method for custom string representation
print(bob)
# By default, this prints out the class object and its address in memory
# But due to __str__, this prints the custom message

# Perform addition operation on objects, demonstrating operator overloading
print(bob + alice)
print(alice + bob)
# Both print 55

# We can implement multiple dunder methods for other operators as well
```

## Class Decorators

* Class Decorators - decorators applied to class methods and properties.

```py
# Base class demonstrating class decorators
class Person:
    'Person base class'

    # Class attribute shared by all objects
    wants_to_hack = True

    def __init__(self, name, age):
        self.name = name
        self.__age = age

    def get_age(self):
        return self.__age
  
    def set_age(self, age):
        self.__age = age

    # Property decorator to define age as a property
    @property
    def age(self):
        return self.__age

    # Property setter to set age property
    @age.setter
    def age(self, age):
        self.__age = age
  
    # Property deleter to delete age property
    @age.deleter
    def age(self):
        del self.__age

    # Class method decorator to access class-level attributes
    @classmethod
    def wants_to(cls):
        return cls.wants_to_hack
  
    # Class method decorator to create instances of class
    @classmethod
    def bob_factory(cls):
        return cls("bob", 30)
  
    # Static method decorator to define static methods
    # These methods cannot access class attributes and per-instance attributes
    # These methods do not take any parameters
    @staticmethod
    def static_print():
        print("Static message")

    # User-defined method to print name
    def print_name(self):
        print("My name is {}".format(self.name))

    # User-defined method to print age
    def print_age(self):
        print("My age is {}".format(self.__age))
  
    # User-defined method to increment age
    def birthday(self):
        self.__age += 1

# Create an instance of the Person class
bob = Person("bob", 30)

# Print age property using property decorator
print(bob.age)
# 30

# Set age property using property setter
bob.age = 50
print(bob.age)
# 50

# Access class attribute using class method decorator
print(Person.wants_to())
# True

# Create instances using class method decorator
bob1 = Person.bob_factory()
bob2 = Person.bob_factory()

# Print names of instances created using class method decorator
bob1.print_name()
bob2.print_name()

# Call static method using static method decorator
Person.static_print()
bob2.static_print()
# Prints the same output
```
