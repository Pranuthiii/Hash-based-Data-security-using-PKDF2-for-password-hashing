Password Hashing and Verification Program

Overview
This program is a Python-based tool designed to securely hash and verify user passwords using PBKDF2 (Password-Based Key Derivation Function 2) with the SHA-256 hashing algorithm. 
It incorporates the use of a unique, random salt for each password to enhance security and prevent common attacks such as brute-force and rainbow table attacks.

Features

Secure Hashing with PBKDF2: Utilizes hashlib.pbkdf2_hmac() to hash passwords with SHA-256, which is computationally intensive and secure.

Random Salt Generation: Generates a unique 16-byte random salt for each password to ensure that even identical passwords have different hashes.

Password Verification: Validates password attempts by hashing them with the same salt and comparing the result to the stored hash.

Customizable Iterations: Includes 100,000 iterations by default for increased security. The number of iterations can be adjusted to balance performance and security.


Requirements

Python 3.x
Standard Python libraries: hashlib, os, binascii
Installation
Ensure Python 3.x is installed on your system.
No external libraries are required; the program runs with Python's built-in modules.


Usage
1. Running the Program
Copy the provided code into a Python file (e.g., password_hashing.py).
Run the script using a terminal or command prompt:
bash
Copy code
python password_hashing.py

2. Input Prompts
The program will prompt the user to enter a user ID and password to create and hash the password.
After hashing, it displays the unique salt (in hexadecimal format) and the password hash.

3. Verification
The user is prompted to re-enter their password to verify it. The program will hash the attempt with the same salt and check if it matches the original hash.
The program outputs whether the password verification is valid or not.
Code Explanation
hash_password() Function

Purpose: Hashes a given password using PBKDF2 with SHA-256 and a salt.

Parameters:

password: The password to hash.

salt: A unique salt (if not provided, a 16-byte salt is generated).

iterations: Number of PBKDF2 iterations (default: 100,000).

Returns: The salt and the password hash in hexadecimal format.

verify_password() Function

Purpose: Verifies a password attempt by hashing it with the same salt and comparing it to the stored hash.

Parameters:
stored_password_hash: The original hashed password to compare against.

password_attempt: The password attempt to verify.

salt: The salt used to hash the original password.

iterations: Number of PBKDF2 iterations (should match the value used during hashing).

Returns: True if the attempt matches the stored hash, False otherwise.

Security Considerations

Salting: The use of a unique salt for each password ensures that even if two users have the same password, their hashes will be different, protecting against rainbow table attacks.

Iterations: The high iteration count (100,000 by default) increases the time required to hash each password, making brute-force attacks significantly more challenging.

Algorithm Choice: PBKDF2 with SHA-256 is a proven, secure standard for password hashing. Future-proofing may involve evaluating algorithms resistant to quantum computing threats as needed.

Customization

Iteration Count: Modify the iterations parameter for stronger security:
salt, password_hash = hash_password(password, iterations=200000)

Salt Length: Adjust the salt length as needed:
salt = os.urandom(32)  # Generates a 32-byte salt
