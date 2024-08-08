# MedSecureApp

## Usage
1. Login:
- Use your credentials to log in to the application.
  
2. Search Patient Records:
- Enter patient information in the search field to retrieve records securely.

3. Access Control:
- Only authorized doctors can access their assigned patient records.

4. Password Management:
- Ensure strong passwords for user accounts. Passwords are securely hashed and verified using BCrypt.

## Security Enhancements
1. SQL Injection Fix:
- Refactored the searchResults() method to use prepared statements and bind parameters.

2. Access Control Implementation:
- Added a hasAccess() function to enforce data isolation between doctors and patient records.

3. Password Encryption:
- Integrated BCrypt hashing for password storage and verification.
Implemented methods to hash and check passwords securely.
 
4. Session Management:
- Introduced session timeout to prevent unauthorized access through hijacked sessions.

5. Secure Authentication:
- Established strong password policies and limited login attempts to protect against brute force attacks.
