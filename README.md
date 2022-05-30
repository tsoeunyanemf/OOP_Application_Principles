# End of Module Assignment: OOP application of principles and concepts

In my final submission, I had a focus on two security threats, those being Cross-Site Scripting (XSS) as well as insider threats. In my practical approach, I have mainly focused on security from the client side rather than from insider threats. The python code addresses the following key items:
1.	Sanitization of user input to ensure protection against XSS and other common attacks as a result of unsensitized inputs
2.	Storing of user passwords in the database in an encrypted format
3.	User login to the portal using Multi-Factor authentication as well as captcha for curbing automated login attempts such as those from botnets

### Sanitization:
In order to provide barriers against invalid inputs, all user input will have character restriction as a first in line. This means that some combinations of special characters and codes will be restricted from the valid set of input data. Then, for insertions and querying data from the database, safe parameters are crafted to ensure that non can be executed directly to the database. 

### Encrypting user Passwords
Saving password in an unencrypted format is one of the critical basics that should be avoided at all costs. If data were to be access by malicious users, it means that essentially compromise has ensured since the no additional effort is required to gain access. The user passwords are encrypted using bcrypt and are then stored in the database. The function essentially produces a hash of a password, using an additional salt parameter to strengthen the output to avoid any collisions as a result of hashing. The database only has the hash value saved and when user has to login, the hash is retrieved and a comparison using the function bcrypt.checkpw(password, hash) is used  to validate the input password.

### Multi-factor authentication
Access to the system will enforce a multi-factor authentication using a time-based one-time-password (OTP) along with the user credentials. The library used is derived from PyOTP. When being enforced, the user is prompted for their credentials (username and password) and those are validated against the already stored credentials. The user is then prompted for the OTP and once inserted, they are then prompted to enter text from the captcha image. Login success is base on all the mentioned parameters to be correct. CAPTCHA is enabled to ensure that we can secure the platform against unsolicited login attempts which any lead to system instability or even denial-of-service(DoS).



### References:
Benita, H (2021) Preventing SQL Injection Attacks With Python. Available from:
https://realpython.com/prevent-python-sql-injection/ [Accessed 29 may 2022].
PyOTP PyOTP -The Python One-Time Password Library. Available from https://pyauth.github.io/pyotp/ [Accessed 29 May 2022].
PyPI(2022) bcrypt 3.2.2 Available from: https://pypi.org/project/bcrypt/ [Accessed 28 May 2022]
