#REF: https://dev.to/otumianempire/custom-password-validation-in-python-refactoring-the-function-for-password-validation-2i95
#REF: https://www.geeksforgeeks.org/password-validation-in-python/

#Conditions for a valid password are:
#Should be between 8 to 15 characters long.
#Should only contain valid characters, with at least one special character
#Should have at least one number.
#Should have at least one uppercase and one lowercase character.

import getpass
import string
import secrets
import sqlite3

from string import (
        punctuation, whitespace, digits,
        ascii_lowercase, ascii_uppercase)

def pass_validator(password):
    new_password = password.strip()


    while True:
      #Testing password length
      MIN_SIZE = 8
      MAX_SIZE = 15
      password_size = len(new_password)

      if password_size < MIN_SIZE or password_size > MAX_SIZE:
        new_password = getpass.getpass("Password length should be between 8 and 15 characters in length, try again: ")
        #return False
        continue

      #Testing special characters
      valid_chars = {'-', '_', '.', '!', '@', '#', '$', '^', '&', '(', ')'}
      invalid_chars = set(punctuation + whitespace) - valid_chars

      for char in invalid_chars:
        if char in new_password:
          new_password = getpass.getpass("Password has invalid characters, try again: ")
          #return False
          continue
      
      password_has_special_chars = False
      
      for char in valid_chars:
        if char in new_password:
          password_has_special_chars = True
          break
      
      if not password_has_special_chars:
        new_password = getpass.getpass("Password should have at least one special character, try again: ")
        #return False
        continue

      #Testing is password has digits
      password_has_digit = False

      for char in new_password:
        if char in digits:
          password_has_digit = True
          break

      if not password_has_digit:
        new_password = getpass.getpass("Password should have digits, try again: ")
        continue
        #return False

      #Testing Password character case
      password_has_lowercase = False

      for char in new_password:
        if char in ascii_lowercase:
            password_has_lowercase = True
            break

      if not password_has_lowercase:
        new_password = getpass.getpass("Password should have at least one lower case character, try again: ")
        continue
        #return False

      password_has_uppercase = False

      for char in new_password:
        if char in ascii_uppercase:
          password_has_uppercase = True
          break

      if not password_has_uppercase:
        new_password = getpass.getpass("Password should have at least one upper case character, try again: ")
        continue
        #return False

      return True

#Encrypt user password using bcrypt
import bcrypt
def encrypt_pass(password):

    password = password.encode("ascii") #encode the password using base64 encoding
    hashed = bcrypt.hashpw(password, bcrypt.gensalt()) #add hash to the password
    #print("Password successfully encrypted as " + str(hashed))

    return hashed

def not_robot():
  from captcha.image import ImageCaptcha
  # Create an image instance of the given size
  image = ImageCaptcha(width = 280, height = 90)
  # Image captcha text
  captcha_text = 'LCYS_PCOM7E'
  # generate the image of the given text
  data = image.generate(captcha_text)
  # write the image on the given file and save it, the image can then be inserted onto the web login page
  image.write(captcha_text, 'captch.png')

  #Prompt the user to insert the CAPTCHA text
  user_input = input("Enter the text in the captcha image: ")

  #user can only login after providing the CAPTCHA text correctly
  if user_input == captcha_text:
      print("Corrrect! ")
      return True
  else:
    print("Incorrect, try again!")
    return False

#The function if for anbling Multi-Fcator Authentication(MFA) through use if time-based one-time password
#import pyotp
#REF: https://pyauth.github.io/pyotp/

def genOTP():
  totp = pyotp.TOTP('base32secret3234')
  user_otp = totp.now()
  print("Your OTP is:", user_otp)
  return user_otp

def validate_otp(user_otp):
  sys_otp = genOTP()
  if user_otp == sys_otp:
    return True
  else:
    return False

#REF: https://codereview.stackexchange.com/questions/153079/asking-the-user-to-input-a-proper-email-address
#The function is just a helper for defining structure of an email address

def check_email_contains(email_address, characters, min_length=6):
    
    while True: #The loops iterates for as long as the conditions for the email address structure are not met
        for character in characters:
            if character not in email_address:
                email_address = input("Your email address must have '{}' in it\nPlease write your email address again: ".format(character))
                continue
        if len(email_address) <= min_length:
            email_address = input("Your email address is too short\nPlease write your email address again: ")
            continue
        return email_address


def check_phone_number(phone_number, min_length=8):

  while True:
    for digits in phone_number:
      if  digits.isnumeric() == False:
        phone_number = input("Phone number should only use numeric values, re-enter Phone Number: ")
        break
      if len(phone_number) < 8:
        phone_number = input("Phone number should contain at least 8 numerals, re-enter the Phone Number: ")
        break
    return phone_number


#REF: https://www.codegrepper.com/code-examples/python/how+to+check+if+user+input+is+a+special+character+in+python
#Function to check special characters as part of input sanitization
import re #use regular expression  library for improved and simplified coding 
def check_special_characters(str_input):
  
  regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]') 

  while True:
    if (regex.search(str_input) == None):
      #has_spec = False
      return str_input
      break
    else:
      #has_pec = True
      str_input = input("Should not contain special characters, enter again: ")
      continue


#Create a connection function to be reused across the other functions
def create_connection(db_file):
    
    sqliteConnection = None
    try:
        sqliteConnection = sqlite3.connect(db_file) # Open connection
        return sqliteConnection
    except Error as e:
        print(e)

    return sqliteConnection

#Function to validate data input
from datetime import datetime
def get_dob(birthday):

    format = "%d/%m/%Y"
    #correct_format = True
    while True:
      try:
        birth_date = datetime.strptime(birthday, format)
        return birth_date
        break
      except ValueError:
        birthday = input('Enter your birthday in dd/mm/yyyy format: ')
        continue
        #correct_format = False

#Function for creating a new user account
import getpass
import string
import secrets
import sqlite3

def create_account():

  enc_pass = "" #encrypted password

  #First get all the details of the user. They will self-register on the public facing ASMIS portal
  name = input("Enter First Name: ")
  surname = check_special_characters(input("Enter Last Name: "))
  gender = check_special_characters(input("Enter gender: "))
  date_of_birth = get_dob(input("Enter D.O.B: "))
  city = check_special_characters(input("Enter City: "))
  email = check_email_contains(input("Enter email addres: "), "@.")
  phone_number = check_phone_number(input("Enter your phone number: "))
  username = check_special_characters(input("Enter username: "))
  password = getpass.getpass("Enter Password: ")

  #Create connection to the database so that the newly input user data can then be kept securely in the Database
  conn = create_connection("asmis.db")
  cursor = conn.cursor()
  
  #First test to find if the users table exist, if not then create new table
  user_table = cursor.execute(''' SELECT name FROM sqlite_master WHERE type='table' AND name='users' ''').fetchall()
  if user_table == []:
      #create new table
      cursor.execute("CREATE TABLE users (name VARCHAR(25),surname VARCHAR(25), gender VARCHAR(10), dob DATE, city VARCHAR(20), email VARCHAR(25), phone_number VARCHAR(20), username VARCHAR(25), enc_pass TEXT)")
  
  conn.commit()
  #Ensure the fields are nont empty
  if username =="" or password =="":
    print("Username or password can not be empty!")
    return
  
  #Read all users in the database and check the existance of the username. There should be distinct usernames in the database
  users = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()
  if users:
    print("Username already exist!")  

  #If the username and passwords are not empty and the username does not exist yet, then proceed to validate the password and insert the user into the users table in the DB
  else:
    if pass_validator(password): #Validate Password against the set password requirements
      enc_pass = encrypt_pass(password) #If valid, encrypt the password for secure storage of the credentials
      insert_users(name, surname, gender, str(date_of_birth), city, email, phone_number, username, enc_pass) #Insert the user details into the DB
      #print("Account created successfully."+ str(enc_pass))
    else:
      print("Password invalid!") # If password requirements not met, the creation of user fails
      #print(enc_password)

  return name, surname, gender, date_of_birth, city, email, phone_number, username, enc_pass


#REF: https://pynative.com/python-sqlite-insert-into-table/
#This is a helper function for inserting the newlcy created users into the DB

import sqlite3
def insert_users(name, surname, gender,date_of_birth, city, email, phone_number, username, enc_pass):
  
  try:
    conn = create_connection("asmis.db")
    cursor = conn.cursor()
    #print("Successfully Connected to SQLite")

    #Once connected to the DB, insert the details into the users table. The paramenters other than the enc_pass parameter are captured from user input on the portal
    cursor.execute("""INSERT INTO users
                          (name, surname, gender, dob, city, email, phone_number, username, enc_pass) 
                           VALUES (?,?,?,?,?,?,?,?,?)
                           """, (name, surname, gender, date_of_birth, city, email, phone_number, username, enc_pass))

    #count = cursor.execute(sqlite_insert_query)
    conn.commit()
    print("Record inserted successfully into users table ")
    cursor.close()

  except sqlite3.Error as error: #If any errors encoutered, the insertion fails
      print("Failed to insert data into sqlite table", error)
  finally:
      if conn:
          conn.close()
          print("The SQLite connection is closed")


#Helper method for searching all records in the DB
def search_db():
  
  conn = create_connection("asmis.db")
  cursor = conn.cursor()

  #Once connection to the DB opened, we can list all stored data, each on a new line
  print('\nAll Users:')
  data = cursor.execute('''SELECT * FROM users''')
  for row in data:
      print(row)


#Helper function for exttracting login details from the Database. User name and the encrypted password(hashed) are used as a challenge for login

def login_check(username, user_password):

  #Encode the authenticating password as well 
  
  conn = create_connection("asmis.db")
  cursor = conn.cursor()

  hashed = ""
  
  users = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall() #Get all users macthing the input username(will always be one record since no two users can have same username)
  #print(users)

  if users:
    hashed = users[0][8] #A record macthing the user will always be at index 0  from the output list and then the corresponding encrypted pasword is static at index 8 for all records
    user_password = user_password.encode("ascii") #Always encode the string values so that they can be compared with hashed value on the bcrypt function
    #print(hashed)
    
    #Use conditions to compare the authenticating password with the stored one:
    if bcrypt.checkpw(user_password, hashed): #Compare the user input password with the stored encrypted password
        #print("Login success!")
        return True
    else:
        #print("Incorrect password")
        return False
  else:
      print("No such user in the database") #When no username matches user input, no further executions done


#Function evoked when a user attempts login to the platform
def user_login():
  
  #can be send via email, sms, authenticator etc
  sys_otp = genOTP() #Call the function defined for generating the OTP

  username = input("Enter username: ")
  password = getpass.getpass("Enter Password: ") #Hide input password behind the dots
  password_success = login_check(username, password) # Call the login helper function to check whether the input username and password match

  #users can only login when they have provided  correct username and passwords and then the OTP. The final step is that of CAPTCHA to ensure is is not an automated login(Robot)
  if password_success:
    user_otp = input("Enter the otp: ")
    not_a_robot = not_robot()
    if sys_otp == user_otp and not_a_robot:
      print("Logged in Successfully!")
      return True
    else:
      print("Failed Login")
    return False
  else:
    print("Invalid login details")



