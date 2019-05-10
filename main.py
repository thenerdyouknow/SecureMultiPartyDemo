#Imports for all the packages
import os
import re
import argon2
import socket
import functools
import random
import motor.motor_tornado
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
from tornado.options import define, options
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from urllib.parse import urlparse
from Crypto.Cipher import AES  # http://pycrypto.org
from pymongo import MongoClient

#Setting options for the server
define("port", default=8100, help="run on the given port", type=int)

NUMBER_OF_SERVERS = 3
PORT = 8105

def generating_AES_keys():
	key = os.urandom(16)
	IV = os.urandom(16)
	with open('AES.txt', 'wb') as open_file:
		open_file.write(key)
		open_file.write('\n'.encode())
		open_file.write(IV)


def check_username(username):
	if (re.fullmatch('^(?=.{8,20}$)(?![_.])(?!.*[_.]{2})[a-zA-Z0-9._]+(?<![_.])$', username) == None):
		return 0
	else:
		return 1
	#Found at :https://stackoverflow.com/questions/12018245/regular-expression-to-validate-username

def check_email(email):
	if (re.fullmatch(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', email) == None):
		return 0
	else:
		return 1 
	#Rudimentary Regex, will need to be updated to be simpler and email validation by sending an email will have to be done

class BaseHandler(tornado.web.RequestHandler):
	""" BaseHandler():
	Class that'll be used later when @tornado.web.authenticated is needed for POST requests.
	"""
	def get_current_user(self):
		user_cookie = self.get_secure_cookie("user")
		if user_cookie is None:
			self.clear_all_cookies(path="/")
		return user_cookie

def protected(method):
	""" protected():
	Protected decorator which invokes the authenticated decorator, and then also prevents browsers from caching the pages
	so that the user can't press back after logging out and access login-protected pages by setting header settings.
	"""
	@tornado.web.authenticated
	@functools.wraps(method)
	def wrapper(self, *args, **kwargs):
		self.set_header('Cache-Control', 'no-cache, no-store, must-revalidate')
		self.set_header('Pragma', 'no-cache')
		self.set_header('Expires', '0')
		return method(self, *args, **kwargs)
	return wrapper

def if_poll_created(method):
	
	@tornado.web.authenticated
	@functools.wraps(method)
	def wrapper(self, *args, **kwargs):
		if self.get_secure_cookie("poll_data") is None:
			self.redirect("/postlogin")
		return method(self,*args,**kwargs)
	return wrapper

def if_already_logged_in(method):
	""" if_already_logged_in():
	Decorator that checks if the user is already logged in, if they are then it just redirects to /postlogin immediately. 
	this is important functionality for the buttons on the index page.
	"""
	@functools.wraps(method)
	def  wrapper(self, *args, **kwargs):
		if self.get_secure_cookie("user"):
			self.redirect("/postlogin")
		return method(self,*args,**kwargs)
	return wrapper

class ErrorHandler(tornado.web.ErrorHandler):
	"""
	Default handler gonna to be used in case of 404 error
	"""
	def write_error(self, status_code, **kwargs):
		if status_code in [403, 404, 500, 503]:
			self.redirect("/")


class IndexHandler(tornado.web.RequestHandler):
	""" IndexHandler():
	Class that handles /
	"""
	def get(self):
		self.render('index.html')


class SignUpHandler(tornado.web.RequestHandler):
	""" SignUpHandler():
	Class that handles /signup
	"""
	@if_already_logged_in
	def get(self):
		"""	get():
		Renders the Sign Up page when the user arrives at /signup. 
		If the user is already logged in and tries to sign up, then it just immediately redirects to /postlogin instead.
		"""
		self.render('signup.html',error='')
		return
	
	def check_if_exists(self):
		""" check_if_exists():
		Uses the pymongo driver(so everything is synchronous) to check if the username exists in database
		then checks if the email address also exists in the database
		depending on conditions, returns None or the error message to be displayed.
		"""
		error = None
		document_username = sync_db.users.find_one({'username':self.username})
		if (document_username!=None):
			error = "Username exists already"
		document_email = sync_db.users.find_one({'email':self.email})
		if (document_email!=None):
			error = "Email exists already"
		return error

	async def do_insert(self,hashed_password):
		""" do_insert():
		Forms a document of the username, the email, and the hashed password
		and using the Motor driver(asynchronously) inserts the document into database.
		"""
		document = {'username': self.username,'email': self.email,'password': hashed_password}
		result = await async_db.users.insert_one(document)

	def hash_password(self):
		""" hash_password():
		Initializes an instance of argon2.PasswordHasher from argon2, hashes the password,
		verifies if the hashing happened properly, raises error if the verification failed,
		and then returns hashed password if verifications passes.
		"""
		ph = argon2.PasswordHasher()
		hashed_password = ph.hash(self.password)
		try:
			ph.verify(hashed_password,self.password)
		except argon2.exceptions.VerifyMismatchError:
			raise
		return hashed_password

	async def post(self):
		""" post():
		Sets class variables, does rudimentary checks on username and email submitted using regex
		and renders signup.html with the error if the regex fails to match the submitted value.
		Then checks if the submitted username and email already exist in database by calling check_if_exists 
		if check_if_exists returns not None then renders signup.html with the error. 
		After confirming that no errors have occured, hashes the password and then inserts it into the
		MongoDB database by calling hash_password() and do_insert() respectively.
		Finally, sets the secure cookie and logs in the user.
		"""
		self.username = self.get_argument("username").lower()
		self.email = self.get_argument("email").lower()
		self.password = self.get_argument("psword").lower()

		if (check_username(self.username)==0): #Found at :https://stackoverflow.com/questions/12018245/regular-expression-to-validate-username
			self.render("signup.html",error="Your username doesn't follow our username rules. Please fix it.")
			return
		elif (check_email(self.email)==0): #Rudimentary Regex, will need to be updated to be simpler and email validation by sending an email will have to be done
			self.render("signup.html",error="Your email doesn't look like a valid email")
			return

		does_it_exist = self.check_if_exists()
		if(does_it_exist!=None):
			self.render("signup.html",error=does_it_exist)
			return

		hashed_password = self.hash_password()
		await self.do_insert(hashed_password)

		self.set_secure_cookie("user", self.username)
		# self.set_secure_cookie("tnc", "1")
		self.redirect('/postlogin')
		return

class SignInHandler(tornado.web.RequestHandler):
	""" SignInHandler():
	Class that handles /signin
	"""
	@if_already_logged_in
	def get(self):
		""" get():
		Renders the Sign In page when the user arrives at /signin.
		If a user is already logged in, automatically takes the user to /postlogin instead of letting them sign in again.
		"""
		self.render('signin.html',error='')
		return

	def check_database(self):
		""" check_database():
		Creates an instance of argon2.PasswordHasher, finds if there is any document in the database with the 
		username submitted, verifies the password with the hashed password inside the database if the 
		document exists, returns None or the error message.
		"""
		ph = argon2.PasswordHasher()
		error = None
		document_username = sync_db.users.find_one({'username':self.username})
		if(document_username == None):
			error = "User doesn't exist. Please sign up first!"
		else:
			try:
				ph.verify(document_username['password'],self.password)
			except argon2.exceptions.VerifyMismatchError:
				error = "Password is wrong, try again!"
		return error			

	def post(self):
		""" post():
		Sets the class variables and checks the database to verify if the credentials exist and
		are valid, renders the Sign In page with the error if they don't.
		Finally, sets the secure cookie and redirects to /postlogin.
		"""
		self.username = self.get_argument("username").lower()
		self.password = self.get_argument("psword").lower()

		check_details = self.check_database()
		if(check_details!=None):
			self.render('signin.html',error=check_details)
			return

		self.set_secure_cookie("user", self.username)
		# self.set_secure_cookie("tnc", "1")
		self.redirect('/postlogin')
		return

class PostLoginHandler(BaseHandler):
	""" PostLoginHandler():
	Class that handles /postlogin
	"""
	@protected
	def get(self):
		""" get():
		Renders the postlogin page, uses the decorator to make sure the user is logged in first.
		"""
		self.render('postlogin.html',error='')
		return

class CreatePollHandler(BaseHandler):
	""" CreatePollHandler():
	Class that handles /createpoll
	"""
	@protected
	def get(self):
		""" get():
		Renders the createpoll page. uses the decorator to make sure the user is logged in first.
		"""
		self.render('createpoll.html',error='')
		return

	async def add_to_database(self,collection,title,question,choices,username):
		""" add_to_database():
		Creates a document of the question and the choices, and then asynchronously inserts the document into the
		MongoDB database.
		"""
		document = {'username': username,'title':title,'question': question,'choices': choices}
		_id = await collection.insert_one(document)
		return _id

	def check_validity(self,participants):
		participant_list = participants.split(",")

		if(len(participant_list) == 1):
			participant_list_new = participants.split(" ")
			if(len(participant_list_new) > 1):
				return 'Looks like you forgot about the commas to seperate them, please rectify!'

		for participant in participant_list:
			participant = participant.strip()
			if(check_email(participant)==0):
				return 'Participant '+ participant +' looks like an invalid email! Please rectify!'
		return None

	def get_IP_address(self):

		hostname = urlparse("%s://%s"
		% (self.request.protocol, self.request.host)).hostname

		ip_address = socket.gethostbyname(hostname)

		return ip_address

	def read_AES_keys(self):
		AES_keys = []
		with open('AES.txt','rb') as open_file:
			file_contents = open_file.read()
			AES_keys = file_contents.splitlines()
		key = AES_keys[0]
		iv = AES_keys[1]
		return key, iv

	def decrypt_link(self,string_to_decrypt):

		key, iv = self.read_AES_keys()
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())

		decryptor = cipher.decryptor()
		string_to_decrypt = bytes.fromhex(string_to_decrypt)

		padded_plaintext = decryptor.update(string_to_decrypt) + decryptor.finalize()

		unpadder = padding.PKCS7(128).unpadder()
		plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

		return plaintext


	def encrypt_link(self,string_to_encrypt):

		key, iv = self.read_AES_keys()
		padder = padding.PKCS7(128).padder()

		padded_data = padder.update(bytes(string_to_encrypt.encode())) + padder.finalize()
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())

		encryptor = cipher.encryptor()

		ciphertext = encryptor.update(padded_data) + encryptor.finalize()
		
		return ciphertext.hex()


	def generating_user_links(self,participants,poll_id):

		unique_link_doc = []
		participant_list = participants.split(",")
		number_of_participants = len(participant_list)

		ip_address = self.get_IP_address()

		for i in range(1,number_of_participants+1):

			initial_unique_poll_link = str(ip_address) + ":"+ str(options.port)+"/get_poll/?"
			part_to_be_encrypted = "poll_id="+str(poll_id.inserted_id) +"&participant_number="+str(i)

			encrypted_link = self.encrypt_link(part_to_be_encrypted)
			final_unique_poll_link = initial_unique_poll_link + encrypted_link

			unique_link_doc.append(final_unique_poll_link)

		return unique_link_doc

	@protected
	async def post(self):
		""" post():
		Gets the poll question and the choices added by the user as a list, decodes the username of the user from the secure cookie,
		and then asynchronously adds the poll created to the collection of user polls, which is named after the user. Then redirects 
		to postlogin.
		"""
		title = self.get_argument("title")
		question = self.get_argument("question")
		choices = self.get_arguments("choice")
		participants = self.get_argument("participants")
		username = self.get_secure_cookie("user").decode('ascii')

		validation_error = self.check_validity(participants)

		if(validation_error != None):
			self.render('createpoll.html',error=validation_error)
			return

		user_collection = async_db.polls
		insert_id = await self.add_to_database(user_collection,title,question,choices,username)

		all_links = self.generating_user_links(participants,insert_id)

		sync_db.polls.update_one({"_id":insert_id.inserted_id}, {'$push': {'participant_links': {"$each": all_links}}})

		self.set_secure_cookie("poll_data",str(insert_id.inserted_id))

		self.redirect("/uniquepollid")

class PollIdHandler(BaseHandler):

	@protected
	@if_poll_created
	def get(self):
		
		return

class ExistingPollsHandler(BaseHandler):
	""" ExistingPollsHandler():
	Class that handles /existingpolls
	"""

	def get_user_polls(self,user):
		result = sync_db.polls.find({"username":user})
		return result

	@protected
	def get(self):
		""" get():
		Renders the existingpolls page. uses the decorator to make sure the user is logged in first.
		"""
		username = self.get_secure_cookie("user").decode('ascii')
		all_polls = self.get_user_polls(username)

		self.render('existingpolls.html',all_the_polls=all_polls,error='')
		return


class LogoutHandler(tornado.web.RequestHandler):
	""" LogoutHandler():
	Class that handles /logout
	"""
	def get(self):
		""" get():
		Cleans out the secure cookie. Also redirects to home page.
		"""
		self.clear_all_cookies(path="/")
		self.redirect("/")

# ---------------------MODULES BEGIN---------------------

class CDNIncludesModule(tornado.web.UIModule):
	""" CDNIncludesModule():
	Class that has the CDN includes statements which are included in every page,
	except it's easier when it's made into a module.
	"""
	def render(self):
		""" render():
		Renders the module as a HTML string.
		"""
		return self.render_string('modules/CDN_includes.html')

class NavbarModule(tornado.web.UIModule):
	""" NavbarModule():
	Class that has the Navbar code, put into a module for easier integration.
	"""
	def render(self):
		""" render():
		Renders the navbar code as an HTML string.
		"""
		return self.render_string('modules/navbar.html')

# ---------------------MODULES END---------------------

def recieve_public_keys(port):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error as err:
		raise err

	sock.bind(('',port))

	sock.listen(5)

	counter = 0
	while True:
		connection,address = sock.accept()

		connection.send('Send public key!'.encode())

		file_size, file_name = (connection.recv(1024)).decode().split(",")
		
		int_filesize = int(file_size)
		file_to_write_to = open('public_keys/'+file_name,'wb')

		while int_filesize>0:
			temp_data = connection.recv(1024)
			file_to_write_to.write(temp_data)
			int_filesize -= len(temp_data)

		file_to_write_to.close()
		connection.close()
		counter += 1

		if(counter == NUMBER_OF_SERVERS):
			break

	sock.close()


#---------------------MAIN BEGINS---------------------
if __name__ == '__main__':
	tornado.options.parse_command_line() 
	settings = {
		"cookie_secret": "j84i6ykTfmew9As25eYqAbs5KIhrUv/gmp801s9zRo=",
		"xsrf_cookies":True, 
		"login_url": "/index",
		"default_handler_class": ErrorHandler, #Error Handler in case of 404s
		"default_handler_args": dict(status_code=404) #Argument that needs to be passed if 404 page is hit
	}
	async_db = motor.motor_tornado.MotorClient().example #Asynchronous DB driver  
	sync_db = MongoClient().example 					 #Synchronous DB driver

	public_keys = os.listdir('public_keys')
	if(len(public_keys)<NUMBER_OF_SERVERS):
		recieve_public_keys(PORT)

	# generating_AES_keys()

	application = tornado.web.Application(
		handlers = [
			(r'/',IndexHandler),
			(r'/signup', SignUpHandler),
			(r'/signin', SignInHandler),
			(r'/postlogin',PostLoginHandler),
			(r'/createpoll',CreatePollHandler),
			(r'/uniquepollid',PollIdHandler),
			(r'/existingpolls',ExistingPollsHandler),
			(r'/logout', LogoutHandler)
		],
		template_path = os.path.join(os.path.dirname(__file__),"templates"),
		static_path = os.path.join(os.path.dirname(__file__),"static"),
		ui_modules={'cdn_includes': CDNIncludesModule, 'navbar':NavbarModule},
		debug = True,
		async_db = async_db,
		sync_db = sync_db,

		**settings
	)
	http_server = tornado.httpserver.HTTPServer(application)
	http_server.listen(options.port)
	tornado.ioloop.IOLoop.instance().start()

#---------------------MAIN ENDS---------------------