#Imports for all the packages
import os
import re
import argon2
import socket
import functools
import copy
import random
import smtplib
import motor.motor_tornado
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
from bson import ObjectId
from tornado.options import define, options
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from urllib.parse import urlparse
from Crypto.Cipher import AES  # http://pycrypto.org
from pymongo import MongoClient

#Setting options for the server
define("port", default=8100, help="run on the given port", type=int)

NUMBER_OF_SERVERS = 3
SERVER_IPS = ['127.0.0.1','127.0.0.1','127.0.0.1']
SERVER_PORTS = [9000,9001,9002]
PORT = 8105
PUBLIC_KEYS = ['public_keys/public_key_1.pem','public_keys/public_key_2.pem','public_keys/public_key_3.pem']

def generating_AES_keys():
	key = os.urandom(16)
	IV = os.urandom(16)
	with open('AES.txt', 'wb') as open_file:
		open_file.write(key)
		open_file.write('\n'.encode())
		open_file.write(IV)

def read_AES_keys():
	AES_keys = []
	with open('AES.txt','rb') as open_file:
		file_contents = open_file.read()
		AES_keys = file_contents.splitlines()
	key = AES_keys[0]
	iv = AES_keys[1]
	return key, iv

def check_username(username):
	if (re.fullmatch('^(?=.{8,20}$)(?![_.])(?!.*[_.]{2})[a-zA-Z0-9._]+(?<![_.])$', username) is None):
		return 0
	else:
		return 1
	#Found at :https://stackoverflow.com/questions/12018245/regular-expression-to-validate-username

def check_email(email):
	if (re.fullmatch(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', email) is None):
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
		if (document_username is not None):
			error = "Username exists already"
		document_email = sync_db.users.find_one({'email':self.email})
		if (document_email is not None):
			error = "Email exists already"
		return error

	async def do_insert(self,collection,hashed_password):
		""" do_insert():
		Forms a document of the username, the email, and the hashed password
		and using the Motor driver(asynchronously) inserts the document into database.
		"""
		document = {'username': self.username,'email': self.email,'password': hashed_password}
		result = await collection.insert_one(document)

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
		if(does_it_exist is not None):
			self.render("signup.html",error=does_it_exist)
			return
		hashed_password = self.hash_password()
		user_collection = async_db.users
		await self.do_insert(user_collection, hashed_password)
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

	def check_database(self,collection):
		""" check_database():
		Creates an instance of argon2.PasswordHasher, finds if there is any document in the database with the 
		username submitted, verifies the password with the hashed password inside the database if the 
		document exists, returns None or the error message.
		"""
		ph = argon2.PasswordHasher()
		error = None
		document_username = collection.find_one({'username':self.username})
		if(document_username is None):
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
		user_collection = sync_db.users
		check_details = self.check_database(user_collection)
		if(check_details is not None):
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

	def check_validity(self,participant_list):
		for participant in participant_list:
			if(check_email(participant)==0):
				return 'Participant '+ participant +' looks like an invalid email! Please rectify!'
		return None

	def get_IP_address(self):
		hostname = urlparse("%s://%s"
		% (self.request.protocol, self.request.host)).hostname
		ip_address = socket.gethostbyname(hostname)
		return ip_address

	def encrypt_link(self,string_to_encrypt):
		key, iv = read_AES_keys()
		padder = padding.PKCS7(128).padder()
		padded_data = padder.update(bytes(string_to_encrypt.encode())) + padder.finalize()
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
		encryptor = cipher.encryptor()
		ciphertext = encryptor.update(padded_data) + encryptor.finalize()
		return ciphertext.hex()


	def generating_user_links(self,participant_list,poll_id):
		unique_link_doc = []
		number_of_participants = len(participant_list)
		ip_address = self.get_IP_address()
		for i in range(1,number_of_participants+1):
			participant_dict = {}
			initial_unique_poll_link = str(ip_address) + ":"+ str(options.port)+"/get_poll/"
			part_to_be_encrypted = "poll_id="+str(poll_id.inserted_id) +"&participant_email="+str(participant_list[i-1])
			encrypted_link = self.encrypt_link(part_to_be_encrypted)
			final_unique_poll_link = initial_unique_poll_link + encrypted_link

			participant_dict["poll_id"] = poll_id.inserted_id
			participant_dict["email"] = participant_list[i-1]
			participant_dict["link"] = final_unique_poll_link
			participant_dict["vote_flag"] = 0
			unique_link_doc.append(participant_dict)
		return unique_link_doc

	#Taken and modified from Rosetta Code
	def send_email(self,server,from_address, to_address, subject, message):
		header  = 'From: %s\n' % from_address
		header += 'To: %s\n' % to_address
		header += 'Subject: %s\n\n' % subject
		message = header + message
		problems = server.sendmail(from_address, to_address, message)
		#For some reason doesn't actually return invalid addresses which you can't mail.
		return problems


	def send_participant_emails(self,links,smtpserver='smtp.gmail.com:587'):
		unsuccessful_emails = []
		login = 'pollingapplication42'
		password = 'doloripsum'
		server = smtplib.SMTP(smtpserver)
		server.starttls()
		server.login(login,password)
		for each_link in links:
			subject = 'Invitation to Vote on Poll'
			message = 'Your link to vote on the poll is : ' + each_link['link']
			status = self.send_email( server, 'Polling Application' ,each_link['email'],subject,message)
			#TODO : Figure out how to get the invalid addresses back so you can alert the user email wasn't sent to them
		server.quit()
		return 

	def preprocessing(self,participants):
		participant_list = participants.split(",")
		if(len(participant_list) == 1):
			participant_list_new = participants.split(" ")
			if(len(participant_list_new) > 1):
				return None
		no_space_participants = [x.strip() for x in participant_list]
		return no_space_participants

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
		participant_list = self.preprocessing(participants) 
		if participant_list is None:
			self.render('createpoll.html',error='Participant e-mails filled incorrectly! Please rectify!')
			return
		validation_error = self.check_validity(participant_list)
		if(validation_error is not None):
			self.render('createpoll.html',error=validation_error)
			return
		choice_dict = {}
		for i in range(len(choices)):
			choice_dict[str(i)] = choices[i]
		user_collection = async_db.polls
		insert_id = await self.add_to_database(user_collection,title,question,choice_dict,username)
		all_links = self.generating_user_links(participant_list,insert_id)
		emails_not_sent = self.send_participant_emails(all_links)
		for each_link in all_links:
			sync_db.links.insert_one(each_link)

		# sync_db.polls.update_one({"_id":insert_id.inserted_id}, {'$push': {'participant_links': {"$each": all_links}}})
		self.set_secure_cookie("poll_data",str(insert_id.inserted_id))
		self.redirect("/uniquepollid")

class ServePollHandler(tornado.web.RequestHandler):

	def decrypt_AES(self,string_to_decrypt):
		key, iv = read_AES_keys()
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
		decryptor = cipher.decryptor()
		try:
			string_to_decrypt = bytes.fromhex(string_to_decrypt)
			padded_plaintext = decryptor.update(string_to_decrypt) + decryptor.finalize()
		except ValueError:
			return None
		unpadder = padding.PKCS7(128).unpadder()
		plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
		return plaintext

	def check_and_decrypt(self,string_to_check):
		try:
			decrypted_plaintext = self.decrypt_AES(string_to_check)
			if(decrypted_plaintext is None):
				return None
			decrypted_list = decrypted_plaintext.decode().split("&")
		except UnicodeDecodeError:
			return None
		#Additional check to make sure even if some fake ciphertext does get decrypted, it should split in exactly two pieces or else it'll 
		#be rejected.
		if(len(decrypted_list)!=2):
			return None
		return decrypted_list

	def get_poll(self,link_collection,poll_collection,poll_id,participant_email):
		result = link_collection.find_one({'poll_id':ObjectId(poll_id), 'email':participant_email})
		if result is not None:
			if result['vote_flag'] == 1:
				return 1
			poll = poll_collection.find_one({'_id':ObjectId(poll_id)})
			return poll
		return result


	def collect_public_keys(self,filename_list):
		all_keys = []
		for each_file in filename_list:
			with open(each_file, "rb") as key_file:
				public_key = serialization.load_pem_public_key(
					key_file.read(),
					backend=default_backend()
					)
				pem = public_key.public_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PublicFormat.SubjectPublicKeyInfo
					)
				pem = pem.decode()
				pem = pem.replace('\n','')
				all_keys.append(pem);
		return all_keys

	def get(self,poll_link):
		decrypted_list = self.check_and_decrypt(poll_link)
		if(decrypted_list is None):
			self.render('404.html')
			return
		poll_id = decrypted_list[0].split("=")[1]
		participant_email = decrypted_list[1].split("=")[1]
		link_collection = sync_db.links
		poll_collection = sync_db.polls
		poll_document = self.get_poll(link_collection,poll_collection,poll_id,participant_email)
		if(poll_document is None):
			self.render('404.html')
			return
		elif(poll_document == 1):
			self.write("You seem to have already voted! Please reach out to the admin if this is not the case so they can reset your vote!")
			return
		public_keys = self.collect_public_keys(PUBLIC_KEYS)
		self.render('viewpoll.html',title=poll_document['title'],question=poll_document['question'],choices=poll_document['choices'],public_keys=public_keys,error='')
		return

	def invalidate_link(self,collection,poll_id,participant_email):
		result = collection.update_one({ "poll_id": ObjectId(poll_id), "email": participant_email}, { "$inc" : {"vote_flag":1}})
		return result

	def send_shares_to_servers(server_ips, server_ports, shares):
		for i in range(0,len(shares)):
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
				s.send('Sending share!'.encode())
				time.sleep(1)
				s.connect((server_ips[i], server_ports[i]))
				s.sendall(shares[i].encode())
				print('Done sending share',i)

	def post(self,poll_link):
		encrypted_shares = self.get_argument("choice") #Gets the first input with that name
		share_list = encrypted_shares.split(",")
		decrypted_list = self.check_and_decrypt(poll_link)
		poll_id = decrypted_list[0].split("=")[1]
		participant_email = decrypted_list[1].split("=")[1]
		if(decrypted_list is None):
			self.render('404.html')
			return
		user_collection = sync_db.links
		result = self.invalidate_link(user_collection,poll_id,participant_email)
		if(result is None):
			self.render('wentwrong.html')
			return
		for each_share in share_list:
			each_share = poll_id + "," + each_share
		self.send_shares_to_servers(SERVER_IPS,SERVER_PORTS,share_list)
		# prepared_string = 
		# print(share_list)

class ExistingPollsHandler(BaseHandler):
	""" ExistingPollsHandler():
	Class that handles /existingpolls
	"""

	def get_user_polls(self,collection,user):
		result = collection.find({"username":user})
		return result

	@protected
	def get(self):
		""" get():
		Renders the existingpolls page. uses the decorator to make sure the user is logged in first.
		"""
		username = self.get_secure_cookie("user").decode('ascii')
		poll_collection = sync_db.polls
		all_polls = self.get_user_polls(poll_collection,username)
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
			(r'/existingpolls',ExistingPollsHandler),
			(r'/logout', LogoutHandler),
			(r'/get_poll/(\w+)', ServePollHandler),
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