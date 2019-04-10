#Imports for all the packages
import os.path
import re
import motor.motor_tornado
from argon2 import PasswordHasher
from pymongo import MongoClient
import random
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import pymongo
from tornado.options import define, options

#Setting options for the server
define("port", default=8100, help="run on the given port", type=int)

""" BaseHandler():
Class that'll be used later when @tornado.web.authenticated is needed for POST requests.
"""

class BaseHandler(tornado.web.RequestHandler):
	def get_current_user(self):
		return self.get_secure_cookie("user")

""" SignUpHandler():
Class that handles /signup
"""

class SignUpHandler(tornado.web.RequestHandler):
	"""	get():
	Renders the Sign Up page when the user arrives at /signup. 
	"""
	def get(self):
		self.render('signup.html',error='')
	
	""" check_if_exists():
	Uses the pymongo driver(so everything is synchronous) to check if the username exists in database
	then checks if the email address also exists in the database
	depending on conditions, returns None or the error message to be displayed.
	"""
	def check_if_exists(self):
		error = None
		document_username = sync_db.users.find_one({'username':self.username})
		if (document_username!=None):
			error = "Username exists already"
		document_email = sync_db.users.find_one({'email':self.email})
		if (document_email!=None):
			error = "Email exists already"
		return error

	""" do_insert():
	Forms a document of the username, the email, and the hashed password
	and using the Motor driver(asynchronously) inserts the document into database.
	"""
	async def do_insert(self,hashed_password):
		document = {'username': self.username,'email': self.email,'password': hashed_password}
		result = await async_db.users.insert_one(document)

	""" hash_password():
	Initializes an instance of PasswordHasher from argon2, hashes the password,
	verifies if the hashing happened properly, re-hashes if the verification failed,
	and then returns hashed password.
	"""
	def hash_password(self):
		ph = PasswordHasher()
		hashed_password = ph.hash(self.password)
		try:
			ph.verify(hashed_password,self.password)
		except VerifyMismatchError:
			hashed_password = ph.hash(self.password)
		return hashed_password

	""" post():
	Sets class variables, does rudimentary checks on username and email submitted using regex
	and renders signup.html with the error if the regex fails to match the submitted value.
	Then checks if the submitted username and email already exist in database by calling check_if_exists 
	if check_if_exists returns not None then renders signup.html with the error. 
	After confirming that no errors have occured, hashes the password and then inserts it into the
	MongoDB database by calling hash_password() and do_insert() respectively.
	Finally, sets the secure cookie and logs in the user.
	"""
	async def post(self):
		self.username = self.get_argument("username").lower()
		self.email = self.get_argument("email").lower()
		self.password = self.get_argument("psword").lower()

		if (re.fullmatch('^(?=.{8,20}$)(?![_.])(?!.*[_.]{2})[a-zA-Z0-9._]+(?<![_.])$', self.username) == None): #Found at :https://stackoverflow.com/questions/12018245/regular-expression-to-validate-username
			self.render("signup.html",error="Your username doesn't follow our username rules. Please fix it.")
			return
		elif (re.fullmatch(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', self.email) == None): #Rudimentary Regex, will need to be updated to be simpler and email validation by sending an email will have to be done
			self.render("signup.html",error="Your email doesn't look like a valid email")
			return

		does_it_exist = self.check_if_exists()
		if(does_it_exist!=None):
			self.render("signup.html",error=does_it_exist)
			return

		hashed_password = self.hash_password()
		await self.do_insert(hashed_password)

		self.set_secure_cookie("user", self.username)
		self.redirect('/postlogin')
		return

""" SignInHandler():
Class that handles /signin
"""

class SignInHandler(tornado.web.RequestHandler):
	""" get():
	Renders the Sign In page when the user arrives at /signin
	"""
	def get(self):
		self.render('signin.html',error='')

	""" check_database():
	Creates an instance of PasswordHasher, finds if there is any document in the database with the 
	username submitted, verifies the password with the hashed password inside the database if the 
	document exists, returns None or the error message.
	"""
	def check_database(self):
		ph = PasswordHasher()
		error = None
		document_username = sync_db.users.find_one({'username':self.username})
		if(document_username == None):
			error = "User doesn't exist. Please sign up first!"
		elif(ph.verify(document_username['password'],self.password)==False):
			error = "Password is wrong, try again!"
		return error			

	""" post():
	Sets the class variables and checks the database to verify if the credentials exist and
	are valid, renders the Sign In page with the error if they don't.
	Finally, sets the secure cookie and redirects to /postlogin.
	"""
	def post(self):
		self.username = self.get_argument("username").lower()
		self.password = self.get_argument("psword").lower()

		check_details = self.check_database()
		if(check_details!=None):
			self.render('signin.html',error=check_details)
			return

		self.set_secure_cookie("user", self.username)
		self.redirect('/postlogin')
		return

""" IndexHandler():
Class that handles /
"""

class IndexHandler(tornado.web.RequestHandler):
	def get(self):
		self.render('index.html')

""" PostLoginHandler():
Class that handles /postlogin
"""

class PostLoginHandler(tornado.web.RequestHandler):
	""" get():
	Checks if a secure_cookie exists, if it doesn't then it redirects the user to /,
	else it renders /postlogin.
	"""
	def get(self):
		cookie_status = self.get_secure_cookie("user")
		if(cookie_status==None):
			self.render('index.html')
			return
		else:
			self.render('postlogin.html')
			return

""" BootstrapModule():
Class that has the bootstrap includes statements which are included in every page,
except it's easier when it's made into a module.
"""

class BootstrapModule(tornado.web.UIModule):
	def render(self):
		return self.render_string('modules/bootstrap_include.html')

if __name__ == '__main__':
	tornado.options.parse_command_line() 
	settings = {
		"cookie_secret": "j84i6ykTfmew9As25eYqAbs5KIhrUv/gmp801s9zRo=",
		"xsrf_cookies":True, 
		"login_url": "/signin",
	}
	async_db = motor.motor_tornado.MotorClient().example #Asynchronous DB driver  
	sync_db = MongoClient().example 					 #Synchronous DB driver

	application = tornado.web.Application(
		handlers = [
			(r'/',IndexHandler),
			(r'/signup', SignUpHandler),
			(r'/signin', SignInHandler),
			(r'/postlogin',PostLoginHandler)
		],
		template_path = os.path.join(os.path.dirname(__file__),"templates"),
		static_path = os.path.join(os.path.dirname(__file__),"static"),
		ui_modules={'bootstrap': BootstrapModule},
		debug = True,
		async_db = async_db,
		sync_db = sync_db,

		**settings
	)
	http_server = tornado.httpserver.HTTPServer(application)
	http_server.listen(options.port)
	tornado.ioloop.IOLoop.instance().start()
