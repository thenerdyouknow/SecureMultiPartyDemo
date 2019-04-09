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


class BaseHandler(tornado.web.RequestHandler):
	def get_current_user(self):
		return self.get_secure_cookie("user")

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
		self.username = self.get_argument("username")
		self.email = self.get_argument("email")
		self.password = self.get_argument("psword")

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

class SignInHandler(tornado.web.RequestHandler):
	def get(self):
		self.render('signin.html')

class IndexHandler(tornado.web.RequestHandler):
	def get(self):
		self.render('index.html')

class PostLoginHandler(tornado.web.RequestHandler):
	def get(self):
		cookie_status = self.get_secure_cookie("user")
		if(cookie_status==None):
			self.render('index.html')
			return
		else:
			self.render('postlogin.html')
			return

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
	async_db = motor.motor_tornado.MotorClient().example 
	sync_db = MongoClient().example

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
