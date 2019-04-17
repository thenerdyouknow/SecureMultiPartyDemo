#Imports for all the packages
import os.path
import re
import motor.motor_tornado
import argon2
from pymongo import MongoClient
import functools
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
	""" BaseHandler():
	Class that'll be used later when @tornado.web.authenticated is needed for POST requests.
	"""
	def get_current_user(self):
		user_cookie = self.get_secure_cookie("user")
		# tnc_cookie = self.get_secure_cookie("tnc")
		# if(user_cookie is None or tnc_cookie is None):
		# 	self.clear_cookie("user")
		# 	self.clear_cookie("tnc")
		# 	return None
		# else:
		return user_cookie

def protected(method):
    @tornado.web.authenticated
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        self.set_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.set_header('Pragma', 'no-cache')
        self.set_header('Expires', '0')
        return method(self, *args, **kwargs)
    return wrapper

def if_already_logged_in(method):
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
		verifies if the hashing happened properly, re-hashes if the verification failed,
		and then returns hashed password.
		"""
		ph = argon2.PasswordHasher()
		hashed_password = ph.hash(self.password)
		try:
			ph.verify(hashed_password,self.password)
		except argon2.exceptions.VerifyMismatchError:
			hashed_password = ph.hash(self.password)
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

	async def add_to_database(self,collection,question,choices):
		document = {'question': question,'choices': choices}
		result = await collection.insert_one(document)

	@protected
	async def post(self):
		question = self.get_argument("question")
		choices = self.get_arguments("choice")
		username = str(self.get_secure_cookie("user"))
		user_collection = async_db.username
		await self.add_to_database(user_collection,question,choices)
		self.redirect("/postlogin")



class ExistingPollsHandler(BaseHandler):
	""" ExistingPollsHandler():
	Class that handles /existingpolls
	"""
	@protected
	def get(self):
		""" get():
		Renders the existingpolls page. uses the decorator to make sure the user is logged in first.
		"""
		self.render('existingpolls.html',error='')
		return

class LogoutHandler(tornado.web.RequestHandler):
	""" LogoutHandler():
	Class that handles /logout
	"""
	def get(self):
		""" get():
		Cleans out the secure cookie. Also redirects to home page.
		"""
		self.clear_cookie("user")
		# self.clear_cookie("tnc")
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

	application = tornado.web.Application(
		handlers = [
			(r'/',IndexHandler),
			(r'/signup', SignUpHandler),
			(r'/signin', SignInHandler),
			(r'/postlogin',PostLoginHandler),
			(r'/createpoll',CreatePollHandler),
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