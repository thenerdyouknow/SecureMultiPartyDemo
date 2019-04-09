#Imports for all the packages
import os.path
import re
import motor.motor_tornado
from argon2 import PasswordHasher
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
	def get(self):
		self.render('signup.html',error='')
	
	async def post(self):
		username = self.get_argument("username")
		email = self.get_argument("email")
		password = self.get_argument("psword")
		if (re.fullmatch('^(?=.{8,20}$)(?![_.])(?!.*[_.]{2})[a-zA-Z0-9._]+(?<![_.])$', username) == None): #Found at :https://stackoverflow.com/questions/12018245/regular-expression-to-validate-username
			self.render("signup.html",error="Your username doesn't follow our username rules. Please fix it.")
			return
		elif (re.fullmatch(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', email) == None): #Rudimentary Regex, will need to be updated to be simpler and email validation by sending an email will have to be done
			self.render("signup.html",error="Your email doesn't look like a valid email")
			return

		async def check_if_exists(username,email):
			error = None
			document = await db.users.find_one({'username':username})
			if not bool(document):
				error = "Username exists already"
			document = await db.users.find_one({'email':email})
			if not bool(document):
				error = "Email exists already"
			return error

		async def do_insert(username,email,password):
			document = {'username': username,'email': email,'password': password}
			result = await db.users.insert_one(document)

		def hash_password(password):
			ph = PasswordHasher()
			hashed_password = ph.hash(password)
			try:
				ph.verify(hashed_password,password)
			except VerifyMismatchError:
				hashed_password = ph.hash(password)
			return hashed_password

		does_it_exist = await check_if_exists(username,email)

		if(does_it_exist!=None):
			self.render("signup.html",error=does_it_exist)

		hashed_password = hash_password(password)

		await do_insert(username,email,hashed_password)

		self.redirect('/postlogin')

	def _on_response(self,result,error):
		if error:
			raise tornado.web.HTTPError(500,error)
		else:
			self.redirect('/postlogin')

class SignInHandler(tornado.web.RequestHandler):
	def get(self):
		self.render('signin.html')

class IndexHandler(tornado.web.RequestHandler):
	def get(self):
		self.render('index.html')

class PostLoginHandler(tornado.web.RequestHandler):
	def get(self):
		self.render('postlogin.html')

class BootstrapModule(tornado.web.UIModule):
	def render(self):
		return self.render_string('modules/bootstrap_include.html')

if __name__ == '__main__':
	tornado.options.parse_command_line()
	settings = {
		"cookie_secret": "j84i6ykTfmew9As25eYqAbs5KIhrUv/gmp801s9zRo=",
		"xsrf_cookies":True
	}
	db = motor.motor_tornado.MotorClient().example

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
		db = db,
		**settings
	)
	http_server = tornado.httpserver.HTTPServer(application)
	http_server.listen(options.port)
	tornado.ioloop.IOLoop.instance().start()
