import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web

from tornado.options import define, options
define("port", default=8000, help="run on the given port", type=int)

class IndexHandler(tornado.web.RequestHandler):
	def get(self):
		greeting = self.get_argument('greeting','Hello') #Second value is the one it defaults to if the argument isn't defined.
		self.write(greeting + ', friendly user!')
	def write_error(self,status_code, **kwargs): #Can rewrite the default error with something nicer
		self.write("Damnit, bro. You caused a %d error." % status_code)

if __name__ == "__main__":
	tornado.options.parse_command_line()
	app = tornado.web.Application(handlers=[(r"/", IndexHandler)])
	http_server = tornado.httpserver.HTTPServer(app)
	http_server.listen(options.port)
	tornado.ioloop.IOLoop.instance().start()

