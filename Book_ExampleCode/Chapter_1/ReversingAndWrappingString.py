import textwrap
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web

from tornado.options import define, options
define("port", default=8000, help="run on the given port", type=int)

#Reverses a string given as a GET request. For example : "http://localhost:8000/reverse/stressed" returns desserts
class ReverseHandler(tornado.web.RequestHandler):
	def get(self,input):
		self.write(input[::-1])
#Takes the text given as POST request and wraps it according to the width given, defaults to 40 if no width is given.
class WrapHandler(tornado.web.RequestHandler):
	def post(self):
		text = self.get_argument('text')
		width = self.get_argument('width',40)
		self.write(textwrap.fill(text,width))

if __name__ == "__main__":
	tornado.options.parse_command_line() #Parses command lines arguments
	app = tornado.web.Application( #Defines handlers for each url case
		handlers=[
			(r"/reverse/(\w+)", ReverseHandler), #The ( ) around w+ means that string needs to be sent to ReverseHandler
			(r"/wrap", WrapHandler)
		]
	)
	http_server = tornado.httpserver.HTTPServer(app)
	http_server.listen(options.port)
	tornado.ioloop.IOLoop.instance().start()
	