import os.path
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web

from tornado.options import define, options
define("port", default=8000, help="run on the given port", type=int)

class IndexHandler(tornado.web.RequestHandler):
	def get(self):
		self.render('index.html')

class PoemPageHandler(tornado.web.RequestHandler):
	def post(self):
		noun_1 = self.get_argument('noun_1')
		noun_2 = self.get_argument('noun_2')
		verb = self.get_argument('verb')
		noun_3 = self.get_argument('noun_3')
		self.render('poem.html', roads=noun_1, wood=noun_2, made=verb, difference=noun_3) #Renders the page with all the variables mentioned available inside template

if __name__ == '__main__':
	tornado.options.parse_command_line()
	app = tornado.web.Application(
		handlers=[
			(r'/', IndexHandler),
			(r'/poem', PoemPageHandler)
		],
		template_path=os.path.join(os.path.dirname(__file__), "templates") #Tells tornado where to look for the .html files
	)
	http_server = tornado.httpserver.HTTPServer(app)
	http_server.listen(options.port)
	tornado.ioloop.IOLoop.instance().start()
