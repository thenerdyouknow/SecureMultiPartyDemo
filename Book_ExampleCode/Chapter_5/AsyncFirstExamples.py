import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.httpclient
import urllib
import json
import datetime
import time
from tornado.options import define, options
define("port", default=8000, help="run on the given port", type=int)

#Dummy program that doesn't work because the Twitter API code is outdated 
#Explains two ways of handling asynchronous requests with Tornado

class IndexHandler(tornado.web.RequestHandler):
	@tornado.web.asynchronous
	def get(self):
		query = self.get_argument('q')
		client = tornado.httpclient.AsyncHTTPClient()
		#Calls the function once the fetch completes.
		client.fetch("http://search.twitter.com/search.json?" + \
 					urllib.urlencode({"q": query, "result_type": "recent", "rpp": 100}), callback=self.on_response)
		def on_response(self,response):
			body = json.loads(response.body)
			result_count = len(body['results'])
			now = datetime.datetime.utcnow()
			raw_oldest_tweet_at = body['results'][-1]['created_at']
			oldest_tweet_at = datetime.datetime.strptime(raw_oldest_tweet_at,
			"%a, %d %b %Y %H:%M:%S +0000")
			seconds_diff = time.mktime(now.timetuple()) - \
			time.mktime(oldest_tweet_at.timetuple())
			tweets_per_second = float(result_count) / seconds_diff
			self.write("""
			div style="text-align: center">
			<div style="font-size: 72px">%s</div>
			<div style="font-size: 144px">%.02f</div>
			<div style="font-size: 24px">tweets per second</div>
			</div>""" % (self.get_argument('q'), tweets_per_second))
			self.finish() #Need to close connection because the server won't do it if it's an asynchronous request


class IndexHandler(tornado.web.RequestHandler):
	@tornado.web.asynchronous
	@tornado.gen.engine
	def get(self):
		query = self.get_argument('q')
		client = tornado.httpclient.AsyncHTTPClient()
		#Cleaner with yield and tornado.gen since it doesn't call another function but just stops executing this here and goes on to the next request
		#comes back to the same spot once the HTTP request is done and then executes the rest of the code
		response = yield tornado.gen.Task(client.fetch, "https://api.twitter.com/1.1/search/tweets.json?"+ urllib.parse.urlencode({"q":query, "result_type":"recent"}))
		body = json.loads(response.body)
		result_count = len(body['results'])
		now = datetime.datetime.utcnow()
		raw_oldest_tweet_at = body['results'][-1]['created_at']
		oldest_tweet_at = datetime.datetime.strptime(raw_oldest_tweet_at, "%a, %d %b %Y %H:%M:%S +0000")
		seconds_diff = time.mktime(now.timetuple()) - time.mktime(oldest_tweet_at.timetuple())
		tweets_per_second = float(result_count)/seconds_diff
		self.write("""
		<div style="text-align: center">
		 <div style="font-size: 72px">%s</div>
		 <div style="font-size: 144px">%.02f</div>
		 <div style="font-size: 24px">tweets per second</div>
		</div>""" %(query,tweets_per_second))
		self.finish() #Same idea as above; connection needs to be closed.

if __name__ == "__main__":
	tornado.options.parse_command_line()
	app = tornado.web.Application(handlers=[(r"/", IndexHandler)])
	http_server = tornado.httpserver.HTTPServer(app)
	http_server.listen(options.port)
	tornado.ioloop.IOLoop.instance().start()