#!/usr/bin/python

# https://twitter.com/statuses/user_timeline/albertzeyer.xml?page=x

import better_exchook
better_exchook.install()

# via https://dev.twitter.com/apps/
# not sure how to keep this a secret in an open source app
# note that in your app, you must set *some* value for callback so that we can set any callback (https://dev.twitter.com/discussions/392). Otherwise error: Desktop applications only support the oauth_callback value 'oob'
consumer_key = "EAoZyRlPKxlCkVruwSzEtQ"
consumer_secret = "k8C06gxSs2qbZtapAm3D9BEwat5ceDcMtCiStFRNU"

import os
mydir = os.path.dirname(__file__)
LogFile = mydir + "/twitter.log"
oauth_filename = mydir + "/twitter_auth_data.json"

import time, sys
from urllib2 import Request, HTTPError, URLError, build_opener
from urlparse import urlparse

def resolveShortlink(url):
	tries = 0
	RetriesMax = 10
	origDomain = urlparse(url).hostname
	opener = build_opener()
	lastUrl = {}
	orig_open = opener.open
	def wrap_open(url, *args, **kwargs):
		lastUrl["url"] = url.get_full_url()
		return orig_open(url, *args, **kwargs)
	opener.open = wrap_open
	while True:
		tries += 1
		try:
			req = Request(url, headers={"User-Agent":"Twitter-export"})
			open_req = opener.open(req)
			return open_req.geturl()
		except HTTPError, e:
			if origDomain != urlparse(e.geturl()).hostname:
				# it might be that the shortlink resolved to some 404 or so.
				# but it resolved, we are at a different domain, so just return it.
				return e.geturl()
			if tries > RetriesMax: raise e
			if e.code == 429: # too many requests
				time.sleep(1)
				continue
			raise e
		except URLError, e:
			# maybe we got a strange error while opening the redirect
			if origDomain != urlparse(lastUrl["url"]).hostname:
				return lastUrl["url"]
			raise e

def loadLog():
	global log
	
	try:
		log = eval(open(LogFile).read())
		assert isinstance(log, dict)
	except IOError: # e.g. file-not-found. that's ok
		log = {}
	except:
		print "logfile reading error"
		sys.excepthook(*sys.exc_info())
		log = {}

def betterRepr(o):
	# the main difference: this one is deterministic
	# the orig dict.__repr__ has the order undefined.
	if isinstance(o, list):
		return "[" + ", ".join(map(betterRepr, o)) + "]"
	if isinstance(o, tuple):
		return "(" + ", ".join(map(betterRepr, o)) + ")"
	if isinstance(o, dict):
		return "{\n" + "".join(map(lambda (k,v): betterRepr(k) + ": " + betterRepr(v) + ",\n", sorted(o.iteritems()))) + "}"
	# fallback
	return repr(o)
	
def saveLog():
	global log, LogFile
	f = open(LogFile, "w")
	f.write(betterRepr(log))
	f.write("\n")

def formatDate(t):
	# if you used an old script which didn't saved the UTC stamp, use this script:
	# https://github.com/albertz/memos/blob/7a19a7cc4a3fcb2f1daebbc45e2da896032704a2/twitter-fixdates.py
	return time.strftime("%Y-%m-%d %H:%M:%S +0000", t)
	
# log is dict: (date, id) -> tweet, date as in formatDate

def updateTweetFromSource(tweet, s):
	# https://dev.twitter.com/docs/api/1.1/get/statuses/user_timeline
	# https://dev.twitter.com/docs/platform-objects/tweets
	tweet["text"] = s.text
	tweet["geo"] = s.coordinates
	if s.in_reply_to_status_id:
		retweetFrom = tweet.setdefault("retweeted-from", {})
		retweetFrom["status-id"] = long(s.in_reply_to_status_id)
		retweetFrom["user-id"] = long(s.in_reply_to_user_id)
		retweetFrom["user-name"] = s.in_reply_to_screen_name

ShortlinkDomains = ["bit.ly", "goo.gl", "youtu.be", "t.co"]
def linksInText(s):
	s = unicode(s)
	# do some replaces for better splitting
	s = s.replace("(", " ")
	s = s.replace(")", " ")
	for part in s.split():
		if part.startswith("http://") or part.startswith("https://"):
			yield part
			continue

def updateTweet(tweet):
	for l in linksInText(tweet["text"]):
		parsedUrl = urlparse(l)
		if parsedUrl.hostname in ShortlinkDomains:
			print "resolved", l, "->",
			resolvedUrl = resolveShortlink(l)
			print resolvedUrl
			tweet["text"] = tweet["text"].replace(l, resolvedUrl)

def updateOldTweets():
	global log
	for tweet in log.itervalues():
		old = str(tweet)
		updateTweet(tweet)
		if str(tweet) != old: saveLog()

SkipOldWebupdate = True
DataCount = 200

def lastStatusId():
	return max([tweetId for (tweetDate, tweetId) in log.keys()] + [0])

def getNewTweets():
	while True:
		data = api.user_timeline(since_id=lastStatusId())
		#data = getXml("https://api.twitter.com/1.1/statuses/user_timeline.xml?screen_name=%s&page=%i&count=%i" % (twitterUser, pageNum, DataCount))

		for s in data:
			tweetId = long(s.id)
			tweetDate = formatDate(s.created_at.utctimetuple())
			tweetKey = (tweetDate, tweetId)
			if SkipOldWebupdate and tweetKey in log:
				print "** hit old entry, finished"
				data = None
				break
			tweet = log.setdefault(tweetKey, {})
			tweet["id"] = tweetId
			tweet["date"] = tweetDate
			updateTweetFromSource(tweet, s)
			updateTweet(tweet)
			saveLog()

		if not data:
			print "** finished"
			break

def login():
	import tweetpony

	auth_data = None
	def finalize():
		global api, twitterUser
		api = tweetpony.API(
			consumer_key=consumer_key,
			consumer_secret=consumer_secret,
			access_token=auth_data['access_token'],
			access_token_secret=auth_data['access_token_secret'])
		twitterUser = api.user

	import json
	try:
		with open(oauth_filename, "r") as f:
			auth_data = json.loads(f.read())
	except IOError:
		pass
	else:
		try:
			finalize()
		except tweetpony.APIError as err:
			print "Twitter login error:", err, err.code, err.description
			print "trying to relogin..."
		else:
			return

	#api = tweetpony.API(consumer_key = tweetpony.CONSUMER_KEY, consumer_secret = tweetpony.CONSUMER_SECRET)
	api = tweetpony.API(consumer_key = consumer_key, consumer_secret = consumer_secret)

	# Start a small webserver to provide a simple callback URL to
	# get the oauth token.
	class OAuthReturnHandler:
		def __init__(oself):
			oself.httpd_access_token_callback = None

			import BaseHTTPServer
			class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
				def log_message(self, format, *args): pass
				def do_GET(webself):
					pathStart = "/get_access_token?"
					if webself.path.startswith(pathStart):
						oself.httpd_access_token_callback = webself.path[len(pathStart):]

						webself.send_response(200)
						webself.send_header("Content-type", "text/html")
						webself.end_headers()
						webself.wfile.write("""
							<html><head><title>OAuth return</title></head>
							<body onload="onLoad()">
							<script type="text/javascript">
							function onLoad() {
								ww = window.open(window.location, "_self");
								ww.close();
							}
							</script>
							</body></html>""")
					else:
						webself.send_response(404)
						webself.end_headers()

			oself.handler = Handler
			def tryOrFail(fn):
				try: fn(); return True
				except: return False
			# Try with some default ports first to avoid cluttering the users Google Authorized Access list.
			tryOrFail(lambda: oself.startserver(port = 8123)) or \
			tryOrFail(lambda: oself.startserver(port = 8321)) or \
			oself.startserver(port = 0)

			_,oself.port = oself.httpd.server_address
			oself.oauth_callback_url = "http://localhost:%d/get_access_token" % oself.port

		def startserver(self, port):
			import BaseHTTPServer
			self.httpd = BaseHTTPServer.HTTPServer(("", port), self.handler)

		def wait_callback_response(self):
			while self.httpd_access_token_callback == None:
				self.httpd.handle_request()
			return self.httpd_access_token_callback

	oauthreturnhandler = OAuthReturnHandler()

	# monkey-patch. we need to use POST for callback_url (https://dev.twitter.com/docs/api/1/get/oauth/authorize)
	# upstream bug report: https://github.com/Mezgrman/TweetPony/issues/5
	def get_request_token(self, callback_url = None):
		url = self.build_request_url(self.oauth_root, 'request_token')
		resp = self.do_request("POST", url, callback_url, is_json = False)
		token_data = self.parse_qs(resp)
		self.set_request_token(token_data['oauth_token'], token_data['oauth_token_secret'])
		return (self.request_token, self.request_token_secret, token_data.get('oauth_callback_confirmed'))
	tweetpony.API.get_request_token = get_request_token

	# monkey-patch to get detailed error information
	# workaround for this issue: https://github.com/Mezgrman/TweetPony/issues/6
	import requests
	orig_post = requests.post
	def post_wrapper(*args, **kwargs):
		resp = orig_post(*args, **kwargs)
		if resp.status_code != 200:
			print "POST error code", resp.status_code, resp.description
			print resp
			print resp.text
		return resp
	requests.post = post_wrapper

	auth_url = api.get_auth_url(callback_url=oauthreturnhandler.oauth_callback_url)
	print "open oauth login page"
	import webbrowser; webbrowser.open(auth_url)

	print "waiting for redirect callback ...",
	httpd_access_token_callback = oauthreturnhandler.wait_callback_response()
	print "done login"
	from urlparse import parse_qs
	token = parse_qs(httpd_access_token_callback)

	api.authenticate(token["oauth_verifier"])
	auth_data = {'access_token': api.access_token, 'access_token_secret': api.access_token_secret}

	with open(oauth_filename, 'w') as f:
		f.write(json.dumps(auth_data))

	finalize()

def main():
	print "logfile:", LogFile
	loadLog()
	login()
	updateOldTweets()
	getNewTweets()

if __name__ == '__main__':
	main()
	
