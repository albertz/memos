#!/usr/bin/env python3

# https://twitter.com/statuses/user_timeline/albertzeyer.xml?page=x

import os
import time
import typing
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, build_opener
import http.server
import webbrowser
import requests
import json
import tweetpony
import better_exchook

# via https://dev.twitter.com/apps/
# not sure how to keep this a secret in an open source app
# note that in your app, you must set *some* value for callback
# so that we can set any callback (https://dev.twitter.com/discussions/392).
# Otherwise error: Desktop applications only support the oauth_callback value 'oob'
consumer_key = "EAoZyRlPKxlCkVruwSzEtQ"
consumer_secret = "k8C06gxSs2qbZtapAm3D9BEwat5ceDcMtCiStFRNU"

my_dir = os.path.dirname(__file__)
log_filename = my_dir + "/twitter.log"
oauth_filename = my_dir + "/twitter_auth_data.json"


def resolve_shortlink(url):
	tries = 0
	retries_max = 10
	orig_domain = urlparse(url).hostname
	opener = build_opener()
	last_url = {}
	orig_open = opener.open

	def wrap_open(url, *args, **kwargs):
		last_url["url"] = url.get_full_url()
		return orig_open(url, *args, **kwargs)

	opener.open = wrap_open
	while True:
		tries += 1
		try:
			req = Request(url, headers={"User-Agent":"Twitter-export"})
			open_req = opener.open(req)
			return open_req.geturl()
		except HTTPError as e:
			if orig_domain != urlparse(e.geturl()).hostname:
				# it might be that the shortlink resolved to some 404 or so.
				# but it resolved, we are at a different domain, so just return it.
				return e.geturl()
			if tries > retries_max:
				raise e
			if e.code == 429:  # too many requests
				time.sleep(1)
				continue
			raise e
		except URLError as e:
			# maybe we got a strange error while opening the redirect
			if orig_domain != urlparse(last_url["url"]).hostname:
				return last_url["url"]
			raise e


# log is dict: (date, id) -> tweet, date as in formatDate
log = None  # type: typing.Optional[typing.Dict[typing.Tuple[str,int],typing.Dict[str]]]


def load_log():
	global log

	# noinspection PyBroadException
	try:
		# TODO: convert old-style Python unicode string (`u"foo"`).
		log = eval(open(log_filename).read())
		assert isinstance(log, dict)
	except IOError:  # e.g. file-not-found. that's ok
		log = {}


def better_repr(o):
	# the main difference: this one is deterministic
	# the orig dict.__repr__ has the order undefined.
	if isinstance(o, list):
		return "[" + ", ".join(map(better_repr, o)) + "]"
	if isinstance(o, tuple):
		return "(" + ", ".join(map(better_repr, o)) + ")"
	if isinstance(o, dict):
		return "{\n" + "".join([better_repr(k_v[0]) + ": " + better_repr(k_v[1]) + ",\n" for k_v in sorted(o.items())]) + "}"
	# fallback
	return repr(o)


def save_log():
	f = open(log_filename, "w")
	f.write(better_repr(log))
	f.write("\n")


def format_date(t):
	# if you used an old script which didn't saved the UTC stamp, use this script:
	# https://github.com/albertz/memos/blob/7a19a7cc4a3fcb2f1daebbc45e2da896032704a2/twitter-fixdates.py
	return time.strftime("%Y-%m-%d %H:%M:%S +0000", t)


def replace_indexed_text(txt, indices_replacements):
	p = 0
	new_txt = ""
	for (p1, p2), replacement in sorted(indices_replacements.items()):
		assert p <= p1
		if p < p1:
			new_txt += txt[p:p1]
		assert p1 < p2
		new_txt += replacement
		p = p2
	new_txt += txt[p:]
	return new_txt


def update_tweet_from_source(tweet, s):
	# https://dev.twitter.com/docs/api/1.1/get/statuses/user_timeline
	# https://dev.twitter.com/docs/platform-objects/tweets
	tweet["text"] = replace_indexed_text(
		s.text,
		{tuple(url.indices): url.expanded_url for url in s.entities.urls})
	tweet["geo"] = s.coordinates
	if s.in_reply_to_status_id:
		retweet_from = tweet.setdefault("retweeted-from", {})
		retweet_from["status-id"] = int(s.in_reply_to_status_id)
		retweet_from["user-id"] = int(s.in_reply_to_user_id)
		retweet_from["user-name"] = s.in_reply_to_screen_name


ShortlinkDomains = ["bit.ly", "goo.gl", "youtu.be", "t.co"]


def links_in_text(s):
	s = str(s)
	# do some replaces for better splitting
	s = s.replace("(", " ")
	s = s.replace(")", " ")
	for part in s.split():
		if part.startswith("http://") or part.startswith("https://"):
			yield part
			continue


def update_tweet(tweet):
	for link in links_in_text(tweet["text"]):
		parsed_url = urlparse(link)
		if parsed_url.hostname in ShortlinkDomains:
			print("resolved", link, "->", end=' ')
			resolved_url = resolve_shortlink(link)
			print(resolved_url)
			tweet["text"] = tweet["text"].replace(link, resolved_url)


def update_old_tweets():
	global log
	for tweet in log.values():
		old = str(tweet)
		update_tweet(tweet)
		if str(tweet) != old:
			save_log()


SkipOldWebupdate = True
DataCount = 200


def last_status_id():
	return max([tweet_id for (tweet_date, tweet_id) in list(log.keys())] + [0])


def get_new_tweets():
	# https://dev.twitter.com/docs/working-with-timelines
	while True:
		data = api.user_timeline(since_id=last_status_id())

		for s in reversed(list(data)):
			tweet_id = int(s.id)
			tweet_date = format_date(s.created_at.utctimetuple())
			tweet_key = (tweet_date, tweet_id)
			if SkipOldWebupdate and tweet_key in log:
				print("** hit old entry, finished")
				data = None
				break
			tweet = log.setdefault(tweet_key, {})
			tweet["id"] = tweet_id
			tweet["date"] = tweet_date
			update_tweet_from_source(tweet, s)
			update_tweet(tweet)
			save_log()

		if not data:
			print("** finished")
			break


api = None  # type: typing.Optional[tweetpony.API]
twitter_user = None  # type: typing.Optional[tweetpony.User]


def login():
	auth_data = None

	def finalize():
		global api, twitter_user
		api = tweetpony.API(
			consumer_key=consumer_key,
			consumer_secret=consumer_secret,
			access_token=auth_data['access_token'],
			access_token_secret=auth_data['access_token_secret'])
		twitter_user = api.user

	try:
		with open(oauth_filename, "r") as f:
			auth_data = json.loads(f.read())
	except IOError:
		pass
	else:
		try:
			finalize()
		except tweetpony.APIError as err:
			print("Twitter login error:", err, err.code, err.description)
			print("trying to relogin...")
		else:
			return

	# api = tweetpony.API(consumer_key = tweetpony.CONSUMER_KEY, consumer_secret = tweetpony.CONSUMER_SECRET)
	api = tweetpony.API(consumer_key=consumer_key, consumer_secret=consumer_secret)

	# Start a small webserver to provide a simple callback URL to
	# get the oauth token.
	class OAuthReturnHandler:
		# noinspection PyMethodParameters
		def __init__(o_self):
			o_self.httpd = None  # type: typing.Optional[http.server.HTTPServer]
			o_self.httpd_access_token_callback = None

			class Handler(http.server.BaseHTTPRequestHandler):
				# noinspection PyShadowingBuiltins
				def log_message(self, format, *args): pass

				# noinspection PyPep8Naming,PyMethodParameters
				def do_GET(web_self):
					path_start = "/get_access_token?"
					if web_self.path.startswith(path_start):
						o_self.httpd_access_token_callback = web_self.path[len(path_start):]

						web_self.send_response(200)
						web_self.send_header("Content-type", "text/html")
						web_self.end_headers()
						web_self.wfile.write(b"""
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
						web_self.send_response(404)
						web_self.end_headers()

			o_self.handler = Handler

			def try_or_fail(fn):
				# noinspection PyBroadException
				try:
					fn()
					return True
				except Exception:
					return False

			# Try with some default ports first to avoid cluttering the users Google Authorized Access list.
			(
					try_or_fail(lambda: o_self.start_server(port=8123)) or
					try_or_fail(lambda: o_self.start_server(port=8321)) or
					o_self.start_server(port=0))

			_, o_self.port = o_self.httpd.server_address
			o_self.oauth_callback_url = "http://localhost:%d/get_access_token" % o_self.port

		def start_server(self, port):
			self.httpd = http.server.HTTPServer(("", port), self.handler)

		def wait_callback_response(self):
			while self.httpd_access_token_callback is None:
				self.httpd.handle_request()
			return self.httpd_access_token_callback

	oauth_return_handler = OAuthReturnHandler()

	# monkey-patch. we need to use POST for callback_url (https://dev.twitter.com/docs/api/1/get/oauth/authorize)
	# upstream bug report: https://github.com/Mezgrman/TweetPony/issues/5
	def get_request_token(self, callback_url=None):
		url = self.build_request_url(self.oauth_root, 'request_token')
		resp = self.do_request("POST", url, callback_url, is_json=False)
		token_data = self.parse_qs(resp)
		self.set_request_token(token_data['oauth_token'], token_data['oauth_token_secret'])
		return self.request_token, self.request_token_secret, token_data.get('oauth_callback_confirmed')
	tweetpony.API.get_request_token = get_request_token

	# monkey-patch to get detailed error information
	# workaround for this issue: https://github.com/Mezgrman/TweetPony/issues/6
	orig_post = requests.post

	def post_wrapper(*args, **kwargs):
		resp = orig_post(*args, **kwargs)
		if resp.status_code != 200:
			print("POST error code", resp.status_code)
			print(resp)
			print(resp.text)
		return resp
	requests.post = post_wrapper

	auth_url = api.get_auth_url(callback_url=oauth_return_handler.oauth_callback_url)
	print("open oauth login page")
	webbrowser.open(auth_url)

	print("waiting for redirect callback ...", end=' ')
	httpd_access_token_callback = oauth_return_handler.wait_callback_response()
	print("done login")
	from urllib.parse import parse_qs
	token = parse_qs(httpd_access_token_callback)

	api.authenticate(token["oauth_verifier"])
	auth_data = {'access_token': api.access_token, 'access_token_secret': api.access_token_secret}

	with open(oauth_filename, 'w') as f:
		f.write(json.dumps(auth_data))

	finalize()


def main():
	print("logfile:", log_filename)
	load_log()
	login()
	update_old_tweets()
	get_new_tweets()


if __name__ == '__main__':
	better_exchook.install()
	main()
