#!/usr/bin/python

# https://twitter.com/statuses/user_timeline/albertzeyer.xml?page=x

import better_exchook
better_exchook.install()

twitterUser = "albertzeyer"
# TODO: maybe allow other twitter users...

import time, os, sys
import BeautifulSoup
from urllib2 import Request, HTTPError, URLError, urlopen, build_opener
from urlparse import urlparse

def getXml(url):
	while True:
		try:
			req = Request(url)
			open_req = urlopen(req)
			content = open_req.read()
			content_type = open_req.headers.get('content-type')
			break
		except HTTPError, e:
			print e
			if e.code in (502,503): # bad gateway, Service Unavailable. happens if overloaded
				print "waiting a few seconds"
				time.sleep(2)
				continue
			if e.code == 400 and int(e.hdrs.get("X-RateLimit-Remaining", -1)) == 0:
				print "rate limit exceeded. waiting 1h"
				time.sleep(60 * 60)
				continue
			raise e
		assert False
	assert "xml" in content_type
	soup = BeautifulSoup.BeautifulSoup(content)
	return soup

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
		
mydir = os.path.dirname(__file__)
LogFile = mydir + "/twitter.log"

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
	tweet["text"] = s.find("text").text
	tweetGeo = s.find("georss:polygon")
	tweet["geo"] = tweetGeo.text if tweetGeo else None
	if s.in_reply_to_status_id.text:
		retweetFrom = tweet.setdefault("retweeted-from", {})
		retweetFrom["status-id"] = long(s.in_reply_to_status_id.text)
		retweetFrom["user-id"] = long(s.in_reply_to_user_id.text)
		retweetFrom["user-name"] = s.in_reply_to_screen_name.text

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

def getNewTweets():
	from itertools import count
	for pageNum in count(1):
		print "> page", pageNum
		data = getXml("https://api.twitter.com/1.1/statuses/user_timeline.xml?screen_name=%s&page=%i&count=%i" % (twitterUser, pageNum, DataCount))
	
		statuses = []	
		for s in data.statuses.childGenerator():
			if isinstance(s, (str,unicode)): continue
			assert isinstance(s, BeautifulSoup.Tag)
			assert s.name == "status"
			statuses += [s]
	
		if not statuses:
			print "** finished"
			break
			
		for s in statuses:
			tweetId = long(s.id.text)
			tweetDate = formatDate(time.strptime(s.created_at.text, "%a %b %d %H:%M:%S +0000 %Y"))
			tweetKey = (tweetDate, tweetId)
			if SkipOldWebupdate and tweetKey in log:
				print "** hit old entry, finished"
				pageNum = None
				break
			tweet = log.setdefault(tweetKey, {})
			tweet["id"] = tweetId
			tweet["date"] = tweetDate
			updateTweetFromSource(tweet, s)
			updateTweet(tweet)
			saveLog()
		if not pageNum: break
	
def main():
	print "logfile:", LogFile
	loadLog()
	updateOldTweets()
	getNewTweets()

if __name__ == '__main__':
	main()
	
