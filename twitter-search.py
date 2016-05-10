#!/usr/bin/env python2

def usage():
	print __file__, "<search terms>"

import os, sys

twitter = __import__("twitter-export")

searchTerms = []
for arg in sys.argv[1:]:
	if arg.startswith("http://") or arg.startswith("https://"):
		arg = twitter.resolveShortlink(arg)
	arg = arg.lower()
	searchTerms += [arg.decode("utf8")]

if not searchTerms:
	usage()
	sys.exit(1)
	
# reset LogFile to avoid wrong dir because of symlinks
twitter.mydir = os.path.dirname(__file__)
twitter.LogFile = twitter.mydir + "/twitter.log"
twitter.loadLog()

for _,twit in sorted(twitter.log.iteritems()):
	
	if all([term in twit["text"].lower() for term in searchTerms]):
		print twit["date"], ":", twit["text"]
