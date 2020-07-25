#!/usr/bin/env python3

import os
import sys


def usage():
	print(__file__, "<search terms>")


twitter = __import__("twitter-export")

searchTerms = []
for arg in sys.argv[1:]:
	if arg.startswith("http://") or arg.startswith("https://"):
		arg = twitter.resolve_shortlink(arg)
	arg = arg.lower()
	searchTerms += [arg]

if not searchTerms:
	usage()
	sys.exit(1)

# reset LogFile to avoid wrong dir because of symlinks
twitter.my_dir = os.path.dirname(__file__)
twitter.log_filename = twitter.my_dir + "/twitter.log"
twitter.load_log()

for _, tweet in sorted(twitter.log.items()):

	if all([term in tweet["text"].lower() for term in searchTerms]):
		print(tweet["date"], ":", tweet["text"])
