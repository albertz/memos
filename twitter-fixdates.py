#!/usr/bin/python

import os, sys

twitter = __import__("twitter-export")

# reset LogFile. easier to call from current dir
twitter.mydir = "."
twitter.LogFile = twitter.mydir + "/twitter.log"
twitter.loadLog()

log = twitter.log

import time

for key, value in log.iteritems():
	timeStr, tweetId = key

	try:
		time.strptime(timeStr, "%Y-%m-%d %H:%M:%S +0000")
		# no exception, thus this format matches, thus continue
		continue
	except: pass
	
	# we assume that just "+0000" is missing and we already have UTC
	timeStr += " +0000"
	# check again
	time.strptime(timeStr, "%Y-%m-%d %H:%M:%S +0000")
	
	# update value dict
	value["date"] = timeStr
	
	# remove old and set new
	del log[key]
	log[(timeStr,tweetId)] = value

twitter.saveLog()
