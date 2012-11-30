#!/usr/bin/env python2.7

from datetime import datetime
from HTMLParser import HTMLParser
from optparse import OptionParser

import hashlib
import mechanize
import Queue
import threading
import time
import sys
import urllib2

base_url = 'http://www.dnsbl.info'

######## Classes ##############

"""
Utility class to log timestamped messages to stdout/stderr
"""
class Logger() :

    @staticmethod
    def info(msg) :
        sys.stderr.write(Logger.timestamp())
        sys.stderr.write(' - INFO - ')
        sys.stderr.write(msg)
        sys.stderr.write('\n')

    @staticmethod
    def warning(msg) :
        pass

    @staticmethod
    def error(msg) :
        pass

    @staticmethod
    def debug(msg) :
        sys.stderr.write(Logger.timestamp())
        sys.stderr.write(' - DEBUG - ')
        sys.stderr.write(msg)
        sys.stderr.write('\n')

    @staticmethod
    def timestamp() :
        return datetime.today().strftime('%b %e %H:%M:%S')

"""
Object used to store BlackList provider url, name and MX reputation status
(valid/invalid)
"""
class BlackList() :
    
    name = ''
    img_url = ''
    valid = None

"""
Parses result page to get blacklist provider url and reputation status
"""
class DnsblParser(HTMLParser) :

    def __init__(self, base_url) :
        HTMLParser.__init__(self)
        self.in_table = False
        self.in_td = False
        self.in_bl = False
        self.current_result_url = ''
        self.current_bl_name = ''
        self.bl_list = list()
        self.base_url = base_url

    def handle_starttag(self, tag, attrs):
        if(tag=='table') :
            if debug : Logger.debug(' '.join(('table', dict(attrs)['class'])))
            self.in_table = True

        if(self.in_table and tag=='td') :
            if debug : Logger.debug('  TD')
            self.in_td = True

        if(self.in_table and self.in_td and tag=='img') :
            self.current_result_url = dict(attrs)['src']

        if(self.in_table and self.in_td and tag=='a') :
            self.in_bl = True

    def handle_endtag(self, tag):
        if(self.in_td and tag=='td') :
            self.in_td = False
            self.print_info()

        if(self.in_table and tag=='table') :
            self.in_table = False

        if(self.in_bl and tag=='a') :
            self.in_bl = False

    def handle_data(self, data):
        if(self.in_bl) :
            self.current_bl_name = data

    def print_info(self) :
        if debug : Logger.debug(' '.join(('   ', self.current_bl_name, self.current_result_url)))
        bl = BlackList()
        bl.name = self.current_bl_name
        bl.img_url = self.base_url+self.current_result_url
        self.bl_list.append(bl)

"""
Download the images representing the MX reputation and compute the sha1 digest
"""
class ResultFetcher() :

    def __init__(self) :
        self.queue = Queue.Queue()

    @staticmethod
    def read_url(queue, url) :
        if debug : Logger.debug('Fetching '+url)
        data = urllib2.urlopen(url).read()
        H = hashlib.sha1()
        H.update(data)
        queue.put((url,H.hexdigest()))
        if debug : Logger.debug('Done '+url)

    def fetch_parallel(self, bl_list) :
        threads = [ threading.Thread(target=ResultFetcher.read_url, args=(self.queue,bl.img_url,))
            for bl in bl_list ]

        for t in threads :
            t.start()
        for t in threads : 
            t.join()

"""
Checks images digests and compare to stored values to see wether the image is
the green or red one. Unknown status is not handled
"""
class BlValidator() :

    VALID = '11f40b11c891c53b6f97945ed71e771d0caa2503'
    INVALID = '2ab93125fbe266b3bb4fd3704e5b1523d895dda3'

    ignore_list = ('ips.backscatterer.org')

    @staticmethod
    def check(bl) :
        if debug : Logger.debug(' '.join(('opening', bl.img_url)))
        img = urllib2.urlopen(bl.img_url)
        data = img.read()
        # get the gif sha1 sum
        H = hashlib.sha1()
        H.update(data)
        h = H.hexdigest()
        img.close()

        # Compare sha1 sums with stored values
        if(h==BlValidator.VALID) :
            if debug : Logger.debug('valid')
            bl.valid = True
        elif(h==BlValidator.INVALID) :
            if debug : Logger.debug('invalid')
            bl.valid = False

    @staticmethod
    def validate_parallel(bl_list) :
        fetcher = ResultFetcher()
        fetcher.fetch_parallel(bl_list)
        Logger.info("Download ok")

        results = list()
        while fetcher.queue.qsize() != 0 :
            results.append(fetcher.queue.get(True, 5))
    
        # Individual validation
        Logger.info("Validating results")
        results = dict(results)
        for bl in bl_list :
            if results.has_key(bl.img_url) :
                if(results[bl.img_url]==BlValidator.VALID) :
                    Logger.info(':'.join((bl.name,'valid')))
                    bl.valid = True
                elif(results[bl.img_url]==BlValidator.INVALID) :
                    Logger.info(':'.join((bl.name,'invalid')))
                    bl.valid = False

        # Global validation
        if debug : Logger.debug("Validating MX")
        for bl in bl_list :
            if not bl.valid and bl.name not in BlValidator.ignore_list :
                return False
        return True

    @staticmethod
    def validate_sequential(bl_list) :
        for bl in bl_list :
            BlValidator.check(bl)

        for bl in bl_list :
            if not bl.valid and bl.name not in BlValidator.ignore_list :
                return False
        return True
 

####### Options parsing ###############

parser = OptionParser("usage: %prog -s SERVER [options]")
parser.add_option("-d", "--debug", default=False, action="store_true",
            help="Debug mode, prints out lot of garbage", dest="debug")
parser.add_option("-s", "--server", dest="server",
            help="MX server to check")

(options, args) = parser.parse_args()

if not options.server :
    parser.error("Server is mandatory")
    sys.exit(3)

debug = options.debug

#######  Main ###############
Logger.info('Starting MX validation for %s'%(options.server))
page = mechanize.Browser()
page.open(base_url)

assert page.viewing_html()

# Fills form and submit
page.select_form(nr=0)
page["IP"] = options.server
response = page.submit()

if debug : Logger.debug("Getting data")
# Get result page
html = response.get_data()
   
# Parse results and retrieve images url
parser = DnsblParser(base_url)
if debug : Logger.debug('Feeding')
parser.feed(html)

# Check MX reputation
status = BlValidator.validate_parallel(parser.bl_list)

# Prints out result
if status :
    sys.stdout.write('OK\n')
    sys.exit(0)
else :
    sys.stdout.write('ERROR, check %s\n' % (base_url))
    sys.exit(2)
