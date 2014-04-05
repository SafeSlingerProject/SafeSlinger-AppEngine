# The MIT License (MIT)
# 
# Copyright (c) 2010-2014 Carnegie Mellon University
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import with_statement

import base64
import logging
import os
import struct

from google.appengine.api import urlfetch
from google.appengine.api.urlfetch_errors import DeadlineExceededError
from google.appengine.ext import webapp
from google.appengine.ext.webapp import util

import airshipAuthToken
from django.utils import simplejson


class checkStatus(webapp.RequestHandler):
 
    def post(self): 
        minlen = 4 + 4 + 20                
        STR_VERSERVER = '01060000'
        INT_VERCLIENT = 0x01060000
        STR_VERCLIENT = '1.6'

        # must be able to query for https
        if not os.environ.has_key('HTTPS'):
            self.resp_simple(0, 'HTTPS environment variable not found')
            return

        # must be able to query for server version
        if not os.environ.has_key('CURRENT_VERSION_ID'):
            self.resp_simple(0, 'CURRENT_VERSION_ID environment variable not found')
            return

        HTTPS = os.environ.get('HTTPS', 'off')
        CURRENT_VERSION_ID = os.environ.get('CURRENT_VERSION_ID', STR_VERSERVER)

        # SSL must be enabled
        if HTTPS.__str__() != 'on':
            self.resp_simple(0, 'Secure socket required.')
            return

        # get the data from the post
        self.response.headers['Content-Type'] = 'application/octet-stream'
        data = self.request.body        
        size = str.__len__(data)

        # size check
        if size < minlen:
            self.resp_simple(0, 'Request was formatted incorrectly.')
            return

        # unpack all incoming data
        client = (struct.unpack("!i", data[0:4]))[0]
        data = data[4:]

        # client version check
        if client < INT_VERCLIENT:
            self.resp_simple(0, ('Client version mismatch; %s required.  Download latest client release first.' % STR_VERCLIENT))
            return

        server = int(CURRENT_VERSION_ID[0:8], 16)
        isProd = CURRENT_VERSION_ID[8:9] == 'p'

        # unpack all incoming data
        pos = 0
        
        lenrid = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
        pos = pos + 4
        retrievalToken = data[pos:(pos + lenrid)]
        pos = pos + lenrid
        
        devtype = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
        
        # APPLE PUSH MSG ===============================================================================

        # grab latest proper auth token from our cache
        query = airshipAuthToken.AirshipAuthToken.all()
        if isProd:
            query.filter('lookuptag =', 'production')
        else:
            query.filter('lookuptag =', 'test')

        items = query.fetch(1)  # only want the latest
        num = 0
        for token in items:
            # Application Key/Secret from UrbanAirship -> App Menu -> App Details to Display
            UA_API_APPLICATION_KEY = token.appkey 
            UA_API_APPLICATION_MASTER_SECRET = token.appsecret
            num = num + 1
                    
        pingurl = 'https://go.urbanairship.com/api/device_tokens/'
        auth_string = 'Basic ' + base64.encodestring('%s:%s' % (UA_API_APPLICATION_KEY, UA_API_APPLICATION_MASTER_SECRET))[:-1]
        
        if devtype == 2:
            # test an iOS token status
            pingurl = pingurl + str(retrievalToken) + '/'
            
            # attempt to retrieve status using exponential backoff timeout
            timeout_sec = 2
            timeout_tot = 0
            url_retry = True
            while url_retry and timeout_tot < 60:
                try:
                    timeout_tot += timeout_sec
                    ua_data = urlfetch.fetch(pingurl, headers={'content-type': 'application/json', 'authorization' : auth_string}, payload=None, method=urlfetch.GET, deadline=timeout_sec)
                    url_retry = False
                except DeadlineExceededError:
                    logging.info("DeadlineExceededError - timeout: " + str(timeout_sec) + ", url: " + pingurl)
                    timeout_sec *= 2
            # received no status, and our retries have exceeded the timeout
            if url_retry:
                self.response.out.write('%s' % struct.pack('!i', server))
                self.response.out.write('%s Unknown status.' % struct.pack('!i', -1))
                return
            # received status from fetch, handle appropriately
            if ua_data.status_code == 200:
                tokenstatus = simplejson.loads(ua_data.content)
                if tokenstatus.get('active'):
                    self.response.out.write('%s' % struct.pack('!i', server))
                    self.response.out.write('%s Active status.' % struct.pack('!i', 1))
                else:
                    self.resp_simple(0, 'Error=InvalidRegistration')
            else:
                self.response.out.write('%s' % struct.pack('!i', server))
                self.response.out.write('%s Unknown status.' % struct.pack('!i', -1))


    def resp_simple(self, code, msg):
        self.response.out.write('%s%s' % (struct.pack('!i', code), msg))

def main():
    application = webapp.WSGIApplication([('/checkStatus', checkStatus)],
                                         debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
