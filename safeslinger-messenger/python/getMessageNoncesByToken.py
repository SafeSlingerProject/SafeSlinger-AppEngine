# The MIT License (MIT)
# 
# Copyright (c) 2010-2015 Carnegie Mellon University
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

import logging
import os
import struct

from google.appengine.ext import webapp
from google.appengine.ext.webapp import util

import filestorage


class GetMessageNoncesByToken(webapp.RequestHandler):
 
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
            logging.debug("in body '%s'" % data)
            logging.debug("in size %d" % size)
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

        # unpack all incoming data
        pos = 0
        
        lenrtok = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
        pos = pos + 4
        recipientToken = str(data[pos:(pos + lenrtok)])
        pos = pos + lenrtok
        
        # number of recent message nonces the user needs to query
        numquery = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
        pos = pos + 4
        
        # query for file in database
        query = filestorage.FileStorage.all()
        downloaded = False
        query.filter('sender_token =', recipientToken).filter('downloaded = ', downloaded)
        num = query.count()
        items = query.fetch(num)

        # if found package up file and return it
        lenArray = []
        nonceArray = []
        num = 0
        for item in items:
            msgId = item.id
            lenid = str.__len__(msgId)
            lenArray.append(lenid)
            nonceArray.append(msgId)
            num = num + 1

        # not found, send back error message
        if num == 0:            
            self.response.out.write('%s' % struct.pack('!i', server))
            self.response.out.write('%s' % (struct.pack('!i', 1)))
            self.response.out.write('%s' % struct.pack('!i', num))
            return
        else:
            # send out nonce arrays
            self.response.out.write('%s' % struct.pack('!i', server))
            self.response.out.write('%s' % (struct.pack('!i', 1)))
            self.response.out.write('%s' % struct.pack('!i', num))
            idx = 0
            for nonce in nonceArray:
                # logging.debug("nonce: " + nonce)
                self.response.out.write('%s%s' % (struct.pack('!i', lenArray[idx]), nonce))
                idx = idx + 1
    


    def resp_simple(self, code, msg):
        self.response.out.write('%s%s' % (struct.pack('!i', code), msg))
        if code == 0:
            logging.error(msg)

def main():
    STR_VERSERVER = '01060000'
    CURRENT_VERSION_ID = os.environ.get('CURRENT_VERSION_ID', STR_VERSERVER)
    isProd = CURRENT_VERSION_ID[8:9] == 'p'
    # Set the logging level in the main function
    if isProd:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.DEBUG)

    application = webapp.WSGIApplication([('/getMessageNoncesByToken', GetMessageNoncesByToken)],
                                         debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
