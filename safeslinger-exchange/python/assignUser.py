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
import random
import struct

from google.appengine.ext import webapp
from google.appengine.ext.webapp import util

import member


class AssignUser(webapp.RequestHandler):
   
    def post(self):
        self.response.headers.add_header("Access-Control-Allow-Origin", "*")

        STR_VERSERVER = '01060000'
        INT_VERCLIENT = 0x01060000
        STR_VERCLIENT = '1.6'

        if not os.environ.has_key('HTTPS'):
            self.resp_simple(0, 'HTTPS environment variable not found')
            return

        if not os.environ.has_key('CURRENT_VERSION_ID'):
            self.resp_simple(0, 'CURRENT_VERSION_ID environment variable not found')
            return

        HTTPS = os.environ.get('HTTPS', 'off')
        CURRENT_VERSION_ID = os.environ.get('CURRENT_VERSION_ID', STR_VERSERVER)
        
        # SSL must be enabled
        if HTTPS.__str__() != 'on':
            self.resp_simple(0, 'Secure socket required.')
            return

        minlen = 4 + 32
                
        # get the data from the post
        self.response.headers['Content-Type'] = 'application/octet-stream'
        data = self.request.body
    
        size = str.__len__(data)

        if size < minlen:
            self.resp_simple(0, 'Request was formatted incorrectly.')
            return
         
        # unpack all incoming data
        server = int(CURRENT_VERSION_ID[0:8], 16)
        client = (struct.unpack("!i", data[0:4]))[0]
        data = data[4:]
 
        # client version check
        if client < INT_VERCLIENT:
            self.resp_simple(0, ('Client version mismatch; %s required.  Download latest client release first.' % STR_VERCLIENT))
            return        

        # assign grouping id number
        num = 1
        while (num > 0):
            # we get the current numbers in the database
            query = member.Member.all()
            num = query.count()

            # we know how many are left in the current range
            if (num >= 999):
                maxUsers = 9999
            elif (num >= 99):
                maxUsers = 999
            else:
                maxUsers = 99

            # we know we can build a set of what remains
            used = []
            for m in query:
                used.append(m.usr_id)
                
                # each commitment must be unique
                if str(m.commitment) == str(data):
                    self.resp_simple(0, 'Request was formatted incorrectly.')
                    return        

            # create a super set of all items from smallest to largest
            # also don't assign 1-10 so that users won't confuse the # of users with the grouping id 
            full = set(xrange(11, maxUsers + 1))
            avail = sorted(full - set(used))   
    
            # we know can get a random number of the remaining range
            # we know what position the random number will be at
            # we know the new number
            r = random.SystemRandom()
            usrid = r.choice(avail)       

            # we check the new number against the database again
            query = member.Member.all()
            query.filter('usr_id =', usrid)
            num = query.count()

            # if number is taken by now, we start over again
            if num > 0:
                logging.info("found duplicate usr_id=" + str(usrid) + ", retrying...")
 
        # return the user id
        mem = member.Member(usr_id=usrid, commitment=data, client_ver=client)
        mem.put()
        key = mem.key()
        if not key.has_id_or_name():
            self.resp_simple(0, 'Unable to create new user.')
            return       
                              
        # version
        self.response.out.write('%s' % struct.pack('!i', server))

        # user id assigned
        self.response.out.write('%s' % struct.pack('!i', usrid))

    def resp_simple(self, code, msg):
        self.response.out.write('%s%s' % (struct.pack('!i', code), msg))
    

def main():
    application = webapp.WSGIApplication([('/assignUser', AssignUser),
                                     ],
                                     debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()

