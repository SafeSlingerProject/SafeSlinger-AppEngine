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

import base64
import json
import logging
import os
import random
import struct

from google.appengine.ext import webapp
from google.appengine.ext.webapp import util

import member


class AssignUser(webapp.RequestHandler):
   
    isJson = False
   
    def post(self):
        self.response.headers.add_header("Access-Control-Allow-Origin", "*")
        
        header = self.request.headers['Content-Type']
        logging.debug("Content-Type: '%s'" % header)
        if (str(header).startswith('text/plain')):
            self.isJson = True
            # set response to json
            self.response.headers['Content-Type'] = 'text/plain'
            data_dict = json.loads(self.request.body)
        else:
            self.response.headers['Content-Type'] = 'application/octet-stream'
            
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
        data = self.request.body
        logging.debug("in body '%s'" % data)
    
        size = str.__len__(data)
        logging.debug("in size %d" % size)

        if size < minlen:
            self.resp_simple(0, 'Request was formatted incorrectly.')
            return
         
        # unpack all incoming data
        server = int(CURRENT_VERSION_ID[0:8], 16)
        
        if self.isJson:
            client = int(data_dict['ver_client'], 10)
        else:
            client = (struct.unpack("!i", data[0:4]))[0]
        logging.debug("in client %d" % client)
        
        if self.isJson:
            commit = base64.decodestring(data_dict['commit_b64'])
        else:
            commit = data[4:]
        logging.debug("in commitment '%s'" % commit)
 
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
                if str(m.commitment) == str(commit):
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
        mem = member.Member(usr_id=usrid, commitment=commit, client_ver=client)
        mem.put()
        key = mem.key()
        if not key.has_id_or_name():
            self.resp_simple(0, 'Unable to create new user.')
            return       
                              
        # version
        if not self.isJson:
            self.response.out.write('%s' % struct.pack('!i', server))
        logging.debug("out server %i" % server)

        # user id assigned
        if not self.isJson:
            self.response.out.write('%s' % struct.pack('!i', usrid))
        logging.debug("out usrid %i" % usrid)

        if self.isJson:            
            json.dump({"ver_server":str(server), "usrid":str(usrid)}, self.response.out)
        
        
    def resp_simple(self, code, msg):
        if self.isJson:            
            json.dump({"err_code":str(code), "err_msg":str(msg)}, self.response.out)
        else:
            self.response.out.write('%s%s' % (struct.pack('!i', code), msg))
        logging.debug("out error code %i" % code)
        logging.debug("out error msg '%s'" % msg)
    

def main():
    STR_VERSERVER = '01060000'
    CURRENT_VERSION_ID = os.environ.get('CURRENT_VERSION_ID', STR_VERSERVER)
    isProd = CURRENT_VERSION_ID[8:9] == 'p'
    # Set the logging level in the main function
    if isProd:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.DEBUG)

    application = webapp.WSGIApplication([('/assignUser', AssignUser),
                                     ],
                                     debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()

