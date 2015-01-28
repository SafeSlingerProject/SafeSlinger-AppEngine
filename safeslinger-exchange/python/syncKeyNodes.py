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

import os
import struct

from google.appengine.ext import webapp
from google.appengine.ext.webapp import util

import member


class SyncKeyNodes(webapp.RequestHandler):

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

        minlen = 4 + 4
                
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
        usrid = (struct.unpack("!i", data[4:8]))[0]
        data = data[8:]
        expectedsize = 4 + 4

        postKeyNodes = False
        if size > expectedsize:
            usridpost = (struct.unpack("!i", data[0:4]))[0]
            sizeData = (struct.unpack("!i", data[4:8]))[0]
            key_node = (struct.unpack(str(sizeData) + "s", data[8:8 + sizeData]))[0]
            postKeyNodes = True
 
        # client version check
        if client < INT_VERCLIENT:
            self.resp_simple(0, ('Client version mismatch; %s required.  Download latest client release first.' % STR_VERCLIENT))
            return        

        # verify you have an existing group
        query = member.Member.all()
        query.filter('usr_id =', usrid)
        num = query.count()
        
        # requesting user exists
        if num == 1:
            mem = query.get()
            
            # verify...
            if postKeyNodes:
                query = member.Member.all()
                query.filter('usr_id =', usridpost)
                num = query.count()
                # user exists for updating node
                if num == 1:
                    mem_other = query.get()
                    mem_other.key_node = key_node
                    mem_other.put()
                    key = mem_other.key()
                    if not key.has_id_or_name():
                        self.resp_simple(0, 'Unable to update user.')
                        return       
                else:
                    self.resp_simple(0, ' user %i does not exist for update' % (usridpost))
                    return   
                                
            # version
            self.response.out.write('%s' % struct.pack('!i', server))

            # node data
            mem = query.get()
            if mem.key_node != None:
                # n results
                self.response.out.write('%s' % struct.pack('!i', num))
                length = str.__len__(mem.key_node)
                self.response.out.write('%s%s' % (struct.pack('!i', length), mem.key_node))                    
            else:
                # n results
                self.response.out.write('%s' % struct.pack('!i', 0))

        
        else:
            self.resp_simple(0, ' user %i does not exist' % (usrid))
            return      
        

    def resp_simple(self, code, msg):
        self.response.out.write('%s%s' % (struct.pack('!i', code), msg))


def main():
    application = webapp.WSGIApplication([('/syncKeyNodes', SyncKeyNodes),
                                      ('/syncKeyNodes_1_3', SyncKeyNodes),
                                     ],
                                     debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()

