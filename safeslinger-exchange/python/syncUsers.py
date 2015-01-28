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


class SyncUsers(webapp.RequestHandler):
   
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

        minlen = 4 + 4 + 4 + 4 + 4
                
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

        usrids = []
        usrid = (struct.unpack("!i", data[0:4]))[0]
        usridlink = (struct.unpack("!i", data[4:8]))[0]
        numEntry = (struct.unpack("!i", data[8:12]))[0]
        data = data[12:]
        expectedsize = 4 + 4 + 4 + 4 + (4 * numEntry)

        # append enough entries to hold the expected data
        while numEntry > len(usrids):
            usrids.append(struct.unpack("!i", data[0:4])[0])
            data = data[4:]
 
        # client version check
        if client < INT_VERCLIENT:
            self.resp_simple(0, ('Client version mismatch; %s required.  Download latest client release first.' % STR_VERCLIENT))
            return        

        postSig = False
        if size > expectedsize:
            postSig = True
                    
        # verify you have an existing user
        query = member.Member.all()
        query.filter('usr_id =', usrid)
        num = query.count()
        
        # user exists
        if num == 1:
            mem = query.get()
            
            # commit to group number
            if postSig:            
                mem.usr_id_link = usridlink
                mem.put()
                key = mem.key()
                if not key.has_id_or_name():
                    self.resp_simple(0, 'Unable to update user.')
                    return

            # not posting signature, one must exist
            else:
                if mem.commitment == None:
                    self.resp_simple(0, 'Request was formatted incorrectly.')
                    return

            # get the entries for the group
            query = member.Member.all()
            query.filter('usr_id_link =', usridlink)
            mems = query.fetch(1000)

            # version
            self.response.out.write('%s' % struct.pack('!i', server))

            # lowest client version
            q = member.Member.all()
            q.filter('usr_id_link =', usridlink)
            m = q.fetch(1000)
            low_client = self.getLowestVersion(m)
            self.response.out.write('%s' % struct.pack('!i', low_client))

            # grand total
            num = 0
            for mem in mems:
                if mem.commitment != None:
                    num = num + 1
            
            self.response.out.write('%s' % struct.pack('!i', num))
      
            # add delta ids total
            num = 0
            for mem in mems:
                posted = False
                for known in usrids:
                    if known == mem.usr_id:
                        posted = True                    
                if (not posted) & (mem.commitment != None):
                    num = num + 1
            
            self.response.out.write('%s' % struct.pack('!i', num))
    
            for mem in mems:
                posted = False
                for known in usrids:
                    if known == mem.usr_id:
                        posted = True                    
                if (not posted) & (mem.commitment != None):
                    length = str.__len__(mem.commitment)
                    self.response.out.write('%s%s' % (struct.pack('!ii', mem.usr_id, length), mem.commitment))
        
        else:
            self.resp_simple(0, ' user %i does not exist' % (usrid))
            return       
        

    def resp_simple(self, code, msg):
        self.response.out.write('%s%s' % (struct.pack('!i', code), msg))
    

    def getLowestVersion(self, mems):
        # get lowest available version
        INT_VERCLIENT = 0x01060000
        lowest = 0
        for mem in mems:
            if mem.client_ver != None:    
                cur = mem.client_ver                                
            else:
                cur = INT_VERCLIENT  # default
                
            if lowest == 0:
                lowest = cur  # needs a starting point
            
            if cur < lowest:
                lowest = mem.client_ver                
                
        return lowest
    

def main():
    application = webapp.WSGIApplication([('/syncUsers', SyncUsers),
                                      ('/syncUsers_1_2', SyncUsers),
                                     ],
                                     debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()

