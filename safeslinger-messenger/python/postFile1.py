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

from google.appengine.api import files
from google.appengine.ext import webapp
from google.appengine.ext.webapp import util

import c2dm
import c2dmAuthToken
import filestorage


class PostFile(webapp.RequestHandler):

    def post(self): 
        minlen = 4 + 4 + 20 + 4 + 1 + 4 + 1        
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
        retrievalId = base64.encodestring(data[pos:(pos + lenrid)])
        pos = pos + lenrid

        lenrtok = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
        pos = pos + 4
        recipientToken = str(data[pos:(pos + lenrtok)])
        pos = pos + lenrtok

        lenmd = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
        pos = pos + 4
        msgData = data[pos:(pos + lenmd)]
        pos = pos + lenmd

        lenfd = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
        pos = pos + 4
        fileData = data[pos:(pos + lenfd)]
        pos = pos + lenfd
                      
        # FILE STORAGE ===============================================================================
        if lenfd > 0:
            DATASTORE_LIMIT = 1000000  # max bytes for datastore storage
            # determine which storage method to use....
            if lenfd <= DATASTORE_LIMIT:
                # add file to data base...
                file = filestorage.FileStorage(id=retrievalId, data=fileData, msg=msgData, client_ver=client, sender_token=recipientToken)
            else:
                # Create the file
                blobName = files.blobstore.create(mime_type='application/octet-stream')        
                # Open the file and write to it
                with files.open(blobName, 'a') as f:
                    pos = 0
                    bdata = str(fileData[pos:(pos + 65536)])
                    pos = pos + 65536
                    while bdata:
                        f.write(bdata)
                        bdata = str(fileData[pos:(pos + 65536)])
                        pos = pos + 65536
                # Finalize the file. Do this before attempting to read it.
                files.finalize(blobName)        
                # Get the file's blob key
                blob_key = str(files.blobstore.get_blob_key(blobName)) 
                # This will only work if the file is less than 10MB. Otherwise, we send a 
                # correctly encoded multipart form and use the regular blobstore upload method. 
                file = filestorage.FileStorage(id=retrievalId, blobkey=blob_key, msg=msgData, client_ver=client, sender_token=recipientToken)
        else:
            file = filestorage.FileStorage(id=retrievalId, msg=msgData, client_ver=client, sender_token=recipientToken)
        
        # save file retrieval data and keys to datastore
        file.put()
        key = file.key()
        if not key.has_id_or_name():
            self.resp_simple(0, 'Unable to create new message.')
            return       

        # ANDROID PUSH MSG ===============================================================================
        
        # send push message to Android service...
        sender = c2dm.C2DM()
        sender.registrationId = recipientToken
        sender.collapseKey = retrievalId
        sender.fileid = retrievalId
        
        # grab latest auth token from our cache
        query = c2dmAuthToken.C2dmAuthToken.all().order('-inserted')
        items = query.fetch(1)  # only want the latest
        num = 0
        for token in items:
            sender.clientAuth = token.token
            num = num + 1

        if num != 1:
            logging.error('One C2DM authorization token expected, %i found.' % num)
            self.resp_simple(0, 'Error=PushNotificationFail')
            return

        respMessage = sender.sendMessage()
        
        if respMessage.find('Error') != -1:
            self.resp_simple(0, (' %s') % respMessage)
            return

        # SUCCESS RESPONSE ===============================================================================
        # file inserted and message sent
        self.response.out.write('%s' % struct.pack('!i', server))
        self.response.out.write('%s Success: %s' % (struct.pack('!i', 1), respMessage))
            

    def resp_simple(self, code, msg):
        self.response.out.write('%s%s' % (struct.pack('!i', code), msg))


def main():
    application = webapp.WSGIApplication([('/postFile1', PostFile)],
                                         debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
