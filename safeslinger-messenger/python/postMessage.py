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

from google.appengine.api import files, urlfetch
from google.appengine.api.urlfetch_errors import DeadlineExceededError
from google.appengine.ext import webapp
from google.appengine.ext.webapp import util

import airshipAuthToken
import c2dm
import c2dmAuthToken
from django.utils import simplejson
import filestorage


class PostMessage(webapp.RequestHandler):

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

        # add notify type generically in 1.7 for backward-compatibility
        if len(data) >= (pos + 4):
            devtype = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
        else:
            if lenrtok <= 64:
                devtype = 2  # apns was shorter
            else:
                devtype = 1  # c2dm were longer
                      
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

        # BEGIN NOTIFY TYPES ===============================================================================

        if devtype == 0:
            self.resp_simple(0, 'User has no push registration id.')
            return

        # ANDROID PUSH MSG ===============================================================================
        elif devtype == 1: 
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

        # APPLE PUSH MSG ===============================================================================
        elif devtype == 2: 
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
                
            url = 'https://go.urbanairship.com/api/push/'
            auth_string = 'Basic ' + base64.encodestring('%s:%s' % (UA_API_APPLICATION_KEY, UA_API_APPLICATION_MASTER_SECRET))[:-1]
    
            logging.info("retrievalId: " + retrievalId)
            logging.info("recipientToken: " + recipientToken)
    
            body = simplejson.dumps({"aps": {"badge": "+1", "alert" : { "loc-key" : "title_NotifyFileAvailable" }, "nonce": retrievalId, "sound": "default"}, "device_tokens": [recipientToken]})
            
            # attempt to send push message, using exponential backoff timeout
            timeout_sec = 2
            timeout_tot = 0
            url_retry = True
            while url_retry and timeout_tot < 60:
                try:
                    timeout_tot += timeout_sec
                    ua_data = urlfetch.fetch(url, headers={'content-type': 'application/json', 'authorization' : auth_string}, payload=body, method=urlfetch.POST, deadline=timeout_sec)
                    url_retry = False
                except DeadlineExceededError:
                    logging.info("DeadlineExceededError - timeout: " + str(timeout_sec) + ", url: " + url)
                    timeout_sec *= 2
            # received no status, and our retries have exceeded the timeout
            if url_retry:
                self.resp_simple(0, 'Error=PushServiceFail')
                return
            # received status from fetch, handle appropriately
            if ua_data.status_code == 200:
                logging.info("Remote Notification successfully sent to UrbanAirship " + str(ua_data.status_code) + " " + str(ua_data.content))
            elif ua_data.status_code == 500:
                logging.error("Error: 500, Internal Server Error or Urban Service Unavailable. Our system failed. If this persists, contact support..")
                self.resp_simple(0, 'Error=PushServiceFail')
                return
            else:
                logging.error("UrbanAirship Error: ." + str(ua_data.status_code))
                self.resp_simple(0, 'Error=PushNotificationFail')
                return
            
            respMessage = struct.pack('!i', ua_data.status_code)

        # NOT IMPLEMENTED PUSH TYPE ===============================================================================
        else: 
            self.resp_simple(0, ('Sending to device type %i not yet implemented.' % devtype))
            return

        # END NOTIFY TYPES ===============================================================================
        
        # SUCCESS RESPONSE ===============================================================================
        # file inserted and message sent
        self.response.out.write('%s' % struct.pack('!i', server))
        self.response.out.write('%s Success: %s' % (struct.pack('!i', 1), respMessage))
            

    def resp_simple(self, code, msg):
        self.response.out.write('%s%s' % (struct.pack('!i', code), msg))


def main():
    application = webapp.WSGIApplication([('/postMessage', PostMessage),
                                          ('/postFile1', PostMessage),
                                          ('/postFile2', PostMessage)],
                                         debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
