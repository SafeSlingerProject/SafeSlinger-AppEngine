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
import urllib
import urllib2

import c2dmAuthToken


class C2DM():

    def __init__(self):

        self.url = 'https://android.apis.google.com/c2dm/send'

        self.clientAuth = None
        self.registrationId = None
        self.collapseKey = None
        self.fileid = None

    def sendMessage(self):
        if self.registrationId == None:
            return 'Error: missing registrationId'
        if self.collapseKey == None:
            return 'Error: missing collapseKey'

        # Build payload
        values = {'registration_id' : self.registrationId,
                  'collapse_key' : self.collapseKey,
                  'data.msgid': self.fileid,
                  }        

        # Build request
        headers = {'Authorization': 'GoogleLogin auth=' + self.clientAuth}
        data = urllib.urlencode(values)
        request = urllib2.Request(self.url, data, headers)

        # Post
        try:
            response = urllib2.urlopen(request)
            # see if we have a new token to use or not...
            if 'Update-Client-Auth' in response.headers:
                tokenStore = c2dmAuthToken.C2dmAuthToken(token=response.headers['Update-Client-Auth'], username='Update-Client-Auth', comment='Update-Client-Auth in response')
                tokenStore.put()
                key = tokenStore.key()
                if not key.has_id_or_name():
                    logging.error("C2DM HTTP Error: c2dm token insert failed for " + response.headers['Update-Client-Auth'])

            responseAsString = response.read()
            return responseAsString
        except urllib2.HTTPError, e:
            logging.error("C2DM HTTP Error: ." + str(e))
            if e.code == 500:
                return 'Error=PushServiceFail'
            else:
                return 'Error=PushNotificationFail'
