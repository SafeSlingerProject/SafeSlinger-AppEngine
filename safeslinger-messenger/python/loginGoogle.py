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

import urllib
import urllib2


class GoogleLoginTokenFactory():
    _token = None 

    def __init__(self):
        self.url = 'https://www.google.com/accounts/ClientLogin'
        self.accountType = 'GOOGLE'
        self.email = ''  # role account is submitted externally
        self.password = ''  # password is submitted externally
        self.source = 'edu.cmu.cylab.starslinger'
        self.service = 'ac2dm'

    def getToken(self):
        if self._token is None:

            # Build payload
            values = {'accountType' : self.accountType,
                      'Email' : self.email,
                      'Passwd' : self.password,
                      'source' : self.source,
                      'service' : self.service}

            # Build request
            data = urllib.urlencode(values)
            request = urllib2.Request(self.url, data)

            # Post
            response = urllib2.urlopen(request)
            responseAsString = response.read()

            # Format response
            responseAsList = responseAsString.split('\n')

            self._token = responseAsList[2].split('=')[1]

        return self._token
