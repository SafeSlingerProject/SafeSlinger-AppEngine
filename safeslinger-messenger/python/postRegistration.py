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

from __future__ import with_statement

import base64
import logging
import os
import struct

from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from google.appengine.ext import webapp
from google.appengine.ext.webapp import util

import registration


class PostRegistration(webapp.RequestHandler):

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
            logging.debug("in body '%s'" % data)
            logging.debug("in size %d" % size)
            self.resp_simple(0, 'Request was formatted incorrectly.')
            return

        # unpack all incoming data
        client = (struct.unpack("!i", data[0:4]))[0]

        # client version check
        if client < INT_VERCLIENT:
            self.resp_simple(0, ('Client version mismatch; %s required.  Download latest client release first.' % STR_VERCLIENT))
            return

        server = int(CURRENT_VERSION_ID[0:8], 16)

        # init
        submissionAuth = None
        submissionType = 1

        # unpack all incoming data, skip client version 
        pos = 4        

        lenkeyid = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
        pos = pos + 4
        keyId = data[pos:(pos + lenkeyid)]
        pos = pos + lenkeyid

        lensubtok = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
        pos = pos + 4
        submissionToken = str(data[pos:(pos + lensubtok)])
        pos = pos + lensubtok

        if lensubtok >= 32:  # 256-bit original SHA-3 minimum, before base-64 encoding
            submissionAuth = submissionToken
            submissionType = 1  # version 1 of authentication

        lenregid = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
        pos = pos + 4
        registrationId = str(data[pos:(pos + lenregid)])
        pos = pos + lenregid

        devtype = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
        pos = pos + 4
        
        # additional verifying for self signing
        if size > pos:  # still has data
            lennonce = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
            pos = pos + 4
            nonce = str(data[pos:(pos + lennonce)])
            pos = pos + lennonce
            
            lenpubkey = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
            pos = pos + 4
            pubkey = str(data[pos:(pos + lenpubkey)])
            pos = pos + lenpubkey
            plain_pos = pos
            
            sig_len = (struct.unpack("!i", data[pos:(pos + 4)]))[0]
            pos = pos + 4
            sig = data[pos:(pos + sig_len)]
            pos = pos + sig_len
            
            # signature verification
            if lenpubkey > 0:
                # load RSA public key
                rsa_key = RSA.importKey(base64.decodestring(pubkey))
                # verify signature
                h = SHA.new()
                h.update(data[:plain_pos])
                verifier = PKCS1_v1_5.new(rsa_key)
                if verifier.verify(h, sig):
                    submissionAuth = pubkey
                    submissionType = 2  # version 2 of authentication
                    logging.debug('The signature is authentic. Registration continues.')
                else:
                    logging.error('The signature is not authentic. Registration stops.')
                    return
      
        # REGISTRATION STORAGE =============================================
        # check if registration needs to be authenticated before insertion or update
        query = registration.Registration.all().order('-inserted')
        query.filter('key_id =', keyId)
        num = query.count()

        # key_id exists, submissionAuth must match
        if num >= 1:            
            reg_old = query.get()  # only want the oldest        

            # follow update logic
            updateOld = False
            if submissionType > reg_old.submission_type:
                updateOld = True  # authentication type upgraded
            elif submissionAuth == reg_old.submission_token:
                updateOld = True  # previous authentication matches
                
            # token is authentic
            if updateOld:
                # if record exists, update it
                if registrationId == reg_old.registration_id:
                    # update time and active status only
                    reg_old.active = True
                    reg_old.submission_token = submissionAuth
                    reg_old.submission_type = submissionType
                    reg_old.put()
                    key = reg_old.key()
                    if not key.has_id_or_name():
                        self.resp_simple(0, 'Unable to update registration.')
                        return       
                # if record missing, insert it
                else:
                    reg_new = registration.Registration(key_id=keyId, submission_token=submissionAuth, submission_type=submissionType, registration_id=registrationId, notify_type=devtype, client_ver=client)        
                    reg_new.put()
                    key = reg_new.key()
                    if not key.has_id_or_name():
                        self.resp_simple(0, 'Unable to create new registration.')
                        return       

            # token not authentic, just log it
            else:
                logging.info('Registration failed: submission token in table %s, not matching submitted submission token %s' % (reg_old.submission_token[0:30], submissionAuth[0:30]))

        # key_id is new, submissionAuth can be inserted instantly
        else:         
            reg_new = registration.Registration(key_id=keyId, submission_token=submissionAuth, submission_type=submissionType, registration_id=registrationId, notify_type=devtype, client_ver=client)        
            reg_new.put()
            key = reg_new.key()
            if not key.has_id_or_name():
                self.resp_simple(0, 'Unable to create new registration.')
                return       

        # SEND RESPONSE =========================================        
        # this client background process does not need to log back insert/update errors to the client
        self.response.out.write('%s' % struct.pack('!i', server))
            

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

    application = webapp.WSGIApplication([('/postRegistration', PostRegistration)],
                                         debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
