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

import cgi
import datetime
import os

from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app

import airshipAuthToken
import c2dmAuthToken
import loginGoogle


class MainPage(webapp.RequestHandler):
    def get(self):
        user = users.get_current_user()

        # only admins registered with this app can request to store authentication token for the service
        if users.is_current_user_admin():
            
            STR_VERSERVER = '01060000'
            CURRENT_VERSION_ID = os.environ.get('CURRENT_VERSION_ID', STR_VERSERVER)
            isProd = CURRENT_VERSION_ID[8:9] == 'p'
            isTest = CURRENT_VERSION_ID[8:9] == 't'
            
            self.response.out.write("""
              <html>
                <body>
                  SafeSlinger Administrator Tasks<br>
                  <br>

                  Administrator: %s (%s)<br>
                  Server Version: %s<br>
                  Server is test: %s<br>
                  Server is production: %s<br>
                  <br>

                  C2DM Service Authorization Login Cache<br>
                  <form action="/c2dmLogin" method="post">                    
                      C2DM Registered Email: <input type="text" name="username" size="25" /><br />
                      C2DM Registered Password: <input type="password" name="password" size="25" /><br />
                      C2DM Reason: <textarea name="reason" rows="3" cols="60"></textarea><
                      <div align="left">
                        <p><input type="submit" value="Request C2DM Auth Token" /></p>
                      </div>
                  </form>
                 <br>

                 Urban Airship Service Authorization Update Cache<br>
                 <form action="/airshipLogin" method="post">                    
                    UA Application Key: <input type="text" name="appkey" size="60" /><br />
                    UA Application Secret: <input type="text" name="appsecret" size="60" /><br />
                    UA Reason: <textarea name="reason" rows="3" cols="60"></textarea><
                    <div align="left">
                      <p><input type="submit" name="submittest" value="Submit TEST Urban Airship" /></p>
                      <p><input type="submit" name="submitprod" value="Submit PROD Urban Airship" /></p>
                    </div>
                  </form>
                 <br>

                </body>
              </html>""" % (user.nickname(), user.email(), CURRENT_VERSION_ID, isTest, isProd))
            
        else:
            self.redirect(users.create_login_url(self.request.uri))

class AirshipLogin(webapp.RequestHandler):
    def post(self):
        user = users.get_current_user()

        # only admins registered with this app can request to store authentication token for the service
        if users.is_current_user_admin():

            appKey = self.request.get('appkey')
            appSecret = self.request.get('appsecret')
            comments = self.request.get('reason')
            user = users.get_current_user()
    
            if self.request.get('submitprod'):
                lookup = 'production';
            else:
                lookup = 'test';
                
            
            # grab latest proper auth token from our cache
            query = airshipAuthToken.AirshipAuthToken.all()
            query.filter('lookuptag =', lookup)
            num = query.count()
        
            # store result, updating old one first
            if num == 1:
                tokenStore = query.get()
                tokenStore.appkey = appKey
                tokenStore.appsecret = appSecret
                tokenStore.username = user.email()
                tokenStore.comment = comments
            else:            
                tokenStore = airshipAuthToken.AirshipAuthToken(appkey=appKey, appsecret=appSecret, username=user.email(), comment=comments, lookuptag=lookup)

            tokenStore.put()
            key = tokenStore.key()
            insertSuccess = True
            if not key.has_id_or_name():
                insertSuccess = False
    
            # display result
            self.response.out.write('<html><body>')
            self.response.out.write('UA Updated Lookup Tag: ')
            self.response.out.write(cgi.escape(lookup))
            self.response.out.write('<br>')
            self.response.out.write('UA App Key: ')
            self.response.out.write(cgi.escape(appKey))
            self.response.out.write('<br>')
            self.response.out.write('UA App Secret: ')
            self.response.out.write(cgi.escape(appSecret))
            self.response.out.write('<br>')
            self.response.out.write('Comments: ')
            self.response.out.write(cgi.escape(comments))
            self.response.out.write('<br>')
            self.response.out.write('Update Result: ')
            if insertSuccess:
                self.response.out.write('Success')
            else:
                self.response.out.write('Failed')
            self.response.out.write('</body></html>')
            
        else:
            self.redirect(users.create_login_url(self.request.uri))


class C2dmLogin(webapp.RequestHandler):
    def post(self):
        user = users.get_current_user()

        # only admins registered with this app can request to store authentication token for the service
        if users.is_current_user_admin():

            # request token
            clientAuthFactory = loginGoogle.GoogleLoginTokenFactory()
            clientAuthFactory.email = self.request.get('username')
            clientAuthFactory.password = self.request.get('password')
            comments = self.request.get('reason')
            clientAuth = clientAuthFactory.getToken()
            user = users.get_current_user()
    
            # store result
            tokenStore = c2dmAuthToken.C2dmAuthToken(token=clientAuth, username=user.email(), comment=comments)
            tokenStore.put()
            key = tokenStore.key()
            insertSuccess = True
            if not key.has_id_or_name():
                insertSuccess = False
    
            # display result
            self.response.out.write('<html><body>')
            self.response.out.write('C2DM Registered Account: ')
            self.response.out.write(cgi.escape(self.request.get('username')))
            self.response.out.write('<br>')
            self.response.out.write('User Requesting Token: ')
            self.response.out.write(cgi.escape(user.email()))
            self.response.out.write('<br>')
            self.response.out.write('Comments: ')
            self.response.out.write(cgi.escape(comments))
            self.response.out.write('<br>')
            self.response.out.write('Auth Result: ')
            if insertSuccess:
                self.response.out.write(cgi.escape(clientAuth))
            else:
                self.response.out.write('Failed')
            self.response.out.write('</body></html>')        

        else:
            self.redirect(users.create_login_url(self.request.uri))


application = webapp.WSGIApplication(
                                     [('/admin', MainPage),
                                      ('/c2dmLogin', C2dmLogin),
                                      ('/airshipLogin', AirshipLogin)],
                                     debug=True)

def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()

