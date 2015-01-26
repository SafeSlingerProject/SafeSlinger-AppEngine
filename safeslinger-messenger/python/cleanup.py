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

import datetime

from google.appengine.ext import blobstore, db, webapp
from google.appengine.ext.webapp import util

import c2dmAuthToken
import filestorage


class CleanUp(webapp.RequestHandler):
    
    def get(self):

        # execute only when request comes from appengine.com        
        if self.request.headers.get('X-AppEngine-Cron') == 'true':
    
            # delete messages older than 24 hours
            timeout = 60 * 60 * 24  # 24 hours
            now = datetime.datetime.now()        
            deltaMem = datetime.timedelta(seconds=timeout) 
            thenMem = now - deltaMem        
            fquery = db.Query(filestorage.FileStorage).filter('inserted <', thenMem)
            files = []
    
            for f in fquery:
                blob_key = f.blobkey
                # delete blobstore item if exists
                if blob_key:
                    blobstore.delete(f.blobkey)
                # delete datastore item
                files.append(f)
            
            db.delete(files)
    
            # delete old authorization tokens if there are more than 10
            tquery = db.Query(c2dmAuthToken.C2dmAuthToken).order('-inserted')
            tokens = []
            i = 0
            for t in tquery:
                if i >= 10:
                    tokens.append(t)
                i = i + 1
            
            db.delete(tokens)

def main():
    application = webapp.WSGIApplication([('/cron/cleanup', CleanUp)],
                                         debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
