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

from google.appengine.ext import db, webapp
from google.appengine.ext.webapp import util

import registration


class CleanUpReg(webapp.RequestHandler):
    
    def get(self):

        # execute only when request comes from appengine.com        
        if self.request.headers.get('X-AppEngine-Cron') == 'true':
    
            query = registration.Registration.all().order('key_id').order('-inserted')
            num = 0
            dup_regs = []
            keys = set()
    
            # find duplicated entries in all registrations, keeping all unique most recent ones.
            duplicate = 0
            lastKeyId = None
            lastRegId = None
            for r in query:
                num += 1
                keys.add(r.key_id)
                if r.registration_id == lastRegId:
                    if r.key_id == lastKeyId:
                        dup_regs.append(r)
                        duplicate += 1
                
                lastRegId = r.registration_id
                lastKeyId = r.key_id
            
            # remove duplicates, record our action
            db.delete(dup_regs)
            logging.info('cleanup: duplicate reg=%i (total: %i regs, %i keys)' % (duplicate, num, keys.__len__()))

def main():
    application = webapp.WSGIApplication([('/cron/cleanup_reg', CleanUpReg)],
                                         debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
