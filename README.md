[![Build Status](https://travis-ci.org/SafeSlingerProject/SafeSlinger-AppEngine.png?branch=master)](https://travis-ci.org/SafeSlingerProject/SafeSlinger-AppEngine)

Quick Links:
[Downloads](https://github.com/SafeSlingerProject/SafeSlinger-Media/wiki/Platforms),
[Wiki](https://github.com/SafeSlingerProject/SafeSlinger-Media/wiki),
[Support, Translations, Contributing](https://github.com/SafeSlingerProject/SafeSlinger-Media/wiki/Contributing),
[Research Paper](http://sparrow.ece.cmu.edu/group/pub/farb_safeslinger_mobicom2013.pdf),
[Project Website](http://www.cylab.cmu.edu/safeslinger)

App Engine Server Projects
=======

- **/safeslinger-demo/python** Contains a demo SafeSlinger Exchange server you can implement with Google App Engine for your own projects.
- **/safeslinger-exchange/python** Contains the production server source code for the Sling Keys process to securely exchange keys when using the SafeSlinger Messenger application.
- **/safeslinger-messenger/python** Contains the production server source code for sending and receiving messages for the [Android SafeSlinger Messenger](http://play.google.com/store/apps/details?id=edu.cmu.cylab.starslinger) and [iOS SafeSlinger Messenger](http://itunes.apple.com/app/safeslinger/id493529867) client applications.

Build Your Own Secure Exchange Server
========
To build your own secure exchange server using App Engine:

1. First, go to the Google App Engine [Create Application](http://appengine.google.com/start/createapp) pages to create a new server app. Under 'Application Identifier' use your own identifier: **________.appspot.com**. Do **NOT** use myappengine.appspot.com or slinger-dev.appspot.com, as they are both taken.
3. Under 'Application Title' use the name of your own application.
4. Under 'Authentication Options (Advanced)' choose **Open to all Google Accounts users**.
5. Under 'Storage Options (Advanced)' choose **High Replication**.
6. Click on the **Create Application** button.
7. Next, edit the source code from the **/safeslinger-demo/python** folder to use the new application identifier you just created in the `app.yaml` file. Change the line `application: slinger-demo` to `application: `**mynewapplicationidentifierfromstep1**. 
8. Deploy your new application after reading up on [Uploading Your Application](http://developers.google.com/appengine/docs/python/gettingstartedpython27/uploading).

License
=======
	The MIT License (MIT)

	Copyright (c) 2010-2015 Carnegie Mellon University

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
