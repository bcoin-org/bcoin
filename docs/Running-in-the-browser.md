Because bcoin is written in node.js, it is capable of being browserified.

## Running a full node in the browser

``` bash
$ cd ~/bcoin
$ make # Browserify bcoin
$ node browser/server.js 8080 # Start up a simple webserver and websocket->tcp bridge
$ chromium http://localhost:8080
```

You should see something like this: http://i.imgur.com/0pWySyZ.png

This is a simple proof-of-concept. It's not a pretty interface. I hope to see
others doing something far more interesting. A browser extension may be better:
the chrome extension API exposes raw TCP access.