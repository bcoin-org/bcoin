# bweb

A web server.

## Usage

``` js
const bweb = require('bweb');
const server = bweb.server({
  port: 8080,
  sockets: true
});

server.on('socket', (socket) => {
  // A bsock socket
  socket.fire('hello', 'world');
});

server.use(server.bodyParser());
server.use(server.cookieParser());
server.use(server.jsonRPC());
server.use(server.router());
server.use('/static', server.fileServer(__dirname));

server.get('/', async (req, res) => {
  res.html(200, '<a href="/static">static</a>');
});

server.open();
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017, Christopher Jeffrey (MIT License).

See LICENSE for more info.
