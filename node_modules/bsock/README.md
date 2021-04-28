# bsock

A minimal websocket-only implementation of the socket.io protocol, complete
with ES6/ES7 features.

## Usage

``` js
const http = require('http');
const bsock = require('bsock');
const io = bsock.createServer();
const server = http.createServer();

io.attach(server);

io.on('socket', (socket) => {
  // Bind = listen for event
  socket.bind('bar', (data) => {
    console.log('Received bar: %s.', data.toString('ascii'));
  });
  // Hook = listen for call (event + ack)
  socket.hook('foo', async () => {
    return Buffer.from('bar');
  });
});

server.listen(8000);

const socket = bsock.connect(8000);

socket.on('connect', async () => {
  console.log('Calling foo...');
  // Call = emit event and wait for ack
  const data = await socket.call('foo');
  console.log('Response for foo: %s.', data.toString('ascii'));
  console.log('Sending bar...');
  // Fire = emit event
  socket.fire('bar', Buffer.from('baz'));
});
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017, Christopher Jeffrey (MIT License).

See LICENSE for more info.
