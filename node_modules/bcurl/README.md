# bcurl

A minimal web client.

## Usage

``` js
const bcurl = require('bcurl');

const client = bcurl.client('http://localhost:8080');
const socket = await client.connect();

socket.send('hello', 'world');

// Rest
const json = await client.get('/foobar');
console.log(json);

// JSON-RPC
const json = await client.execute('/', 'method', {});

```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017, Christopher Jeffrey (MIT License).

See LICENSE for more info.
