# BCoin

**BCoin** is a bitcoin client which implements [BIP-37][1]. It can track
transactions, public keys, and public key hashes (bitcoin addresses) without
saving the entire blockchain to disk. This means you can have a wallet with a
synchronized balance and send and receive payments without keeping track of a
20GB database.

BCoin is implemented in *pure* javascript, and is browserify-able (this means
compiling a binding to an ECDSA library is not even required for node.js).

**NOTE**: BCoin is also in the process of supporting the original (pre-bip37)
satoshi protocol, which will also optionally give the user the ability download
the entire blockchain.

## Example Usage

``` js
var bcoin = require('bcoin');
var net = require('net');

// Standard bitcoin seeds
var seeds = [
  'seed.bitcoin.sipa.be',
  'dnsseed.bluematt.me',
  'dnsseed.bitcoin.dashjr.org',
  'seed.bitcoinstats.com',
  'seed.bitnodes.io',
  'bitseed.xf2.org'
];

var index = 0;
var pool = new bcoin.pool({
  // Number of peers allowed
  size: 32,
  // This function must return a socket that supports the standard
  // node socket model: `write()`, `destroy()` `on('data')`, etc.
  createConnection: function() {
    if (index >= seeds.length) {
      index = 0;
    }

    var addr = seeds[index++];
    var parts = addr.split(':');
    var host = parts[0];
    var port = +parts[1] || 8333;
    var socket = net.connect(port, host);

    socket.on('connect', function() {
      console.log('Connected to %s:%d', host, port);
    });

    return socket;
  },
  // Storage DB for transactions and wallet, must support
  // the levelup `put`/`del`/`createReadStream` methods.
  storage: require('levelup')(process.env.HOME + '/.bcoin', {
    db: require('leveldown'),
    valueEncoding: 'json'
  })
});

// Receive the address of another peer.
pool.on('addr', function(data, peer) {
  var host = data.ipv4 + ':' + data.port;
  if (!~seeds.indexOf(host)) {
    console.log('Found new peer: %s', host);
    seeds.push(host);
  }
});

// Receive a block.
pool.on('block', function(block, peer) {
  var hash = bcoin.utils.revHex(block.hash('hex'));
  var ip = peer.socket.remoteAddress;
  console.log(block);
  console.log('Received block %s from %s.', hash, ip);
  // Add tx hashes to our bloom filter. They're not useful if they're not our
  // own, but what the hell: let's see what's going on in the world of bitcoin.
  block.tx.forEach(function(hash) {
    pool.watch(hash);
  });
});

// Receive a transaction.
pool.on('tx', function(tx, peer) {
  var hash = bcoin.utils.revHex(tx.hash('hex'));
  var ip = peer.socket.remoteAddress;
  console.log(block);
  console.log('Received transaction %s from %s.', hash, ip);
});
```

## API Documentation

*TODO...*

## LICENSE

This software is licensed under the MIT License.

Copyright Fedor Indutny, 2014.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.

[1]: https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki
