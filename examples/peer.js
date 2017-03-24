'use strict';

// Usage: $ node ./examples/peer.js [ip]:[port]

var Peer = require('bcoin/lib/net/peer');
var NetAddress = require('bcoin/lib/primitives/netaddress');
var Network = require('bcoin/lib/protocol/network');
var network = Network.get('testnet');
var peer, addr;

peer = Peer.fromOptions({
  network: 'testnet',
  agent: 'my-subversion',
  hasWitness: function() {
    return false;
  }
});

addr = NetAddress.fromHostname(process.argv[2], 'testnet');

peer.connect(addr);
peer.tryOpen();

peer.on('error', function(err) {
  console.error(err);
});

peer.on('packet', function(msg) {
  console.log(msg);

  if (msg.cmd === 'block') {
    console.log('Block!');
    console.log(msg.block.toBlock());
    return;
  }

  if (msg.cmd === 'inv') {
    peer.getData(msg.items);
    return;
  }
});

peer.on('open', function() {
  peer.getBlock([network.genesis.hash]);
});
