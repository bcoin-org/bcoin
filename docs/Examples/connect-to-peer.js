'use strict';

// Usage: $ node ./docs/Examples/connect-to-peer.js [ip]:[port]

const bcoin = require('../..');
const Peer = bcoin.peer;
const NetAddress = bcoin.netaddress;
const Network = bcoin.network;
const network = Network.get('testnet');

const peer = Peer.fromOptions({
  network: 'testnet',
  agent: 'my-subversion',
  hasWitness: () => {
    return false;
  }
});

const addr = NetAddress.fromHostname(process.argv[2], 'testnet');

console.log(`Connecting to ${addr.hostname}`);

peer.connect(addr);
peer.tryOpen();

peer.on('error', (err) => {
  console.error(err);
});

peer.on('packet', (msg) => {
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

peer.on('open', () => {
  peer.getBlock([network.genesis.hash]);
});
