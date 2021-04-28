'use strict';

/*
 * Usage:
 *  Run another Bitcoin node on local regtest network, for example
 *    $ ../../bin/bcoin --network=regtest
 *  Execute this script with the other node's address and port
 *    $ node connect-to-peer.js 127.0.0.1:48444
 */

const bcoin = require('../..');
const network = bcoin.Network.get('regtest');

const peer = bcoin.Peer.fromOptions({
  network: 'regtest',
  agent: 'my-subversion',
  hasWitness: () => {
    return false;
  }
});

const addr = bcoin.net.NetAddress.fromHostname(process.argv[2], 'regtest');

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
