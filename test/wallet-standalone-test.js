/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const FullNode = require('../lib/node/fullnode');
const Node = require('../lib/wallet/node');

const ports = {
  p2p: 49331,
  node: 49332
};

const fullNode = new FullNode({
  network: 'regtest',
  port: ports.p2p,
  httpPort: ports.node,
  memory: true
});

const walletNode = new Node({
  network: 'regtest',
  memory: true,
  nodePort: ports.node
});

const wdb = walletNode.wdb;

describe('Standalone wallet node test', function() {
  before(async () => {
    await fullNode.open();
  });

  after(async () => {
    if (walletNode.opened)
      await walletNode.close();
    await fullNode.close();
  });

  it('should bind hooks on connect', async() => {
    let hooked = false;
    wdb.rescanBlock = () => {
      hooked = true;
    };

    // Initial connect
    assert(!hooked);
    await walletNode.open();

    // Wait for the socket call and check
    await new Promise(r => setTimeout(r, 100));
    assert(hooked);

    // Reset
    await walletNode.close();
    hooked = false;

    // ...and reconnect
    await walletNode.open();
    await new Promise(r => setTimeout(r, 100));
    assert(hooked);
  });
});
