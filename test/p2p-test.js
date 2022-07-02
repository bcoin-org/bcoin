/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const FullNode = require('../lib/node/fullnode');
const {forValue} = require('./util/common');
const packets = require('../lib/net/packets');

describe('Compact Blocks', function() {
  this.timeout(30000);

  const node = new FullNode({
    network: 'regtest',
    memory: true,
    port: 10000,
    httpPort: 20000,
    only: '127.0.0.1'
  });

  const node2 = new FullNode({
    network: 'regtest',
    memory: true,
    listen: true
  });

  let peer;

  before(async () => {
    const waitForConnection = new Promise((resolve, reject) => {
      node.pool.once('peer open', async (peer) => {
        resolve(peer);
      });
    });

    await node.open();
    await node2.open();
    await node.connect();
    await node2.connect();
    node.startSync();
    node2.startSync();

    peer = await waitForConnection;
  });

  after(async () => {
    await node.close();
    await node2.close();
  });

  const nodePackets = [];

  node.pool.on('packet', (packet) => {
    nodePackets.push(packet);
  });

  beforeEach(() => {
    nodePackets.length = 0;
  });

  it('should get compact block in low bandwidth mode', async () => {
    const block = await node2.miner.mineBlock();
    await node2.chain.add(block);

    await forValue(node.chain, 'height', node2.chain.height);

    let inv = false;
    let compactBlock = false;

    for (const packet of nodePackets) {
      if (packet.type === packets.types.INV)
        inv = true;
      if (packet.type === packets.types.CMPCTBLOCK)
        compactBlock = true;
    }

    assert(inv);
    assert(compactBlock);
  });

  it('should switch to high bandwidth mode', async () => {
    peer.sendCompact(1);
    node.pool.options.blockMode = 1;

    const block = await node2.miner.mineBlock();
    await node2.chain.add(block);

    await forValue(node.chain, 'height', node2.chain.height);

    let inv = false;
    let compactBlock = false;

    for (const packet of nodePackets) {
      if (packet.type === packets.types.INV)
        inv = true;
      if (packet.type === packets.types.CMPCTBLOCK)
        compactBlock = true;
    }

    assert(!inv);
    assert(compactBlock);
  });
});
