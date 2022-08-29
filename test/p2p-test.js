/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const FullNode = require('../lib/node/fullnode');
const {forValue} = require('./util/common');
const {MAX_CFILTERS} = require('../lib/net/common');
const packets = require('../lib/net/packets');

describe('P2P', function () {
  this.timeout(5000);

  const node1 = new FullNode({
    network: 'regtest',
    memory: true,
    port: 10000,
    httpPort: 20000,
    only: '127.0.0.1'
  });

  const node2 = new FullNode({
    network: 'regtest',
    memory: true,
    listen: true,
    indexFilter: true,
    bip157: true
  });

  let peer;
  const nodePackets = {};

  node1.pool.on('packet', (packet) => {
    if (!nodePackets[packet.cmd])
      nodePackets[packet.cmd] = [packet];
    else
      nodePackets[packet.cmd].push(packet);
  });

  async function mineBlocks(n) {
    while (n) {
      const block = await node2.miner.mineBlock();
      await node2.chain.add(block);
      n--;
    }
    await forValue(node1.chain, 'height', node2.chain.height);
  }

  before(async () => {
    const waitForConnection = new Promise((resolve, reject) => {
      node1.pool.once('peer open', async (peer) => {
        resolve(peer);
      });
    });

    await node1.open();
    await node2.open();
    await node1.connect();
    await node2.connect();
    node1.startSync();
    node2.startSync();

    // `peer` is node2, from node1's perspective.
    // So peer.send() sends a packet from node1 to node2,
    // and `nodePackets` catches the response packets that
    // node2 sends back to node1.
    peer = await waitForConnection;
  });

  after(async () => {
    await node1.close();
    await node2.close();
  });

  describe('BIP157', function () {
    before(async () => {
      // Do not exceed limit, including genesis block
      await mineBlocks(MAX_CFILTERS - node1.chain.height - 1);
    });

    it('CFilters', async () => {
      nodePackets.cfilter = [];

      const pkt = new packets.GetCFiltersPacket(
        0,
        0,
        node1.chain.tip.hash
      );

      peer.send(pkt);
      await forValue(nodePackets.cfilter, 'length', MAX_CFILTERS);
    });

    it('CFHeaders', async () => {
      nodePackets.cfheaders = [];

      const pkt = new packets.GetCFHeadersPacket(
        0,
        0,
        node1.chain.tip.hash
      );

      peer.send(pkt);
      await forValue(nodePackets.cfheaders, 'length', 1);
      assert.strictEqual(
        nodePackets.cfheaders[0].filterHashes.length,
        node1.chain.height + 1
      );
    });

    it('CFCheckpt', async () => {
      nodePackets.cfcheckpt = [];

      await mineBlocks(2);

      const pkt = new packets.GetCFCheckptPacket(
        0,
        node1.chain.tip.hash
      );

      peer.send(pkt);
      await forValue(nodePackets.cfcheckpt, 'length', 1);
      assert.strictEqual(nodePackets.cfcheckpt[0].filterHeaders.length, 1);
    });
  });

  describe('Compact Blocks', function () {
    it('should get compact block in low bandwidth mode', async () => {
      nodePackets.inv = [];
      nodePackets.cmpctblock = [];

      await mineBlocks(1);

      assert.strictEqual(nodePackets.inv.length, 1);
      assert.strictEqual(nodePackets.cmpctblock.length, 1);
    });

    it('should switch to high bandwidth mode', async () => {
      nodePackets.inv = [];
      nodePackets.cmpctblock = [];

      peer.sendCompact(1);
      node1.pool.options.blockMode = 1;

      await mineBlocks(1);

      assert.strictEqual(nodePackets.inv.length, 0);
      assert.strictEqual(nodePackets.cmpctblock.length, 1);
    });
  });
});
