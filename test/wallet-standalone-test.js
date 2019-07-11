/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const FullNode = require('../lib/node/fullnode');
const Node = require('../lib/wallet/node');
const NetAddress = require('../lib/net/netaddress');

const ports = {
  high: {
    p2p: 49330,
    node: 49331
  },
  low: {
    p2p: 49332,
    node: 49333
  }
};

// This full node will have a longer chain
const high = new FullNode({
  network: 'regtest',
  listen: true,
  port: ports.high.p2p,
  httpPort: ports.high.node,
  memory: true,
  maxOutbound: 1
});

// This full node will have a shorter chain
const low = new FullNode({
  network: 'regtest',
  listen: true,
  port: ports.low.p2p,
  httpPort: ports.low.node,
  memory: true,
  maxOutbound: 1
});

// Wallet server starts off connected to the "high" node
const walletNode = new Node({
  network: 'regtest',
  memory: true,
  nodePort: ports.high.node
});

describe('Standalone wallet server test', function() {
  before( async() => {
    await high.open();
    await low.open();
    await high.connect();
    await low.connect();
    high.startSync();
    low.startSync();
    await walletNode.open();
  });

  after( async() => {
    await walletNode.close();
    await high.close();
    await low.close();
  });

  let wallet;

  it('should connect high and low nodes', async() => {
    const host = NetAddress.fromHostname(
      `127.0.0.1:${ports.low.p2p}`,
      'regtest'
    );
    const peer = high.pool.createOutbound(host);
    high.pool.peers.add(peer);
  });

  it('should mine 10 blocks to wallet from high node', async() => {
    wallet = await walletNode.wdb.get(0);
    let addr = await wallet.receiveAddress();
    addr = addr.toString('regtest');

    for (let i = 0; i < 10; i++) {
      const block = await high.miner.mineBlock(null, addr);
      await high.chain.add(block);
    }

    await walletNode.wdb.scan(0);

    const balance = await wallet.getBalance();
    assert.strictEqual(balance.confirmed, 50 * 10 * 1e8);
    assert.strictEqual(balance.unconfirmed, 50 * 10 * 1e8);

    assert.strictEqual(walletNode.wdb.height, high.chain.height);
  });

  it('should disconnect high and low nodes', async() => {
    high.pool.peers.head().destroy();
  });

  it('should mine 10 more blocks to wallet from high node', async() => {
    const wallet = await walletNode.wdb.get(0);
    let addr = await wallet.receiveAddress();
    addr = addr.toString('regtest');

    for (let i = 0; i < 10; i++) {
      const block = await high.miner.mineBlock(null, addr);
      await high.chain.add(block);
    }

    await walletNode.wdb.scan(0);

    const balance = await wallet.getBalance();
    assert.strictEqual(balance.confirmed, 50 * 20 * 1e8);
    assert.strictEqual(balance.unconfirmed, 50 * 20 * 1e8);

    assert.strictEqual(walletNode.wdb.height, high.chain.height);
  });

  it('should switch wallet from high node to low node', async() => {
    await walletNode.close();
    walletNode.client.port = ports.low.node;
    walletNode.wdb.client.port = ports.low.node;
    await walletNode.open();

    const balance = await wallet.getBalance();

    // At this point the wallet is showing incorrect confirmed balance
    // relative to the shorter-chain node
    assert.strictEqual(balance.confirmed, 50 * 20 * 1e8);
    assert.strictEqual(balance.unconfirmed, 50 * 20 * 1e8);

    assert.strictEqual(walletNode.wdb.height - 10, low.chain.height);
  });

  it('should rescan wallet from low node', async() => {
    await walletNode.wdb.scan(0);

    const balance = await wallet.getBalance();

    // The confirmed balance has dropped to the height of the full node's chain
    assert.strictEqual(balance.confirmed, 50 * 10 * 1e8);
    assert.strictEqual(balance.unconfirmed, 50 * 20 * 1e8);

    assert.strictEqual(walletNode.wdb.height, low.chain.height);
  });
});
