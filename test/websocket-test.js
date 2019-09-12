/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

/**
 * Tests for websockets - test/websocket-test.js
 */

'use strict';

const {NodeClient, WalletClient} = require('bclient');
const blake2b = require('bcrypto/lib/blake2b');
const assert = require('bsert');

const FullNode = require('../lib/node/fullnode');
const ChainEntry = require('../lib/blockchain/chainentry');

// two globally accessible full node objects
let alice, bob;

describe('Websockets', function() {
  before(async () => {
    alice = await newNode('alice');
    bob = await newNode('bob');
  });

  after(async () => {
    await alice.close();
    await bob.close();
  });

  it('should receive chain connect events', async () => {
    const events = [];

    alice.nclient.bind('chain connect', (raw) => {
      const entry = ChainEntry.fromRaw(raw);
      const json = entry.toJSON(); // handle endianness
      events.push(json.hash);
    });

    const {address} = await alice.wallet.createAddress('default');

    const hashes = [];
    for (let i = 0; i < 5; i++) {
      const [hash] = await alice.nclient.execute('generatetoaddress', [1, address]);
      hashes.push(hash);
    }

    assert.equal(events.length, hashes.length);

    for (let i = 0; i < 5; i++)
      assert.equal(hashes[i], events[i]);

    // stop watching the chain
    await alice.nclient.call('unwatch chain');
    await alice.nclient.execute('generatetoaddress', [1, address]);

    // no new websocket events
    assert.equal(events.length, 5);
  });

  it('should receive a reorganize event', async () => {
    // expected to be true after 'chain reorganize' event
    let reorg = false;

    // set up listeners
    await alice.nclient.watchChain();
    alice.nclient.bind('chain reorganize', async (rtip, rcomp) => {
      assert(Buffer.isBuffer(rtip));
      assert(Buffer.isBuffer(rcomp));

      // previous tip should no longer be in the main chain
      const tip = ChainEntry.fromRaw(rtip);
      assert(!(await alice.node.chain.isMainChain(tip)));

      // competitor extends the chain's tip
      const competitor = ChainEntry.fromRaw(rcomp);
      assert(await alice.node.chain.isMainHash(competitor.prevBlock));
      assert.bufferEqual(alice.node.chain.tip.hash, competitor.prevBlock);

      reorg = true;
    });

    // get the height of alice's chain
    const info = await alice.nclient.getInfo();
    const height = info.chain.height;

    // bob mines a heavier chain
    const {address} = await bob.wallet.createAddress('default');
    const args = [height + 2, address];
    await bob.nclient.execute('generatetoaddress', args);

    // add all of bob's blocks to alice's chain
    for (let i = 1; i < bob.node.chain.height; i++) {
      const block = await bob.node.chain.getBlock(i);
      assert(await alice.node.chain.add(block));
    }

    // assert that the reorganize event happened
    assert.equal(reorg, true);
  });
});

// create a new full node with a
// given id, the ports are deterministic
// based on what the id is
async function newNode(id) {
  const digest = blake2b.digest(Buffer.from(id, 'ascii'));
  const port = 40000 + digest.readUInt16BE() % 3000;

  const ports = {
    p2p: port,
    node: port + 1,
    wallet: port + 2
  };

  const apiKey = digest.toString('hex');

  const node = new FullNode({
    network: 'regtest',
    apiKey: apiKey,
    walletAuth: true,
    memory: true,
    workers: true,
    workersSize: 2,
    plugins: [require('../lib/wallet/plugin')],
    port: ports.p2p,
    httpPort: ports.node,
    env: {
      'BCOIN_WALLET_HTTP_PORT': ports.wallet.toString()
    }
  });

  const nclient = new NodeClient({
    port: ports.node,
    apiKey: apiKey
  });

  const wclient = new WalletClient({
    port: ports.wallet,
    apiKey: apiKey
  });

  const wallet = wclient.wallet('primary');

  nclient.on('connect', async () => {
    await nclient.watchChain();
  });

  await node.open();
  await nclient.open();
  await wclient.open();

  async function close() {
    await wclient.close();
    await nclient.close();
    await node.close();
  }

  return {
    ports,
    node,
    nclient,
    wclient,
    wallet,
    close
  };
}
