/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const path = require('path');
const assert = require('./util/assert');
const rimraf = require('./util/rimraf');
const sleep = require('./util/sleep');

const {
  initFullNode,
  initSPVNode,
  initNodeClient,
  initWalletClient,
  initWallet,
  generateInitialBlocks,
  generateReorg
} = require('./util/regtest');

const testPrefix = '/tmp/bcoin-fullnode';
const spvTestPrefix = '/tmp/bcoin-spvnode';
const genesisTime = 1534965859;

const ports = {
  full: {
    p2p: 49331,
    node: 49332,
    wallet: 49333
  },
  spv: {
    p2p: 49431,
    node: 49432,
    wallet: 49433
  }
}

async function testMonotonicTime(wclient) {
  const result = await wclient.execute('getblocksbytime', [genesisTime, 1000]);

  assert.strictEqual(result.length, 125);
  assert.strictEqual(result[0].time, genesisTime);

  let monotonic = true;
  let lastTime = result[0].time;

  for (let i = 1; i < result.length; i++) {
    if (result[i].time <= lastTime)
      monotonic = false;
    lastTime = result[i].time;
  }

  assert(monotonic, 'Expected to be monotonic');
}

async function testReorg(wclient, previous, depth) {
  const current = await wclient.execute('getblocksbytime', [genesisTime, 1000]);
  assert.strictEqual(current.length, previous.length + 2);

  const len = previous.length;

  for (let i = 0; i < len; i++) {
    if (i < len - depth)
      assert.strictEqual(previous[i].block, current[i].block);
    else
      assert.notStrictEqual(previous[i].block, current[i].block);
  }
}

describe('Wallet Monotonic Time', function() {
  this.timeout(10000);

  let node, spvnode, wallet = null;
  let nclient, wclient, spvwclient = null;
  let coinbase = null;

  before(async () => {
    await rimraf(testPrefix);
    await rimraf(spvTestPrefix);

    node = await initFullNode({ports, prefix: testPrefix, logLevel: 'none'});
    spvnode = await initSPVNode({ports, prefix: spvTestPrefix, logLevel: 'none'});

    nclient = await initNodeClient({ports: ports.full});
    wclient = await initWalletClient({ports: ports.full});
    spvwclient = await initWalletClient({ports: ports.spv});
    wallet = await initWallet(wclient);

    await wclient.execute('selectwallet', ['test']);
    coinbase = await wclient.execute('getnewaddress', ['blue']);

    await generateInitialBlocks({
      nclient,
      wclient,
      coinbase,
      genesisTime,
      blocks: 125
    });

    // TODO remove this, and use an event.
    // The wallet may not be lockstep sync with the node
    // so it's necessary to wait until it is in sync.
    await sleep(1000);
  });

  after(async () => {
    await wallet.close();
    await wclient.close();
    await spvwclient.close();
    await nclient.close();
    await node.close();
    await spvnode.close();
  });

  it('time should be monotonic for full node', async () => {
    await testMonotonicTime(wclient);
  });

  it('time should be monotonic for spv node', async () => {
    await testMonotonicTime(spvwclient);
  });

  describe('chain reorganizations', function() {
    const depth = 3;
    let previous = null;

    before(async () => {
      previous = await wclient.execute('getblocksbytime', [genesisTime, 1000]);

      const result = await generateReorg(depth, nclient, wclient, coinbase);
      assert.notStrictEqual(result.invalidated[0], result.validated[0]);

      // TODO remove this
      await sleep(5000);
    });

    it('should reorganize monotonic time for a full node', async() => {
      await testReorg(wclient, previous, depth);
    });

    it('should reorganize monotonic time for a spv node', async() => {
      await testReorg(spvwclient, previous, depth);
    });
  });
});
