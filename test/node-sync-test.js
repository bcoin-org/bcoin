/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const FullNode = require('../lib/node/fullnode');
const WalletNode = require('../lib/wallet/node');
const SPVNode = require('../lib/node/spvnode');
const {forValue} = require('./util/common');
const WalletKey = require('../lib/wallet/walletkey');

describe('Node Sync', function() {
  this.timeout(60000);

  const mnemonic = [
    'abandon', 'abandon', 'abandon', 'abandon',
    'abandon', 'abandon', 'abandon', 'abandon',
    'abandon', 'abandon', 'abandon', 'about'
  ].join(' ');

  const ports = {
    p2p: 49331,
    node: 49332,
    wallet: 49333
  };

  const lookahead = 10;

  let node, node2, node3 = null;
  let node2wallet = null;
  let wdb, wdb2, wdb3 = null;
  let wallet, wallet2, wallet3 = null;

  before(async () => {
    /**
     * Setup initial nodes and wallets.
     */

    node = new FullNode({
      memory: true,
      apiKey: 'foo',
      network: 'regtest',
      workers: true,
      workersSize: 2,
      bip37: true,
      plugins: [require('../lib/wallet/plugin')],
      listen: true,
      port: ports.p2p,
      httpPort: ports.node,
      env: {
        'BCOIN_WALLET_HTTP_PORT': ports.wallet.toString()
      }
    });

    await node.open();

    node2 = new FullNode({
      memory: true,
      apiKey: 'foo',
      network: 'regtest',
      workers: true,
      workersSize: 2,
      port: ports.p2p + 3,
      httpPort: ports.node + 3,
      only: [`127.0.0.1:${ports.p2p}`]
    });

    await node2.open();

    node2wallet = new WalletNode({
      httpPort: ports.wallet + 3,
      nodePort: ports.node + 3,
      nodeApiKey: 'foo',
      network: 'regtest'
    });

    await node2wallet.open();

    node3 = new SPVNode({
      memory: true,
      apiKey: 'foo',
      network: 'regtest',
      workers: true,
      workersSize: 2,
      plugins: [require('../lib/wallet/plugin')],
      port: ports.p2p + 6,
      httpPort: ports.node + 6,
      only: [`127.0.0.1:${ports.p2p}`],
      env: {
        'BCOIN_WALLET_HTTP_PORT': (ports.wallet + 6).toString()
      }
    });

    await node3.open();

    /**
     * Generate blocks and transactions.
     */

    await node.connect();

    // Prepare the miner and wallet.
    const {miner, chain} = node;
    wdb = node.require('walletdb').wdb;
    wallet = await wdb.create();
    miner.addAddress(await wallet.receiveAddress());

    // Mature the initial coins to use for the
    // use in generating the test case.
    for (let i = 0; i < 200; i++) {
      const block = await miner.mineBlock();
      assert(await chain.add(block));
    }

    assert.strictEqual(chain.height, 200);

    // Prepare the full node wallet.
    wdb2 = node2wallet.wdb;
    wallet2 = await wdb2.create({mnemonic});

    // Prepare the spv node wallet.
    wdb3 = node3.require('walletdb').wdb;
    wallet3 = await wdb3.create({mnemonic});

    let index = 0;

    // Generate several blocks of transactions for
    // the identical wallets.
    for (let b = 0; b < 5; b++) {
      const account = await wallet3.getAccount(0);
      assert.equal(account.lookahead, lookahead);
      let count = 0;

      // Include more transactions than the lookahead
      // within the block. The filter will need to be updated
      // and re-download the same block.
      while (count < lookahead + 1) {
        const branch = 0;
        const key = account.accountKey.derive(branch).derive(index);
        const ring = WalletKey.fromHD(account, key, branch, index);
        const spvaddr = ring.getAddress();

        await wallet.send({
          subtractFee: true,
          outputs: [{
            address: spvaddr,
            value: 10000
          }]
        });

        index += 1;
        count += 1;
      }

      const block = await miner.mineBlock();
      assert(await chain.add(block));
    }
  });

  after(async () => {
    await node.close();
    await node2wallet.close();
    await node2.close();
    await node3.close();
  });

  it('should sync with node and wallet (full)', async () => {
    await node2.connect();
    await node2.startSync();

    await forValue(wdb2, 'height', 205);
    await forValue(node2.chain, 'height', 205);

    await new Promise(r => setTimeout(() => r(), 3000));

    const bal = await wallet2.getBalance();
    assert.equal(bal.tx, 5 * lookahead + 5);
    assert.equal(bal.coin, 5 * lookahead + 5);
  });

  it('should sync with node and wallet (spv)', async () => {
    await node3.connect();
    await node3.startSync();

    await forValue(wdb3, 'height', 205);
    await forValue(node3.chain, 'height', 205);

    const bal = await wallet3.getBalance();
    assert.equal(bal.tx, 5 * lookahead + 5);
    assert.equal(bal.coin, 5 * lookahead + 5);
  });
});
