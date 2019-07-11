/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const FullNode = require('../lib/node/fullnode');
const SPVNode = require('../lib/node/spvnode');
const {NodeClient, WalletClient} = require('bclient');
const MerkleBlock = require('../lib/primitives/merkleblock');
const {forValue} = require('./util/common');
const hash256 = require('bcrypto/lib/hash256');
const {revHex} = require('../lib/utils/util');

// main timeout for the tests.
const TIMEOUT = 5000;

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
  },
  pruned: {
    p2p: 49531,
    node: 49532,
    wallet: 49533
  },
  fullindexed: {
    p2p: 49631,
    node: 49632,
    wallet: 49633
  }
};

const nodeOptions = {
  network: 'regtest',
  apiKey: 'foo',
  walletAuth: true,
  memory: true,
  workers: true,
  workersSize: 2,
  publicHost: '127.0.0.1',
  plugins: [require('../lib/wallet/plugin')]
};

describe('RPC', function() {
  this.timeout(TIMEOUT);

  const getNodePorts = (ports) => {
    return {
      port: ports.p2p,
      httpPort: ports.node,
      env: {
        'BCOIN_WALLET_HTTP_PORT': ports.wallet.toString()
      }
    };
  };

  const getClientOpts = (port) => {
    return {
      apiKey: nodeOptions.apiKey,
      timeout: TIMEOUT,
      port: port
    };
  };

  const fullnodeAddr = `127.0.0.1:${ports.full.p2p}`;
  const fullnode = new FullNode({
    listen: true,
    bip37: true,
    ...nodeOptions,
    ...getNodePorts(ports.full)
  });

  const spvnode = new SPVNode({
    only: fullnodeAddr,
    ...nodeOptions,
    ...getNodePorts(ports.spv)
  });

  const prunednode = new FullNode({
    prune: true,
    only: fullnodeAddr,
    ...nodeOptions,
    ...getNodePorts(ports.pruned)
  });
  const fullindexed = new FullNode({
    only: fullnodeAddr,
    indexTX: true,
    ...nodeOptions,
    ...getNodePorts(ports.fullindexed)
  });

  const nclient = new NodeClient({...getClientOpts(ports.full.node)});
  const wclient = new WalletClient({...getClientOpts(ports.full.wallet)});

  const spvnclient = new NodeClient({...getClientOpts(ports.spv.node)});
  const prunednclient = new NodeClient({...getClientOpts(ports.pruned.node)});
  const indexednclient = new NodeClient({
    ...getClientOpts(ports.fullindexed.node)
  });

  const MINER_WALLET = 'test';

  before(async () => {
    await fullnode.open();
    await fullnode.connect();

    await prunednode.open();
    await prunednode.connect();
    prunednode.startSync();

    await spvnode.open();
    await spvnode.connect();
    spvnode.startSync();

    await fullindexed.open();
    await fullindexed.connect();
    fullindexed.startSync();

    // create and select miner wallet.
    await wclient.createWallet(MINER_WALLET);
    await wclient.execute('selectwallet', [MINER_WALLET]);

    // setup miner wallet
    const address = await wclient.execute('getnewaddress');
    const {wdb} = fullnode.require('walletdb');

    // generate coins to our miner.
    await nclient.execute('generatetoaddress', [101, address]);

    // wait for wallet to connect blocks.
    await forValue(wdb, 'height', 101);
    await forValue(fullindexed.txindex, 'height', 101);
    await forValue(prunednode.chain, 'height', 101);
    await forValue(spvnode.chain, 'height', 101);
  });

  after(async () => {
    fullindexed.stopSync();
    spvnode.stopSync();
    prunednode.stopSync();

    await spvnode.disconnect();
    await prunednode.disconnect();
    await fullindexed.disconnect();
    await fullnode.disconnect();

    await fullnode.close();
    await prunednode.close();
    await spvnode.close();
    await fullindexed.close();
  });

  describe('help', function() {
    it('should list all methods', async () => {
      const response = await nclient.execute('help', []);
      const lines = response.split('\n');

      assert(response);
      assert(lines.length);
      assert.strictEqual(lines.length,
        Object.keys(fullnode.rpc.calls).length + 1);

      assert.strictEqual(lines[0], 'Select a command:');
    });

    it('should contain node rpc method', async () => {
      const response = await nclient.execute('help', []);
      const lines = response.split('\n');

      assert(response);
      assert(lines.length);

      // methods that are less likely to be depracated soon.
      assert(lines.includes('getblockchaininfo'));

      // server methods
      assert(lines.includes('help'));
      assert(lines.includes('stop'));
    });

    it('should not contain wallet rpc methods', async () => {
      const response = await nclient.execute('help', []);
      const lines = response.split('\n');

      assert(response);
      assert(lines.length);

      // methods that are less likely to be depracated soon.
      assert(!lines.includes('getwalletinfo'));
    });

    it('should get method help', async () => {
      await assert.rejects(async () => {
        await nclient.execute('help', ['getblockchaininfo']);
      }, {
        name: 'Error',
        message: 'getblockchaininfo'
      });

      await assert.rejects(async () => {
        await nclient.execute('help', ['help']);
      }, {
        name: 'Error',
        type: 'RPCError',
        message: 'help ( "command" )'
      });
    });

    it('should return error on wrong command', async () => {
      const wrongCommand = 'wrongcommand';

      await assert.rejects(async () => {
        await nclient.execute('help', [wrongCommand]);
      }, {
        name: 'Error',
        message: `Method not found: ${wrongCommand}.`
      });
    });

    it('should return help on wrong command', async () => {
      await assert.rejects(async () => {
        await nclient.execute('help', ['command1', 'command2']);
      }, {
        name: 'Error',
        type: 'RPCError',
        message: 'help ( "command" )'
      });
    });
  });

  describe('gettxoutproof/verifytxoutproof', function() {
    const TEST_WALLET = 'wallet-gettxoutproof';

    const blockhashes = [];
    const txids = [];

    let mempoolTXID;

    before(async () => {
      // create wallet for testing.
      await wclient.createWallet(TEST_WALLET);
      await wclient.execute('selectwallet', [TEST_WALLET]);
      const testAddr = await wclient.execute('getnewaddress');

      // back to miner
      await wclient.execute('selectwallet', [MINER_WALLET]);
      const minerAddr = await wclient.execute('getnewaddress');

      { // block 0 - This block will have 2 txs (including coinbase)
        const txid = await wclient.execute('sendtoaddress', [testAddr, 1]);
        const [bh] = await nclient.execute('generatetoaddress', [1, minerAddr]);

        // this txid will be spent in block 2.
        txids.push([txid]);
        blockhashes.push(bh);
      }

      { // block 1 - Spend utxo from block 1 in this block. (2txs)
        await wclient.execute('selectwallet', [TEST_WALLET]);

        const txid = await wclient.execute('sendtoaddress', [minerAddr, 1, '', '', true]);
        const [bh] = await nclient.execute('generatetoaddress', [1, minerAddr]);

        txids.push([txid]);
        blockhashes.push(bh);

        const unspent = await wclient.execute('listunspent');
        assert.strictEqual(unspent.length, 0);

        await wclient.execute('selectwallet', [MINER_WALLET]);
      }

      { // block 2 - This block will have 4 txs (including coinbase)
        const blocktxs = [];
        for (let i = 0; i < 3; i++) {
          const txid = await wclient.execute('sendtoaddress', [testAddr, 1]);
          blocktxs.push(txid);
        }

        const [bh] = await nclient.execute('generatetoaddress', [1, minerAddr]);

        txids.push(blocktxs);
        blockhashes.push(bh);
      }

      { // block 3 - This block will have 7 txs (including coinbase)
        const blocktxs = [];
        for (let i = 0; i < 6; i++) {
          const txid = await wclient.execute('sendtoaddress', [testAddr, 1]);
          blocktxs.push(txid);
        }

        const [bh] = await nclient.execute('generatetoaddress', [1, minerAddr]);

        txids.push(blocktxs);
        blockhashes.push(bh);
      }

      { // mempool tx
        mempoolTXID = await wclient.execute('sendtoaddress', [testAddr, 1]);
        await forValue(fullnode.mempool.map, 'size', 1);
      }

      const bh = blockhashes[blockhashes.length - 1];
      const {height} = await nclient.execute('getblock', [bh]);

      await forValue(fullnode.chain, 'height', height);
      await forValue(fullindexed.txindex, 'height', height);
      await forValue(prunednode.chain, 'height', height);
      await forValue(spvnode.chain, 'height', height);
    });

    it('should fail in spv mode (gettxoutproof)', async () => {
      await assert.rejects(async () => {
        await spvnclient.execute('gettxoutproof', [[mempoolTXID]]);
      }, {
        name: 'Error',
        type: 'RPCError',
        message: /SPV/,
        code: -1 >>> 0
      });
    });

    it('should fail in pruned mode (gettxoutproof)', async () => {
      await assert.rejects(async () => {
        await prunednclient.execute('gettxoutproof', [[mempoolTXID]]);
      }, {
        name: 'Error',
        type: 'RPCError',
        message: /pruned/,
        code: -1 >>> 0
      });
    });

    it('should fail with wrong params (gettxoutproof)', async () => {
      const hash = '00'.repeat(32);

      const error0array = 'Param #0 must be a array.';
      const error0hex = 'Param #0 must be a hex string.';
      const error1hex = 'Param #1 must be a hex string.';

      const tests = [
        {args: [[]], message: 'Invalid TXIDs.', code: -8},
        // help
        {args: [], message: /^gettxoutproof/, code: -1},
        {args: ['test'], message: error0array, code: -3},
        {args: [['test']], message: error0hex, code: -3},
        {args: [['00ff']], message: error0hex, code: -3},
        {args: [[hash, '00ff']], message: error1hex, code: -3},
        {args: [[hash], '0f00'], message: error1hex, code: -3},
        {args: [[hash, hash]], message: /duplicate/i, code: -8}
      ];

      for (const test of tests) {
        // @see https://github.com/bcoin-org/bcurl/pull/16
        const code = test.code >>> 0;

        await assert.rejects(async () => {
          await nclient.execute('gettxoutproof', test.args);
        }, {
          type: 'RPCError',
          message: test.message,
          code: code
        });
      }
    });

    it('should fail with wrong params (verifytxoutproof)', async () => {
      const txid = txids[2][0];
      const proof = await nclient.execute('gettxoutproof', [[txid]]);

      const error0hex = 'Param #0 must be a hex string.';

      const tests = [
        {args: [], message: /^verifytxoutproof/, code: -1},
        {args: [proof, proof], message: /^verifytxoutproof/, code: -1},
        {args: ['test'], message: error0hex, code: -3},
        {args: ['00ff'], message: /Out of bound/, code: -22},
        {args: ['00000022'], message: /Out of bound/, code: -22}
      ];

      for (const test of tests) {
        const code = test.code >>> 0;

        await assert.rejects(async () => {
          await nclient.execute('verifytxoutproof', test.args);
        }, {
          type: 'RPCError',
          message: test.message,
          code: code
        });
      }
    });

    it('should fail with wrong block', async () => {
      const hash = '00'.repeat(32);

      await assert.rejects(async () => {
        await nclient.execute('gettxoutproof', [[hash], hash]);
      }, {
        type: 'RPCError',
        message: 'Block not found.',
        code: -1 >>> 0
      });
    });

    it('should fail for mempool tx', async () => {
      await assert.rejects(async () => {
        await nclient.execute('gettxoutproof', [[mempoolTXID]]);
      }, {
        type: 'RPCError',
        message: 'Transaction not yet in block.',
        code: -5 >>> 0
      });
    });

    it('should fail for spent coin w/o blockhash and txindex', async () => {
      // block 0 has spent txid
      const txid = txids[0][0];

      await assert.rejects(async () => {
        await nclient.execute('gettxoutproof', [[txid]]);
      }, {
        type: 'RPCError',
        message: 'Block not found.',
        code: -1 >>> 0
      });
    });

    it('should fail getting proof from two blocks', async () => {
      // different blocks
      const list = [
        txids[2][0],
        txids[3][0]
      ];

      await assert.rejects(async () => {
        await nclient.execute('gettxoutproof', [list]);
      }, {
        type: 'RPCError',
        message: 'Block does not contain all txids.',
        code: -25 >>> 0
      });
    });

    it('should fail getting proof from wrong block', async () => {
      // txid in one block, blockhash of another.
      const txid = txids[2][0];
      const blockhash = blockhashes[3];

      await assert.rejects(async () => {
        await nclient.execute('gettxoutproof', [[txid], blockhash]);
      }, {
        type: 'RPCError',
        message: 'Block does not contain all txids.',
        code: -25 >>> 0
      });
    });

    it('should verify in spv mode and pruned mode', async () => {
      const txid = txids[2][0];
      const proof = await nclient.execute('gettxoutproof', [[txid]]);

      for (const client of [spvnclient, prunednclient]) {
        const verify = await client.execute('verifytxoutproof', [proof]);

        assert(verify);
        assert.strict(verify.length, 1);
        assert.strict(verify[0], txid);
      }
    });

    it('should create proof for spent coin with txindex', async () => {
      const txid = txids[0][0];
      const res = await indexednclient.execute('gettxoutproof', [[txid]]);
      const verify = await nclient.execute('verifytxoutproof', [res]);

      assert(verify);
      assert.strictEqual(verify.length, 1);
      assert.strictEqual(verify[0], txid);
    });

    it('should create proof for one tx w/o blockhash', async () => {
      const check = [
        txids[2][0],
        txids[2][1],
        txids[3][0],
        txids[3][1]
      ];

      for (const txid of check) {
        const proof = await nclient.execute('gettxoutproof', [[txid]]);
        const verify = await nclient.execute('verifytxoutproof', [proof]);

        assert(verify);
        assert.strictEqual(verify.length, 1);
        assert.strictEqual(verify[0], txid);
      }
    });

    it('should create proof one tx w/o blockhash (merkle)', async () => {
      const txid = txids[2][2];

      const proof = await nclient.execute('gettxoutproof', [[txid]]);
      const verify = await nclient.execute('verifytxoutproof', [proof]);

      assert(verify);
      assert.strictEqual(verify.length, 1);
      assert.strictEqual(verify[0], txid);

      const mblock = MerkleBlock.fromRaw(proof, 'hex');
      const mblockJSON = mblock.toJSON();
      const tree = mblock.getTree();

      assert.strictEqual(mblockJSON.hash, blockhashes[2]);
      assert.strictEqual(mblockJSON.prevBlock, blockhashes[1]);
      assert.strictEqual(mblockJSON.totalTX, txids[2].length + 1);
      assert.bufferEqual(mblock.merkleRoot, tree.root);
      assert.strictEqual(tree.matches.length, 1);
    });

    it('should create proof of multiple txs in a block', async () => {
      const blockhash = blockhashes[3];
      const list = [
        txids[3][0],
        txids[3][5]
      ];

      const proof = await nclient.execute('gettxoutproof', [list, blockhash]);
      const verify = await nclient.execute('verifytxoutproof', [proof]);

      assert(verify);
      assert.strictEqual(verify.length, 2);
      assert.ok(verify.includes(list[0]));
      assert.ok(verify.includes(list[1]));
    });

    it('should fail with tweaked proof (1 tx)', async () => {
      const block = await nclient.execute('getblock', [blockhashes[2]]);
      const txids = block.tx;

      const list = [
        txids[0]
      ];

      const proof = await nclient.execute('gettxoutproof', [list]);
      const verify = await nclient.execute('verifytxoutproof', [proof]);

      assert.deepStrictEqual(verify, list);

      // pretend block only has 1 tx.
      const mblock = MerkleBlock.fromRaw(proof, 'hex');

      mblock.totalTX = 1;
      mblock.hashes = [mblock.merkleRoot];
      mblock.flags = Buffer.from([0x01]);

      const tweaked = mblock.toRaw().toString('hex');

      // should fail in fullnode or in pruned mode (if there's block available).
      for (const client of [nclient, prunednclient]) {
        const verify = await client.execute('verifytxoutproof', [tweaked]);
        assert.deepStrictEqual(verify, []);
      }

      { // spv node or pruned node (passed pruning height) can't verify tx length.
        const verify = await spvnclient.execute('verifytxoutproof', [tweaked]);

        assert(verify);
        assert.strictEqual(verify.length, 1);
      }
    });

    it('should fail with tweaked proof (internal nodes)', async () => {
      const block = await nclient.execute('getblock', [blockhashes[2]]);
      const txids = block.tx;

      const list = [
        txids[0]
      ];

      const proof = await nclient.execute('gettxoutproof', [list]);
      const verify = await nclient.execute('verifytxoutproof', [proof]);

      assert.deepStrictEqual(verify, list);

      // pretend block only has 1 tx.
      const mblock = MerkleBlock.fromRaw(proof, 'hex');

      // left internal node.
      const left = hash256.root(mblock.hashes[0], mblock.hashes[1]);
      const right = mblock.hashes[2];
      const root = hash256.root(left, right);

      assert.bufferEqual(root, mblock.merkleRoot);

      mblock.totalTX = 2;
      mblock.hashes = [left, right];
      mblock.flags = Buffer.from([0x03]); // we are interested in left/first tx.

      const tweaked = mblock.toRaw().toString('hex');

      // should fail in fullnode or in pruned mode (if there's block available).
      for (const client of [nclient, prunednclient]) {
        const verify = await client.execute('verifytxoutproof', [tweaked]);
        assert.deepStrictEqual(verify, []);
      }

      // spv node does not have blocks.
      {
        const verify = await spvnclient.execute('verifytxoutproof', [tweaked]);
        const expected = [revHex(left)];

        assert.deepStrictEqual(verify, expected);
      }
    });
  });
});
