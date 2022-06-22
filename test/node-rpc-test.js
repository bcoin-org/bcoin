/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const FullNode = require('../lib/node/fullnode');
const NodeClient = require('../lib/client/node');
const KeyRing = require('../lib/primitives/keyring');
const util = require('../lib/utils/util');

const ports = {
  p2p: 49331,
  node: 49332,
  wallet: 49333
};

const node = new FullNode({
  network: 'regtest',
  apiKey: 'foo',
  walletAuth: true,
  memory: true,
  workers: true,
  workersSize: 2,
  plugins: [require('../lib/wallet/plugin')],
  port: ports.p2p,
  httpPort: ports.node,
  env: {
    'BCOIN_WALLET_HTTP_PORT': ports.wallet.toString()
  },
  listen: true
});

const nclient = new NodeClient({
  port: ports.node,
  apiKey: 'foo',
  timeout: 15000
});

describe('RPC', function() {
  this.timeout(15000);

  before(async () => {
    await node.open();
  });

  after(async () => {
    await node.close();
  });

  it('should rpc help', async () => {
    assert(await nclient.execute('help', []));

    await assert.rejects(async () => {
      await nclient.execute('help', ['getinfo']);
    }, {
      name: 'Error',
      message: /^getinfo/
    });
  });

  it('should rpc getinfo', async () => {
    const info = await nclient.execute('getinfo', []);
    assert.strictEqual(info.blocks, 0);
  });

  it('should rpc getnetworkinfo', async () => {
    const info = await nclient.execute('getnetworkinfo', []);

    assert.deepEqual(info.localservicenames, ['NETWORK', 'WITNESS']);
  });

  it('should rpc getblockhash', async () => {
    const info = await nclient.execute('getblockhash', [node.chain.tip.height]);
    assert.strictEqual(util.revHex(node.chain.tip.hash), info);
  });

  describe('Blockchain', function () {
    it('should rpc getchaintips', async () => {
      const info = await nclient.execute('getchaintips', []);
      assert.strictEqual(info.length, 1);
      assert.strictEqual(util.revHex(node.chain.tip.hash), info[0].hash);
    });

    it('should rpc getchaintips for chain fork', async () => {
      // function to generate blocks
      const generateblocks = async (height, entry) => {
        for (let i = 0; i <= height; i++) {
          const block = await node.miner.mineBlock(entry);
          entry = await node.chain.add(block);
        }
        return entry;
      };

      // extnding chain1 from genesis.
      const entry1 = await generateblocks(3, await node.chain.getEntry(0));

      /** current state:
       *         genesis block -- block01 -- block02 -- block03
       */

      // Creating a chain fork, by mining block again on genesis as parent.
      const entry2 = await generateblocks(2, await node.chain.getEntry(0));

      /** current state:
       *                        block01 -- block02 -- block03 (chain1, with height 3)
       *                      /
       *         genesis block
       *                      \
       *                        block01 -- block02 (chain2, with height 2)
       */

      const info = await nclient.execute('getchaintips', []);
      assert.notEqual(entry1.hash, entry2.hash);

      const expected = [
        {
          height: 3,
          hash: util.revHex(entry2.hash),
          branchlen: 3,
          status: 'valid-headers'
        },
        {
          height: 4,
          hash: util.revHex(entry1.hash),
          branchlen: 0,
          status: 'active'
        }
      ];

      try {
        assert.deepStrictEqual(info, expected);
      } catch (e) {
        assert.deepStrictEqual(info, expected.reverse());
      }
    });
  });

  describe('Networking', function () {
    const peer = new FullNode({
      network: 'regtest',
      memory: true,
      port: ports.p2p + 100,
      httpPort: ports.node + 100,
      only: [`127.0.0.1:${ports.p2p}`]
    });

    after(async() => {
      if (peer.opened)
        await peer.close();
    });

    it('should rpc getpeerinfo without peers', async () => {
      const info = await nclient.execute('getpeerinfo', []);
      assert.deepEqual(info, []);
    });

    it('should rpc getconnectioncount without peers', async () => {
      const connectionsCnt = await nclient.execute('getconnectioncount', []);
      assert.strictEqual(connectionsCnt, 0);
    });

    it('should rpc getnettotals without peers', async () => {
      const totals = await nclient.execute('getnettotals', []);
      assert.strictEqual(totals.totalbytesrecv, 0);
      assert.strictEqual(totals.totalbytessent, 0);
    });

    it('should connect to a peer', async () => {
      await node.connect();
      await peer.open();
      await peer.connect();
    });

    it('should rpc getpeerinfo with peers', async () => {
      const info = await nclient.execute('getpeerinfo', []);
      assert.strictEqual(info.length, 1);
      assert.strictEqual(info[0].inbound, true);
      assert.strictEqual(info[0].addrlocal, `127.0.0.1:${ports.p2p}`);
    });

    it('should rpc getconnectioncount with peers', async () => {
      const connectionsCnt = await nclient.execute('getconnectioncount', []);
      assert.strictEqual(connectionsCnt, 1);
    });

    it('should rpc getnettotals with peers', async () => {
      const totals = await nclient.execute('getnettotals', []);

      // Checking if the total bytes received in the p2p handshake equal to 259
      // The breakdown of the command vs bytes are as follows:
      // version: 123
      // verack: 24
      // sendcmpct: 33
      // getaddr: 24
      // addr: 55
      // TOTAL: 259
      assert.strictEqual(totals.totalbytesrecv, 259);
      assert.strictEqual(totals.totalbytessent, 259);
    });

    it('should rpc setban a peer', async () => {
      // getting initial connection count
      let connectionsCnt = await nclient.execute('getconnectioncount', []);
      assert.strictEqual(connectionsCnt, 1);

      // getting initial banned list
      let listbanned = await nclient.execute('listbanned', []);
      assert.strictEqual(listbanned.length, 0);

      // fetching peer info and banning it
      const info = await nclient.execute('getpeerinfo', []);
      const banThisPeer = info[0].addr;
      const result = await nclient.execute('setban', [banThisPeer, 'add']);
      assert.strictEqual(result, null);

      // checking banned count after banning
      listbanned = await nclient.execute('listbanned', []);
      assert.strictEqual(listbanned.length, 1);

      // checking connection count after banning
      connectionsCnt = await nclient.execute('getconnectioncount', []);
      assert.strictEqual(connectionsCnt, 0);
    });
  });

  describe('getblock', function () {
    it('should rpc getblock', async () => {
      const info = await nclient.execute('getblock', [util.revHex(node.chain.tip.hash)]);
      const properties = [
        'hash', 'confirmations', 'strippedsize',
        'size', 'weight', 'height', 'version',
        'versionHex', 'merkleroot', 'coinbase',
        'tx', 'time', 'mediantime', 'nonce',
        'bits', 'difficulty', 'chainwork',
        'nTx', 'previousblockhash', 'nextblockhash'
      ];

      for (const property of properties)
        assert(property in info);

      assert.strictEqual(node.chain.tip.bits, parseInt(info.bits, 16));
      assert.strictEqual(util.revHex(node.chain.tip.merkleRoot), info.merkleroot);
      assert.strictEqual(util.revHex(node.chain.tip.hash), info.hash);
      assert.equal(node.chain.tip.version, info.version);
    });

    it('should return correct height', async () => {
      // Create an address to mine with.
      const wallet = await node.plugins.walletdb.wdb.get(0);
      const key = await wallet.createReceive(0);
      const address = key.getAddress().toString(node.network.type);

      // Mine two blocks.
      await nclient.execute('generatetoaddress', [2, address]);

      const info = await nclient.execute('getblock', [util.revHex(node.chain.tip.hash)]);

      // Assert the heights match.
      assert.strictEqual(node.chain.tip.height, info.height);
    });

    it('should return confirmations (main chain)', async () => {
      const {genesis} = node.network;
      const hash = genesis.hash.reverse().toString('hex');

      const info = await nclient.execute('getblock', [hash]);

      assert.strictEqual(node.chain.tip.height, info.confirmations - 1);
    });

    it('should return confirmations (orphan)', async () => {
      // Get the chain entry associated with
      // the genesis block.
      const {genesis} = node.network;
      let entry = await node.chain.getEntry(genesis.hash.reverse());

     // Get current chain tip and chain height
      const chainHeight = node.chain.tip.height + 1;
      const chainTip = util.revHex(node.chain.tip.hash);

      // Reorg from the genesis block.
      for (let i = 0; i < chainHeight; i++) {
        const block = await node.miner.mineBlock(entry);
        await node.chain.add(block);
        entry = await node.chain.getEntry(block.hash());
      }

      // Call getblock using the previous tip
      const info = await nclient.execute('getblock', [chainTip]);
      assert.strictEqual(info.confirmations, -1);
    });
  });

  describe('signmessagewithprivkey', function () {
    const message = 'This is just a test message';
    const privKeyWIF = 'cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N';
    const ring = KeyRing.fromSecret(privKeyWIF, 'regtest');

    const expectedSignature = 'INbVnW4e6PeRmsv2Qgu8NuopvrVjkcxob+sX8OcZG0SALh'
      + 'WybUjzMLPdAsXI46YZGb0KQTRii+wWIQzRpG/U+S0=';

    it('should sign message', async () => {
      const sig = await nclient.execute('signmessagewithprivkey', [
        privKeyWIF,
        message
      ]);

      assert.equal(sig, expectedSignature);
    });

    it('should fail on invalid privkey', async () => {
      const privKey = 'invalid priv key';

      await assert.rejects(async () => {
        await nclient.execute('signmessagewithprivkey', [
          privKey,
          message
        ]);
      }, {
        type: 'RPCError',
        message: 'Invalid key.'
      });
    });

    it('should fail on wrong network privkey', async () => {
      const privKeyWIF = ring.toSecret('main');

      await assert.rejects(async () => {
        await nclient.execute('signmessagewithprivkey', [
          privKeyWIF,
          message
        ]);
      }, {
        type: 'RPCError',
        message: 'Invalid key.'
      });
    });
  });

  describe('verifymessage', function() {
    const message = 'This is just a test message';
    const address = 'mpLQjfK79b7CCV4VMJWEWAj5Mpx8Up5zxB';
    const signature = 'INbVnW4e6PeRmsv2Qgu8NuopvrVjkcxob+sX8OcZG0SALh'
      + 'WybUjzMLPdAsXI46YZGb0KQTRii+wWIQzRpG/U+S0=';

    it('should verify correct signature', async () => {
      const result = await nclient.execute('verifymessage', [
        address,
        signature,
        message
      ]);

      assert.equal(result, true);
    });

    it('should verify invalid signature', async () => {
      const result = await nclient.execute('verifymessage', [
        address,
        signature,
        'different message.'
      ]);

      assert.equal(result, false);
    });

    it('should fail on invalid address', async () => {
      await assert.rejects(async () => {
        await nclient.execute('verifymessage', [
          'Invalid address',
          signature,
          message
        ]);
      }, {
        type: 'RPCError',
        message: 'Invalid address.'
      });
    });

    it('should fail on invalid signature', async () => {
      await assert.rejects(async () => {
        await nclient.execute('verifymessage', [
          address,
          '.',
          message
        ]);
      }, {
        type: 'RPCError',
        message: 'Invalid signature length'
      });
    });
  });
});
