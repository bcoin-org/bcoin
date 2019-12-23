/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const FullNode = require('../lib/node/fullnode');
const NodeClient = require('../lib/client/node');
const KeyRing = require('../lib/primitives/keyring');

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
  }
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

  describe('getblock', function () {
    it('should rpc getblock', async () => {
      const {chain} = await nclient.getInfo();
      const info = await nclient.execute('getblock', [chain.tip]);

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

      assert.deepEqual(chain.height, info.height);
      assert.deepEqual(chain.tip, info.hash);
      assert.equal(info.bits, '207fffff');
    });

    it('should return correct height', async () => {
      // Create an address to mine with.
      const wallet = await node.plugins.walletdb.wdb.get(0);
      const key = await wallet.createReceive(0);
      const address = key.getAddress().toString(node.network.type);

      // Mine two blocks.
      await nclient.execute('generatetoaddress', [2, address]);

      const {chain} = await nclient.getInfo();
      const info = await nclient.execute('getblock', [chain.tip]);

      // Assert the heights match.
      assert.deepEqual(chain.height, info.height);
    });

    it('should return confirmations (main chain)', async () => {
      const {chain} = await nclient.getInfo();

      const {genesis} = node.network;
      const hash = genesis.hash.reverse().toString('hex');

      const info = await nclient.execute('getblock', [hash]);

      assert.deepEqual(chain.height, info.confirmations - 1);
    });

    it('should return confirmations (orphan)', async () => {
      // Get the current chain state
      const {chain} = await nclient.getInfo();

      // Get the chain entry associated with
      // the genesis block.
      const {genesis} = node.network;
      let entry = await node.chain.getEntry(genesis.hash.reverse());

      // Reorg from the genesis block.
      for (let i = 0; i < chain.height + 1; i++) {
        const block = await node.miner.mineBlock(entry);
        await node.chain.add(block);
        entry = await node.chain.getEntry(block.hash());
      }

      // Call getblock using the previous tip
      const info = await nclient.execute('getblock', [chain.tip]);
      assert.deepEqual(info.confirmations, -1);
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
