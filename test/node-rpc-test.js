/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const FullNode = require('../lib/node/fullnode');
const pkg = require('../lib/pkg');
const {NodeClient} = require('bclient');

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
  }});

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

  describe('help', function() {
    it('should list all methods', async () => {
      const response = await nclient.execute('help', []);
      const lines = response.split('\n');

      assert(response);
      assert(lines.length);

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

  describe('getinfo', function() {
    it('should return info', async () => {
      const chain = node.require('chain');
      const info = await nclient.execute('getinfo', []);

      assert.strictEqual(info.version, pkg.version);
      assert.strictEqual(info.blocks, chain.height);
      assert.strictEqual(info.testnet, true);

      // defaults, wallet is no longer in node.
      assert.strictEqual(info.walletversion, 0);
      assert.strictEqual(info.balance, 0);
      assert.strictEqual(info.keypoololdest, 0);
      assert.strictEqual(info.keypoolsize, 0);
      assert.strictEqual(info.unlocked_until, 0);
    });

    it('should return correct time offset', async () => {
      {
        const info = await nclient.execute('getinfo', []);

        assert.strictEqual(info.timeoffset, 0);
      }

      {
        const now = node.network.now();
        await nclient.execute('setmocktime', [now + 1000]);

        const info = await nclient.execute('getinfo', []);
        assert.strictEqual(info.timeoffset, 1000);
      }

      {
        // recover
        const now = node.network.now();
        await nclient.execute('setmocktime', [now - 1000]);

        const info = await nclient.execute('getinfo', []);
        assert.strictEqual(info.timeoffset, 0);
      }
    });
  });
});
