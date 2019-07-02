/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const FullNode = require('../lib/node/fullnode');

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

const {NodeClient} = require('bclient');

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

  it('should rpc getinfo', async () => {
    const info = await nclient.execute('getinfo', []);
    assert.strictEqual(info.blocks, 0);
  });
});
