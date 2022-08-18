/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const consensus = require('../lib/protocol/consensus');
const Address = require('../lib/primitives/address');
const Outpoint = require('../lib/primitives/outpoint');
const Witness = require('../lib/script/witness');
const MTX = require('../lib/primitives/mtx');
const FullNode = require('../lib/node/fullnode');

if (process.browser)
  return;

const ports = {
  p2p: 49331,
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
  env: {
    'BCOIN_WALLET_HTTP_PORT': ports.wallet.toString()
  }});

const {WalletClient} = require('../lib/client');

const wclient = new WalletClient({
  port: ports.wallet,
  apiKey: 'foo'
});

let wallet = null;

const {wdb} = node.require('walletdb');

let addr = null;
let hash = null;
let txFee = 0;

const coinValue = 50000;
const witnessOptions = [true, false];
const wallets = ['primary'];

for (const witnessOpt of witnessOptions) {
  describe(`Wallet HTTP - witness: ${witnessOpt}`, function() {
    this.timeout(15000);

    const name = `test_sw-${witnessOpt}`;

    const actualCoinbaseMaturity = consensus.COINBASE_MATURITY;
    before(async () => {
      consensus.COINBASE_MATURITY = 0;
      await node.open();
      await wclient.open();
    });

    after(async () => {
      consensus.COINBASE_MATURITY = actualCoinbaseMaturity;
      await wclient.close();
      await node.close();
    });

    it('should create wallet', async () => {
      const info = await wclient.createWallet(name, {witness: witnessOpt});
      wallets.push(name);
      assert.strictEqual(info.id, name);
      wallet = wclient.wallet(name, info.token);
      await wallet.open();
    });

    it('should list wallets', async () => {
      const info = await wclient.getWallets();
      assert.deepEqual(info, wallets);
    });

    it('should get wallet info', async () => {
      const info = await wallet.getInfo();
      assert.strictEqual(info.id, name);
      const acct = await wallet.getAccount('default');
      const str = acct.receiveAddress;
      assert(typeof str === 'string');
      addr = Address.fromString(str, node.network);
    });

    it('should change passphrase', async () => {
      await wallet.setPassphrase('initial');

      // Incorrect Passphrase should not work
      await assert.rejects(async () => {
        await wallet.unlock('badpass');
      }, {
        name: 'Error',
        message: 'Could not decrypt.'
      });

      // Correct Passphrase should work
      const masterO1 = await wclient.getMaster(name);
      assert.equal(masterO1.encrypted, true);
      await wallet.unlock('initial');
      const masterO2 = await wclient.getMaster(name);
      assert.equal(masterO2.encrypted, false);

      await wallet.setPassphrase('newpass', 'initial');

      // Old Passphrase should not work
      await assert.rejects(async () => {
        await wallet.unlock('initial');
      }, {
        name: 'Error',
        message: 'Could not decrypt.'
      });

      // New Passphrase should work
      const masterN1 = await wclient.getMaster(name);
      assert.equal(masterN1.encrypted, true);
      await wallet.unlock('newpass', 15000);
      const masterN2 = await wclient.getMaster(name);
      assert.equal(masterN2.encrypted, false);
    });

    it('should enable seed phrase recovery', async () => {
      const options = {
        passphrase: 'PASSPHRASE',
        mnemonic: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'
      };
      const walletName = `test_seed-${witnessOpt}`;
      wallets.push(walletName);

      const testwallet = await wclient.createWallet(walletName, options);
      assert.strictEqual(testwallet.master.encrypted, false);

      const master1 = await wclient.getMaster(walletName);
      assert.strictEqual(master1.encrypted, false);
      assert.strictEqual(master1.mnemonic.phrase, options.mnemonic);

      await wclient.lock(walletName);
      const master2 = await wclient.getMaster(walletName);
      assert.strictEqual(master2.encrypted, true);
      assert.strictEqual(master2.mnemonic, undefined);

      await wclient.unlock(walletName, 'PASSPHRASE', 100);
      const master3 = await wclient.getMaster(walletName);
      assert.strictEqual(master3.encrypted, false);
      assert.strictEqual(master3.mnemonic.phrase, options.mnemonic);
    });

    it('should fill with funds', async () => {
      const mtx = new MTX();
      mtx.addOutpoint(new Outpoint(consensus.ZERO_HASH, 0));
      mtx.addOutput(addr, coinValue);
      mtx.addOutput(addr, coinValue);
      mtx.addOutput(addr, coinValue);
      mtx.addOutput(addr, coinValue);

      const tx = mtx.toTX();

      let balance = null;
      wallet.once('balance', (b) => {
        balance = b;
      });

      let receive = null;
      wallet.once('address', (r) => {
        receive = r[0];
      });

      let details = null;
      wallet.once('tx', (d) => {
        details = d;
      });

      await wdb.addTX(tx);
      await new Promise(r => setTimeout(r, 300));

      assert(receive);
      assert.strictEqual(receive.name, 'default');
      assert.strictEqual(receive.type, witnessOpt ? 'witness' : 'pubkeyhash');
      assert.strictEqual(receive.branch, 0);
      assert(balance);
      assert.strictEqual(balance.confirmed, 0);
      assert.strictEqual(balance.unconfirmed, coinValue * 4);
      assert(details);
      assert.strictEqual(details.hash, tx.txid());
    });

    it('should get balance', async () => {
      const balance = await wallet.getBalance();
      assert.strictEqual(balance.confirmed, 0);
      assert.strictEqual(balance.unconfirmed, coinValue * 4);
    });

    it('should send a tx', async () => {
      const options = {
        rate: 10000,
        useSelectEstimate: true,
        outputs: [{
          value: 10000,
          address: addr.toString(node.network)
        }]
      };

      const tx = await wallet.send(options);

      assert(tx);
      assert.strictEqual(tx.inputs.length, 1);
      assert.strictEqual(tx.outputs.length, 2);

      let value = 0;
      value += tx.outputs[0].value;
      value += tx.outputs[1].value;

      txFee = tx.fee;

      assert.strictEqual(value, coinValue - txFee);

      hash = tx.hash;
    });

    it('should get a tx', async () => {
      const tx = await wallet.getTX(hash);
      assert(tx);
      assert.strictEqual(tx.hash, hash);
    });

    it('should generate new api key', async () => {
      const old = wallet.token.toString('hex');
      const result = await wallet.retoken(null);
      assert.strictEqual(result.token.length, 64);
      assert.notStrictEqual(result.token, old);
    });

    it('should get balance', async () => {
      const balance = await wallet.getBalance();
      assert.strictEqual(balance.unconfirmed, coinValue * 4 - txFee);
    });

    it('should create account', async () => {
      const info = await wallet.createAccount('foo1');
      assert(info);
      assert(info.initialized);
      assert.strictEqual(info.name, 'foo1');
      assert.strictEqual(info.accountIndex, 1);
      assert.strictEqual(info.m, 1);
      assert.strictEqual(info.n, 1);
    });

    it('should create account', async () => {
      const info = await wallet.createAccount('foo2', {
        type: 'multisig',
        m: 1,
        n: 2
      });
      assert(info);
      assert(!info.initialized);
      assert.strictEqual(info.name, 'foo2');
      assert.strictEqual(info.accountIndex, 2);
      assert.strictEqual(info.m, 1);
      assert.strictEqual(info.n, 2);
    });

    for (const template of [true, false]) {
      const suffix = template ? 'with template' : 'without template';
      it(`should create and sign transaction ${suffix}`, async () => {
        const change = await wallet.createChange('default');
        const tx = await wallet.createTX({
          template: template, // should not matter, sign = true
          sign: true,
          outputs: [{
            address: change.address,
            value: 50000
          }]
        });
        const mtx = MTX.fromJSON(tx);

        for (const input of tx.inputs) {
          const vector = witnessOpt ? input.witness : input.script;

          assert.notStrictEqual(vector, '',
            'Input must be signed.');
        }

        assert.strictEqual(mtx.verify(), true,
          'Transaction must be signed.');
      });
    }

    it('should create transaction without template', async () => {
      const change = await wallet.createChange('default');
      const tx = await wallet.createTX({
        sign: false,
        outputs: [{
          address: change.address,
          value: 50000
        }]
      });

      for (const input of tx.inputs) {
        const script = input.script;

        assert.strictEqual(script.length, 0,
          'Input must not be templated.');
      }
    });

    it('should create transaction with template', async () => {
      const change = await wallet.createChange('default');
      const tx = await wallet.createTX({
        sign: false,
        template: true,
        useSelectEstimate: true,
        outputs: [{
          address: change.address,
          value: 20000
        }]
      });

      for (const input of tx.inputs) {
        if (witnessOpt) {
          // p2wpkh
          // [(empty placeholder), (33-byte pubkey)]
          const witness = Witness.fromRaw(Buffer.from(input.witness, 'hex'));
          assert.strictEqual(witness.items.length, 2);
          assert.strictEqual(witness.items[0].length, 0,
            'First item in stack must be a placeholder');
          assert.strictEqual(witness.items[1].length, 33);
        } else {
          // p2pkh
          // 1 (OP_0 placeholder) + 1 (length) + 33 (pubkey)
          const script = Buffer.from(input.script, 'hex');
          assert.strictEqual(script.length, 35);
          assert.strictEqual(script[0], 0x00,
            'First item in stack must be a placeholder OP_0');
        }
      }
    });
  });
}
