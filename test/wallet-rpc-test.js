/* eslint-env mocha */

'use strict';

const {NodeClient, WalletClient} = require('bclient');
const assert = require('./util/assert');
const FullNode = require('../lib/node/fullnode');
const Network = require('../lib/protocol/network');
const Mnemonic = require('../lib/hd/mnemonic');
const HDPrivateKey = require('../lib/hd/private');
const Script = require('../lib/script/script');
const Address = require('../lib/primitives/address');
const network = Network.get('regtest');
const mnemonics = require('./data/mnemonic-english.json');
// Commonly used test mnemonic
const phrase = mnemonics[0][1];

const ports = {
  p2p: 49331,
  node: 49332,
  wallet: 49333
};

const node = new FullNode({
  network: network.type,
  apiKey: 'bar',
  walletAuth: true,
  memory: true,
  workers: true,
  plugins: [require('../lib/wallet/plugin')],
  port: ports.p2p,
  httpPort: ports.node,
  env: {
    'BCOIN_WALLET_HTTP_PORT': ports.wallet.toString()
  }
});

const nclient = new NodeClient({
  port: ports.node,
  apiKey: 'bar'
});

const wclient = new WalletClient({
  port: ports.wallet,
  apiKey: 'bar'
});

describe('Wallet RPC Methods', function() {
  this.timeout(15000);

  // Define an account level hd extended public key to be
  // used to derive addresses throughout the test suite
  let xpub;

  before(async () => {
    await node.open();
    await nclient.open();
    await wclient.open();

    // Derive the xpub using the well known
    // mnemonic and network's coin type
    const mnemonic = Mnemonic.fromPhrase(phrase);
    const priv = HDPrivateKey.fromMnemonic(mnemonic);
    const type = network.keyPrefix.coinType;
    const key = priv.derive(44, true).derive(type, true).derive(0, true);

    xpub = key.toPublic();

    // Assert that the expected test phrase was
    // read from disk
    assert.equal(phrase, [
      'abandon', 'abandon', 'abandon', 'abandon',
      'abandon', 'abandon', 'abandon', 'abandon',
      'abandon', 'abandon', 'abandon', 'about'
    ].join(' '));
  });

  after(async () => {
    await nclient.close();
    await wclient.close();
    await node.close();
  });

  describe('getaddressinfo', () => {
    const watchOnlyWalletId = 'foo';
    const standardWalletId = 'bar';

    // m/44'/1'/0'/0/{0,1}
    const pubkeys = [
      Buffer.from('02a7451395735369f2ecdfc829c0f'
        + '774e88ef1303dfe5b2f04dbaab30a535dfdd6', 'hex'),
      Buffer.from('03589ae7c835ce76e23cf8feb32f1a'
        + 'df4a7f2ba0ed2ad70801802b0bcd70e99c1c', 'hex')
    ];

    // set up the initial testing state
    before(async () => {
      {
        // Set up the testing environment
        // by creating a wallet and a watch
        // only wallet
        const info = await nclient.getInfo();
        assert.equal(info.chain.height, 0);
      }

      {
        // Create a watch only wallet using the path
        // m/44'/1'/0' and assert that the wallet
        // was properly created
        const accountKey = xpub.xpubkey(network.type);
        const response = await wclient.createWallet(watchOnlyWalletId, {
          watchOnly: true,
          accountKey: accountKey
        });

        assert.equal(response.id, watchOnlyWalletId);

        const wallet = wclient.wallet(watchOnlyWalletId);
        const info = await wallet.getAccount('default');
        assert.equal(info.accountKey, accountKey);
        assert.equal(info.watchOnly, true);
      }

      {
        // Create a wallet that manages the private keys itself
        const response = await wclient.createWallet(standardWalletId);
        assert.equal(response.id, standardWalletId);

        const info = await wclient.getAccount(standardWalletId, 'default');
        assert.equal(info.watchOnly, false);
      };
    });

    // The rpc interface requires the wallet to be selected first
    it('should return iswatchonly correctly', async () => {
      // m/44'/1'/0'/0/0
      const receive = 'mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV';

      {
        await wclient.execute('selectwallet', [standardWalletId]);
        const response = await wclient.execute('getaddressinfo', [receive]);
        assert.equal(response.iswatchonly, false);
      }
      {
        await wclient.execute('selectwallet', [watchOnlyWalletId]);
        const response = await wclient.execute('getaddressinfo', [receive]);
        assert.equal(response.iswatchonly, true);
      }
    });

    it('should return the correct address', async () => {
      // m/44'/1'/0'/0/0
      const receive = 'mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV';

      await wclient.execute('selectwallet', [watchOnlyWalletId]);
      const response = await wclient.execute('getaddressinfo', [receive]);
      assert.equal(response.address, receive);
    });

    it('should detect owned address', async () => {
      // m/44'/1'/0'/0/0
      const receive = 'mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV';
      {
        await wclient.execute('selectwallet', [watchOnlyWalletId]);
        const response = await wclient.execute('getaddressinfo', [receive]);
        assert.equal(response.ismine, true);
      }
      {
        await wclient.execute('selectwallet', [standardWalletId]);
        const response = await wclient.execute('getaddressinfo', [receive]);
        assert.equal(response.ismine, false);
      }
    });

    it('should detect a p2sh address', async () => {
      const script = Script.fromMultisig(2, 2, pubkeys);
      const address = Address.fromScript(script);
      const addr = address.toString(network);
      const response = await wclient.execute('getaddressinfo', [addr]);

      assert.equal(response.isscript, true);
      assert.equal(response.iswitness, false);
      assert.equal(response.witness_program, undefined);
    });

    it('should return the correct program for a p2wpkh address', async () => {
      // m/44'/1'/0'/0/5
      const receive = 'bcrt1q53724q6cywuzsvq5e3nvdeuwrepu69jsc6ulmx';
      const addr = Address.fromString(receive);

      await wclient.execute('selectwallet', [watchOnlyWalletId]);
      const str = addr.toString(network);
      const response = await wclient.execute('getaddressinfo', [str]);
      assert.equal(response.witness_program, addr.hash.toString('hex'));
    });

    it('should detect p2wsh program', async () => {
      const script = Script.fromMultisig(2, 2, pubkeys);
      const address = Address.fromWitnessScripthash(script.sha256());
      const addr = address.toString(network);
      const response = await wclient.execute('getaddressinfo', [addr]);

      assert.equal(response.isscript, true);
      assert.equal(response.iswitness, true);
      assert.equal(response.witness_program, address.hash.toString('hex'));
    });

    it('should detect ismine up to the lookahead', async () => {
      const info = await wclient.getAccount(watchOnlyWalletId, 'default');
      await wclient.execute('selectwallet', [watchOnlyWalletId]);

      // m/44'/1'/0'
      const addresses = [
        'mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV', // /0/0
        'mzpbWabUQm1w8ijuJnAof5eiSTep27deVH', // /0/1
        'mnTkxhNkgx7TsZrEdRcPti564yQTzynGJp', // /0/2
        'mpW3iVi2Td1vqDK8Nfie29ddZXf9spmZkX', // /0/3
        'n2BMo5arHDyAK2CM8c56eoEd18uEkKnRLC', // /0/4
        'mvWgTTtQqZohUPnykucneWNXzM5PLj83an', // /0/5
        'muTU2Av1EwnsyhieQhyPL7hgEf883LR4xg', // /0/6
        'mwduZ8Ksa563v7rWdSPmqyKR4y2FeB5g8p', // /0/7
        'miyBE85ro5zt9RseSzYVEbB3TfzkxgSm8C', // /0/8
        'mnYwW7mU3jajB11vrpDZwZDrXwVfE5Jc31', // /0/9
        'mx3YNRT8Vg8QwFq5Z5MAVDDVHp4ihHsffn'  // /0/10
      ];

      // Assert that the lookahead is configured as expected
      // subtract one from addresses.length, it is 0 indexed
      assert.equal(addresses.length - 1, info.lookahead);

      // Each address through the lookahead number should
      // be recognized as an owned address
      for (let i = 0; i <= info.lookahead; i++) {
        const address = addresses[i];
        const response = await wclient.execute('getaddressinfo', [address]);
        assert.equal(response.ismine, true);
      }

      // m/44'/1'/0'/0/11
      // This address is outside of the lookahead range
      const failed = 'myHL2QuECVYkx9Y94gyC6RSweLNnteETsB';

      const response = await wclient.execute('getaddressinfo', [failed]);
      assert.equal(response.ismine, false);
    });

    it('should detect change addresses', async () => {
      // m/44'/1'/0'/1/0
      const address = 'mi8nhzZgGZQthq6DQHbru9crMDerUdTKva';
      const info = await wclient.execute('getaddressinfo', [address]);

      assert.equal(info.ischange, true);
    });

    it('should throw for the wrong network', async () => {
      // m/44'/1'/0'/0/0
      const failed = '16JcQVoL61QsLCPS6ek8UJZ52eRfaFqLJt';

      // Match the bitcoind response when sending the incorrect
      // network. Expect an RPC error
      const fn = async () => await wclient.execute('getaddressinfo', [failed]);
      await assert.asyncThrows(fn, 'Invalid address.');
    });

    it('should fail for invalid address', async () => {
      // m/44'/1'/0'/0/0
      let failed = '16JcQVoL61QsLCPS6ek8UJZ52eRfaFqLJt';
      // remove the first character
      failed = failed.slice(1, failed.length);

      const fn = async () => await wclient.execute('getaddressinfo', [failed]);
      await assert.asyncThrows(fn, 'Invalid address.');
    });
  });
});
