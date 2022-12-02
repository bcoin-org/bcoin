/* eslint-env mocha */

'use strict';

const {NodeClient, WalletClient} = require('../lib/client');
const assert = require('bsert');
const consensus = require('../lib/protocol/consensus');
const FullNode = require('../lib/node/fullnode');
const Network = require('../lib/protocol/network');
const Mnemonic = require('../lib/hd/mnemonic');
const HDPrivateKey = require('../lib/hd/private');
const Script = require('../lib/script/script');
const Address = require('../lib/primitives/address');
const TX = require('../lib/primitives/tx');
const mnemonics = require('./data/mnemonic-english.json');
const {forValue} = require('./util/common');

// Commonly used test mnemonic
const phrase = mnemonics[0][1];

const network = Network.get('regtest');

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
  workersSize: 2,
  indexTX: true,
  indexAddress: true,
  plugins: [require('../lib/wallet/plugin')],
  port: ports.p2p,
  httpPort: ports.node,
  env: {
    'BCOIN_WALLET_HTTP_PORT': ports.wallet.toString()
  }
});

const {wdb} = node.require('walletdb');

const nclient = new NodeClient({
  host: '127.0.0.1',
  port: ports.node,
  apiKey: 'bar',
  timeout: 15000
});

const wclient = new WalletClient({
  host: '127.0.0.1',
  port: ports.wallet,
  apiKey: 'bar'
});

describe('Wallet RPC Methods', function() {
  this.timeout(15000);

  // Define an account level hd extended public key to be
  // used to derive addresses throughout the test suite
  let xpub;
  let xpub2;

  let walletHot = null;
  let walletMiner = null;
  let addressHot = null;
  let addressMiner = null;
  let utxo = null;

  before(async () => {
    await node.open();

    // Derive the xpub using the well known
    // mnemonic and network's coin type
    const mnemonic = Mnemonic.fromPhrase(phrase);
    const priv = HDPrivateKey.fromMnemonic(mnemonic);
    const type = network.keyPrefix.coinType;
    const key = priv.derive(44, true).derive(type, true).derive(0, true);
    const key2 = priv.derive(44, true).derive(type, true).derive(1, true);

    xpub = key.toPublic();
    xpub2 = key2.toPublic();

    // Assert that the expected test phrase was
    // read from disk
    assert.equal(phrase, [
      'abandon', 'abandon', 'abandon', 'abandon',
      'abandon', 'abandon', 'abandon', 'abandon',
      'abandon', 'abandon', 'abandon', 'about'
    ].join(' '));

    // Create wallets.
    {
      const walletInfo = await wclient.createWallet('hot');
      walletHot = wclient.wallet('hot', walletInfo.token);

      const account = await walletHot.getAccount('default');
      addressHot = account.receiveAddress;
    }

    {
      const walletInfo = await wclient.createWallet('miner');
      walletMiner = wclient.wallet('miner', walletInfo.token);

      const account = await walletMiner.getAccount('default');
      addressMiner = account.receiveAddress;
    }

    await nclient.execute('generatetoaddress', [102, addressMiner]);
    await forValue(wdb, 'height', 102);
  });

  after(async () => {
    await node.close();
  });

  it('should rpc help', async () => {
    assert(await wclient.execute('help', []));

    await assert.rejects(async () => {
      await wclient.execute('help', ['getbalance']);
    }, {
      name: 'Error',
      message: /^getbalance/
    });
  });

  it('should rpc selectwallet', async () => {
    for (const wname of ['hot', 'miner']) {
      const response = await wclient.execute('selectwallet', [wname]);
      assert.strictEqual(response, null);

      const info = await wclient.execute('getwalletinfo');
      assert.strictEqual(info.walletid, wname);
    }
  });

  it('should rpc getnewaddress from default account', async () => {
    const acctAddr = await wclient.execute('getnewaddress', []);
    assert(Address.fromString(acctAddr.toString()));
  });

  it('should rpc sendtoaddress', async () => {
    await wclient.execute('selectwallet', ['miner']);

    const txid = await wclient.execute('sendtoaddress', [addressHot, 0.1234, '', '', false, true]);
    assert.strictEqual(txid.length, 64);
  });

  it('should rpc getaccountaddress', async () => {
    addressMiner = await wclient.execute('getaccountaddress', ['default']);
    assert(Address.fromString(addressMiner.toString()));
  });

  it('should fail rpc getnewaddress from nonexistent account', async () => {
    await assert.rejects(async () => {
      await wclient.execute('getnewaddress', ['bad-account-name']);
    }, {
      name: 'Error',
      message: 'Account not found.'
    });
  });

  it('should rpc sendmany', async () => {
    const sendTo = {};
    sendTo[addressHot] = 1.0;
    sendTo[addressMiner] = 0.1111;
    const txid = await wclient.execute('sendmany', ['default', sendTo, 1, '', false, true]);
    assert.strictEqual(txid.length, 64);
  });

  it('should fail malformed rpc sendmany', async () => {
    await assert.rejects(async () => {
      await wclient.execute('sendmany', ['default', null]);
    }, {
      name: 'Error',
      message: 'Invalid send-to address.'
    });

    const sendTo = {};
    sendTo[addressHot] = null;
    await assert.rejects(async () => {
      await wclient.execute('sendmany', ['default', sendTo, 1, '', false, true]);
    }, {
      name: 'Error',
      message: 'Invalid amount.'
    });
  });

  it('should rpc listreceivedbyaddress', async () => {
    await wclient.execute('selectwallet', ['hot']);

    const listZeroConf = await wclient.execute('listreceivedbyaddress',
      [0, false, false]);
    assert.deepStrictEqual(listZeroConf, [{
      'involvesWatchonly': false,
      'address': addressHot,
      'account': 'default',
      'amount': 1.1234,
      'confirmations': 0,
      'label': ''
    }]);

    await nclient.execute('generatetoaddress', [1, addressMiner]);
    await wdb.syncChain();

    const listSomeConf = await wclient.execute('listreceivedbyaddress',
      [1, false, false]);
    assert.deepStrictEqual(listSomeConf, [{
      'involvesWatchonly': false,
      'address': addressHot,
      'account': 'default',
      'amount': 1.1234,
      'confirmations': 1,
      'label': ''
    }]);

    const listTooManyConf = await wclient.execute('listreceivedbyaddress',
      [100, false, false]);
    assert.deepStrictEqual(listTooManyConf, []);
  });

  it('should rpc getreceivedbyaddress', async () => {
    const addressOther = await wclient.execute('getnewaddress', []);

    const result1 = await wclient.execute(
      'getreceivedbyaddress',
      [addressOther]
    );

    // Same as before
    assert.strictEqual(result1, 0);

    // Send a coinbase TX which also has an OP_RETURN (witness commitment)
    await nclient.execute('generatetoaddress', [1, addressOther]);
    await wdb.syncChain();

    const result2 = await wclient.execute(
      'getreceivedbyaddress',
      [addressOther]
    );

    // Same as before
    assert.strictEqual(result2, 50);
  });

  it('should rpc listtransactions with no args', async () => {
    const txs = await wclient.execute('listtransactions', []);
    assert.strictEqual(txs.length, 3);
    assert.strictEqual(txs[0].amount + txs[1].amount + txs[2].amount, 51.1234);
    assert.strictEqual(txs[0].account, 'default');
  });

  it('should rpc listtransactions from specified account', async () => {
    const wallet = await wclient.wallet('hot');
    await wallet.createAccount('foo');

    const txs = await wclient.execute('listtransactions', ['foo']);
    assert.strictEqual(txs.length, 0);
  });

  it('should fail rpc listtransactions from nonexistent account', async () => {
    assert.rejects(async () => {
      await wclient.execute('listtransactions', ['nonexistent']);
    }, {
      name: 'Error',
      message: 'Account not found.'
    });
  });

  it('should rpc listunspent', async () => {
    utxo = await wclient.execute('listunspent', []);
    assert.strictEqual(utxo.length, 3);
  });

  it('should rpc lockunspent and listlockunspent', async () => {
    let result = await wclient.execute('listlockunspent', []);
    assert.deepStrictEqual(result, []);

    // lock one utxo
    const output = utxo[0];
    const outputsToLock = [{'txid': output.txid, 'vout': output.vout}];
    result = await wclient.execute('lockunspent', [false, outputsToLock]);
    assert(result);

    result = await wclient.execute('listlockunspent', []);
    assert.deepStrictEqual(result, outputsToLock);

    // unlock all
    result = await wclient.execute('lockunspent', [true]);
    assert(result);

    result = await wclient.execute('listlockunspent', []);
    assert.deepStrictEqual(result, []);
  });

  it('should rpc listsinceblock', async () => {
    const listNoBlock = await wclient.execute('listsinceblock', []);
    assert.strictEqual(listNoBlock.transactions.length, 1);

    const txs = listNoBlock.transactions;

    // Sort transactions by blockheight
    txs.sort((a, b) => a.blockheight - b.blockheight);

    // get lowest block hash.
    const bhash = txs[0].blockhash;
    const listOldBlock = await wclient.execute('listsinceblock', [bhash]);
    assert.strictEqual(listOldBlock.transactions.length, 1);

    const nonexistentBlock = consensus.ZERO_HASH.toString('hex');
    await assert.rejects(async () => {
      await wclient.execute('listsinceblock', [nonexistentBlock]);
    }, {
      name: 'Error',
      message: 'Block not found.'
    });
  });

  it('should rpc importpubkey rescan = false', async () => {
    // creating new watchOnly wallet
    const accountKey = xpub2.xpubkey(network.type);
    const response = await wclient.createWallet('watchonly', {
      watchOnly: true,
      accountKey: accountKey
    });

    assert.equal(response.id, 'watchonly');
    assert.equal(response.watchOnly, true);

    const wallet = await wclient.wallet('hot');
    const {address, publicKey} = await wallet.createAddress('default');

    await nclient.execute('generatetoaddress', [1, address]);

    const watchOnlyWallet = await wclient.wallet('watchonly');

    let balance;
    balance = await watchOnlyWallet.getBalance();
    assert.equal(balance.coin, 0);
    assert.equal(balance.confirmed, 0);

    // default rescan = false
    await watchOnlyWallet.importPublic('default', publicKey);
    balance = await watchOnlyWallet.getBalance();
    assert.equal(balance.coin, 0);
    assert.equal(balance.confirmed, 0);
  });

  it('should rpc rescan watchonly wallet', async () => {
    await wclient.execute('selectwallet', ['watchonly']);
    await wclient.execute('rescan', [0]);
    const balance = await wclient.execute('getbalance',  ['', 1, true]);

    assert.equal(balance, 50);

    // changing wallet to primary for further tests
    await wclient.execute('selectwallet', ['primary']);
  });

  it('should not abort rescan if WalletDB is not rescanning.', async () => {
    await assert.rejects(
      wclient.execute('abortrescan'),
      {message: 'WalletDB is not rescanning.'}
    );
  });

  it('should rpc abortRescan', async () => {
    assert.strictEqual(wdb.height, 105);
    assert.strictEqual(wdb.height, node.chain.height);

    const handler = async (wallet, data, details) => {
      if (details.height === 51) {
        await wclient.execute('abortrescan');
      }
    };

    wdb.on('confirmed', handler);

    await wclient.execute('rescan', [0]);

    // Can not garuntee where rescan will stop due to async
    assert(wdb.height > 50);
    assert(wdb.height < 60);
    wdb.removeListener('confirmed', handler);
  });

  it('should not "rollback to the future"', async () => {
    await assert.rejects(
      wclient.execute('rescan', [60]),
      {message: 'WDB: Cannot rollback to the future.'}
    );
  });

  it('should rpc rescan and finish rescan after abort', async () => {
    await wclient.execute('rescan', [40]);
    assert.strictEqual(wdb.height, 105);
    assert.strictEqual(wdb.height, node.chain.height);
  });

  describe('signmessage', function() {
    const nonWalletAddress = '2N2PyYb9yKLhFzYfdWLr6LNsdzC9keVgK6f';
    const message = 'This is just a test message';

    it('should signmessage with address', async () => {
      const address = await wclient.execute('getnewaddress');

      const signature = await wclient.execute('signmessage', [
        address,
        message
      ]);

      const verify = await nclient.execute('verifymessage', [
        address,
        signature,
        message
      ]);

      assert.strictEqual(verify, true);
    });

    it('should fail with invalid address', async () => {
      await assert.rejects(async () => {
        await wclient.execute('signmessage', [
          'invalid address format',
          message
        ]);
      }, {
        type: 'RPCError',
        message: 'Invalid address.'
      });
    });

    it('should fail with non-wallet address.', async () => {
      await assert.rejects(async () => {
        await wclient.execute('signmessage', [
          nonWalletAddress,
          message
        ]);
      }, {
        type: 'RPCError',
        message: 'Address not found.'
      });
    });
  });

  describe('getaddressinfo', () => {
    const watchOnlyWalletId = 'getaddressinfo-foo';
    const standardWalletId = 'getaddressinfo-bar';

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
      await assert.rejects(fn, {
        name: 'Error',
        message: 'Invalid address.'
      });
    });

    it('should fail for invalid address', async () => {
      // m/44'/1'/0'/0/0
      let failed = '16JcQVoL61QsLCPS6ek8UJZ52eRfaFqLJt';
      // remove the first character
      failed = failed.slice(1, failed.length);

      const fn = async () => await wclient.execute('getaddressinfo', [failed]);
      await assert.rejects(fn, {
        name: 'Error',
        message: 'Invalid address.'
      });
    });
  });

  describe('importprunedfunds', function() {
    it('will remove and import a tx into the wallet', async () => {
      const response = await wclient.createWallet('import');
      assert.equal(response.id, 'import');
      const wallet = wclient.wallet('import');
      const account = await wallet.getAccount('default');
      assert.equal(account.watchOnly, false);
      const address = account.receiveAddress;

      await wclient.execute('selectwallet', ['miner']);
      const txid = await wclient.execute('sendtoaddress', [address, 0.01843, '', '', false, true]);
      await wclient.execute('selectwallet', ['import']);

      const blocks = await nclient.execute('generatetoaddress', [1, addressMiner]);
      assert.equal(blocks.length, 1);

      const txoutproof = await nclient.execute('gettxoutproof', [[txid], blocks[0]]);
      assert(txoutproof);

      const txraw = await nclient.execute('getrawtransaction', [txid, 0]);
      assert(txraw);

      let balance = await wclient.execute('getbalance');
      assert.equal(balance, 0.01843);

      await wclient.execute('removeprunedfunds', [txid]);
      balance = await wclient.execute('getbalance');
      assert.equal(balance, 0);

      await wclient.execute('importprunedfunds', [txraw, txoutproof]);
      balance = await wclient.execute('getbalance');
      assert.equal(balance, 0.01843);
    });
  });

  describe('raw TXs', function() {
    // 0-in, 2-out
    const rawTX1 =
      '0100000000024e61bc00000000001976a914fbdd46898a6d70a682cbd34420cc' +
      'f0b6bb64493788acf67e4929010000001976a9141b002b6fc0f457bf8d092722' +
      '510fce9f37f0423b88ac00000000';

    let fundedTX1;

    before(async () => {
      await wclient.execute('selectwallet', ['miner']);
    });

    it('should fundrawtransaction', async () => {
      const result = await wclient.execute('fundrawtransaction', [rawTX1]);
      assert(result.hex.length);
      assert(result.changepos > 0);
      assert(result.fee > 0);

      fundedTX1 = TX.fromRaw(result.hex, 'hex');
      assert.strictEqual(fundedTX1.inputs.length, 1);
      assert.strictEqual(fundedTX1.outputs.length, 3);
    });
  });
});
