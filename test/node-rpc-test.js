/* eslint-env mocha */
/* eslint-disable quotes */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const FullNode = require('../lib/node/fullnode');
const NodeClient = require('../lib/client/node');
const KeyRing = require('../lib/primitives/keyring');
const Block = require('../lib/primitives/block');
const util = require('../lib/utils/util');
const NetAddress = require('../lib/net/netaddress');
const {createChecksum} = require("../lib/descriptor/common");

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
  indexFilter: true,
  workers: true,
  workersSize: 2,
  plugins: [require('../lib/wallet/plugin')],
  port: ports.p2p,
  httpPort: ports.node,
  env: {
    'BCOIN_WALLET_HTTP_PORT': ports.wallet.toString()
  },
  listen: true,
  publicHost: '123.123.123.123'
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

  it('should rpc getdescriptorinfo', async () => {
    const testcases = [
      {
        "input": "sh(wsh(sortedmulti(2,[e7dd1c50/48'/1'/40'/1']tpubDFh3VaUEs71ZMcVBmscSSnP4f4r6TvnLssu8yXvpj3uMfAehciMYTrgbfu4KCxXb7oSaz4kriuWRZtQVhZR2oA9toob6aELnsYLN94fXQLF/*,[e7dd1c50/48'/1'/20'/1']tpubDFPemvLnpMqE1BPuturDUh46KxsR8wGSQrA6HofYE7fqxpMAKCcoYWHGA46B6zKY4xcQAc1vLFTcqQ9BvsbHZ4UhzqqF5nUeeNBjNivHxPT/*,[aedb3d12/48'/1'/0'/1']tpubDEbuxto5Kftus28NyPddiEev2yUhzZGpkpQdCK732KBge5FJDhaMdhG1iVw3rMJ2qvABkaLR9HxobkeFkmQZ4RqQgN1KJadDjPn9ANBLo8V/*)))",
        "descriptor": "sh(wsh(sortedmulti(2,[e7dd1c50/48'/1'/40'/1']tpubDFh3VaUEs71ZMcVBmscSSnP4f4r6TvnLssu8yXvpj3uMfAehciMYTrgbfu4KCxXb7oSaz4kriuWRZtQVhZR2oA9toob6aELnsYLN94fXQLF/*,[e7dd1c50/48'/1'/20'/1']tpubDFPemvLnpMqE1BPuturDUh46KxsR8wGSQrA6HofYE7fqxpMAKCcoYWHGA46B6zKY4xcQAc1vLFTcqQ9BvsbHZ4UhzqqF5nUeeNBjNivHxPT/*,[aedb3d12/48'/1'/0'/1']tpubDEbuxto5Kftus28NyPddiEev2yUhzZGpkpQdCK732KBge5FJDhaMdhG1iVw3rMJ2qvABkaLR9HxobkeFkmQZ4RqQgN1KJadDjPn9ANBLo8V/*)))#zlh5y6z5",
        "checksum": "zlh5y6z5",
        "isrange": true,
        "issolvable": true,
        "hasprivatekeys": false
      },
      {
        "input": "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))",
        "descriptor": "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))#2wtr0ej5",
        "checksum": "2wtr0ej5",
        "isrange": false,
        "issolvable": true,
        "hasprivatekeys": false
      },
      {
        "input": "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        "descriptor": "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))#qkrrc7je",
        "checksum": "qkrrc7je",
        "isrange": false,
        "issolvable": true,
        "hasprivatekeys": false
      },
      {
        "input": "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))",
        "descriptor": "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))#y9zthqta",
        "checksum": "y9zthqta",
        "isrange": false,
        "issolvable": true,
        "hasprivatekeys": false
      },
      {
        "input": "sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        "descriptor": "sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))#s53ls94y",
        "checksum": "s53ls94y",
        "isrange": false,
        "issolvable": true,
        "hasprivatekeys": false
      },
      {
        "input": "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))",
        "descriptor": "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))#ks05yr6p",
        "checksum": "ks05yr6p",
        "isrange": false,
        "issolvable": true,
        "hasprivatekeys": false
      },
      {
        "input": "sh(wsh(sortedmulti(2,[e7dd1c50/48'/1'/40'/1']tpubDFh3VaUEs71ZMcVBmscSSnP4f4r6TvnLssu8yXvpj3uMfAehciMYTrgbfu4KCxXb7oSaz4kriuWRZtQVhZR2oA9toob6aELnsYLN94fXQLF/*,[e7dd1c50/48'/1'/20'/1']tpubDFPemvLnpMqE1BPuturDUh46KxsR8wGSQrA6HofYE7fqxpMAKCcoYWHGA46B6zKY4xcQAc1vLFTcqQ9BvsbHZ4UhzqqF5nUeeNBjNivHxPT/*,[aedb3d12/48'/1'/0'/1']tpubDEbuxto5Kftus28NyPddiEev2yUhzZGpkpQdCK732KBge5FJDhaMdhG1iVw3rMJ2qvABkaLR9HxobkeFkmQZ4RqQgN1KJadDjPn9ANBLo8V/*)))",
        "descriptor": "sh(wsh(sortedmulti(2,[e7dd1c50/48'/1'/40'/1']tpubDFh3VaUEs71ZMcVBmscSSnP4f4r6TvnLssu8yXvpj3uMfAehciMYTrgbfu4KCxXb7oSaz4kriuWRZtQVhZR2oA9toob6aELnsYLN94fXQLF/*,[e7dd1c50/48'/1'/20'/1']tpubDFPemvLnpMqE1BPuturDUh46KxsR8wGSQrA6HofYE7fqxpMAKCcoYWHGA46B6zKY4xcQAc1vLFTcqQ9BvsbHZ4UhzqqF5nUeeNBjNivHxPT/*,[aedb3d12/48'/1'/0'/1']tpubDEbuxto5Kftus28NyPddiEev2yUhzZGpkpQdCK732KBge5FJDhaMdhG1iVw3rMJ2qvABkaLR9HxobkeFkmQZ4RqQgN1KJadDjPn9ANBLo8V/*)))#zlh5y6z5",
        "checksum": "zlh5y6z5",
        "isrange": true,
        "issolvable": true,
        "hasprivatekeys": false
      },
      {
        "input": "pkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1'/2)",
        "descriptor": "pkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1'/2)#hvxe7cts",
        "checksum": "hvxe7cts",
        "isrange": false,
        "issolvable": true,
        "hasprivatekeys": false
      },
      {
        "input": "wsh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
        "error": "Invalid descriptor: Can not have wpkh() inside wsh()"
      },
      {
        "input": "wsh(wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
        "error": "Invalid descriptor: Can not have wsh() inside wsh()"
      },
      {
        "input": "wsh(sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
        "error": "Invalid descriptor: Can not have sh() inside wsh()"
      },
      {
        "input": "wsh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        "error": "Invalid descriptor: A valid function is needed inside wsh()"
      }
    ];

    for (const test of testcases) {
      try {
        const result = await nclient.execute("getdescriptorinfo", [test.input]);
        assert.deepStrictEqual(result.descriptor, test.descriptor);
        assert.deepStrictEqual(result.checksum, createChecksum(test.input.split("#")[0]));
        assert.deepStrictEqual(result.isrange, test.isrange);
        assert.deepStrictEqual(result.issolvable, test.issolvable);
        assert.deepStrictEqual(result.hasprivatekeys, test.hasprivatekeys);
      } catch (e) {
        assert.strictEqual(e.message, test.error);
      }
    }
  });

  it('should rpc deriveaddresses', async () => {
    const data = [
      {
        "input": "sh(wsh(sortedmulti(2,[e7dd1c50/48'/1'/40'/1']tpubDFh3VaUEs71ZMcVBmscSSnP4f4r6TvnLssu8yXvpj3uMfAehciMYTrgbfu4KCxXb7oSaz4kriuWRZtQVhZR2oA9toob6aELnsYLN94fXQLF/*,[e7dd1c50/48'/1'/20'/1']tpubDFPemvLnpMqE1BPuturDUh46KxsR8wGSQrA6HofYE7fqxpMAKCcoYWHGA46B6zKY4xcQAc1vLFTcqQ9BvsbHZ4UhzqqF5nUeeNBjNivHxPT/*,[aedb3d12/48'/1'/0'/1']tpubDEbuxto5Kftus28NyPddiEev2yUhzZGpkpQdCK732KBge5FJDhaMdhG1iVw3rMJ2qvABkaLR9HxobkeFkmQZ4RqQgN1KJadDjPn9ANBLo8V/*)))#zlh5y6z5",
        "range": [0, "a"],
        "error": "Range end must be an integer"
      },
      {
        "input": "sh(wsh(sortedmulti(2,[e7dd1c50/48'/1'/40'/1']tpubDFh3VaUEs71ZMcVBmscSSnP4f4r6TvnLssu8yXvpj3uMfAehciMYTrgbfu4KCxXb7oSaz4kriuWRZtQVhZR2oA9toob6aELnsYLN94fXQLF/*,[e7dd1c50/48'/1'/20'/1']tpubDFPemvLnpMqE1BPuturDUh46KxsR8wGSQrA6HofYE7fqxpMAKCcoYWHGA46B6zKY4xcQAc1vLFTcqQ9BvsbHZ4UhzqqF5nUeeNBjNivHxPT/*,[aedb3d12/48'/1'/0'/1']tpubDEbuxto5Kftus28NyPddiEev2yUhzZGpkpQdCK732KBge5FJDhaMdhG1iVw3rMJ2qvABkaLR9HxobkeFkmQZ4RqQgN1KJadDjPn9ANBLo8V/*)))#zlh5y6z5",
        "range": [10, 0],
        "error": "Range specified as [begin,end] must not have begin after end"
      },
      {
        "input": "sh(wsh(sortedmulti(2,[e7dd1c50/48'/1'/40'/1']tpubDFh3VaUEs71ZMcVBmscSSnP4f4r6TvnLssu8yXvpj3uMfAehciMYTrgbfu4KCxXb7oSaz4kriuWRZtQVhZR2oA9toob6aELnsYLN94fXQLF/*,[e7dd1c50/48'/1'/20'/1']tpubDFPemvLnpMqE1BPuturDUh46KxsR8wGSQrA6HofYE7fqxpMAKCcoYWHGA46B6zKY4xcQAc1vLFTcqQ9BvsbHZ4UhzqqF5nUeeNBjNivHxPT/*,[aedb3d12/48'/1'/0'/1']tpubDEbuxto5Kftus28NyPddiEev2yUhzZGpkpQdCK732KBge5FJDhaMdhG1iVw3rMJ2qvABkaLR9HxobkeFkmQZ4RqQgN1KJadDjPn9ANBLo8V/*)))#zlh5y6z5",
        "range": [-1, 2],
        "error": "Range should be >= 0"
      },
      {
        "input": "sh(wsh(sortedmulti(2,[e7dd1c50/48'/1'/40'/1']tpubDFh3VaUEs71ZMcVBmscSSnP4f4r6TvnLssu8yXvpj3uMfAehciMYTrgbfu4KCxXb7oSaz4kriuWRZtQVhZR2oA9toob6aELnsYLN94fXQLF/*,[e7dd1c50/48'/1'/20'/1']tpubDFPemvLnpMqE1BPuturDUh46KxsR8wGSQrA6HofYE7fqxpMAKCcoYWHGA46B6zKY4xcQAc1vLFTcqQ9BvsbHZ4UhzqqF5nUeeNBjNivHxPT/*,[aedb3d12/48'/1'/0'/1']tpubDEbuxto5Kftus28NyPddiEev2yUhzZGpkpQdCK732KBge5FJDhaMdhG1iVw3rMJ2qvABkaLR9HxobkeFkmQZ4RqQgN1KJadDjPn9ANBLo8V/*)))#zlh5y6z5",
        "error": "Range must be specified for ranged descriptor"
      },
      {
        "input": "sh(wsh(sortedmulti(2,[e7dd1c50/48'/1'/40'/1']tpubDFh3VaUEs71ZMcVBmscSSnP4f4r6TvnLssu8yXvpj3uMfAehciMYTrgbfu4KCxXb7oSaz4kriuWRZtQVhZR2oA9toob6aELnsYLN94fXQLF/*,[e7dd1c50/48'/1'/20'/1']tpubDFPemvLnpMqE1BPuturDUh46KxsR8wGSQrA6HofYE7fqxpMAKCcoYWHGA46B6zKY4xcQAc1vLFTcqQ9BvsbHZ4UhzqqF5nUeeNBjNivHxPT/*,[aedb3d12/48'/1'/0'/1']tpubDEbuxto5Kftus28NyPddiEev2yUhzZGpkpQdCK732KBge5FJDhaMdhG1iVw3rMJ2qvABkaLR9HxobkeFkmQZ4RqQgN1KJadDjPn9ANBLo8V/*)))#zlh5y6z5",
        "range": 10,
        "addresses": [
          "2MtWBjxiAi4xYNUdtDe2sHkNw5kdAQqZZNb",
          "2MstQfXgUwTR66bhMrbNU3qDqT6RT4hGHnJ",
          "2N6QXTyf64KHWddFZ5swjaRmEwk4hEawYuo",
          "2NCfXGhiA6EjK6o2JSejtzeP5fYkNxP1TQC",
          "2NCU5HcmKUap923abUPEhGNnTFUf3K2hAYr",
          "2N6K6jKKeuejPTeiPDbnq1qZsqGhigoApzK",
          "2N4jy9MPJee7WvH3tfRVE3LeYQxVNhjt2yH",
          "2NCXTtRLCjwWPeUoRz5qGoKSj84Ci4pbcWy",
          "2NEwEq98wFu1EcSf5jFexCRZEuGjjeTo265",
          "2MzcruaPLyHniY1qjJLXLXEuYRd5PJ1o1EW",
          "2MuY8izcxH5KJfhvc432HQVos483krppmrf"
        ]
      },
      {
        "input": "pkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)#9907vvwz",
        "range": [0, 5],
        "error": "Range should not be specified for un-ranged descriptor"
      },
      {
        "input":"pkh([d34db33f/44h/0h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1h/1h/*h)#u5f4r0y7",
        "range": [1, 5],
        "error": "Private key not available for hardened derivation."
      }
    ];

    for (const test of data) {
      try {
        const result = test.range ? await nclient.execute("deriveaddresses", [test.input, test.range]) : await nclient.execute("deriveaddresses", [test.input]);
        assert.deepStrictEqual(result, test.addresses);
      } catch (e) {
        assert.strictEqual(e.message, test.error);
      }
    }
  });

  it('should rpc createmultisig', async () => {
    const data = [
      {
        'm': 2,
        'keys': [
          '02f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b',
          '03d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad93672',
          '021f360d51b8eb43422fe942c837ad16e36bab87c5f7567609de9a38e205fb51ed',
          '03a778eaee9cc18a4e5e02a78f403082d4e6f3a9c0d9edaea20b9ad86089de7fc9',
          '02a3c95e41e8272c6842df8c9da492ef5e03bbc4ca17c22ce1f88570e716e187db',
          '032e1d465bc5cdea674337934fb861d097dd7ab20289e4d41de14a6cafcd61d30a',
          '0370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea1',
          '03878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf',
          '0248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec894',
          '03f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac4',
          '023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e7372',
          '02e32652928f21764e02822d39ffd1075c428e372a06fe7247023d5b60f1d01596',
          '020e002818c48b1d1766f6196e09db90f51e155bbd49be0ad743d1fa6b7e8efcae',
          '03725d482f0c77f4feb1ecbea28f036b30889f462222002e88aa8f8346dce94474',
          '031fa2798d9f40bc2746f91f300460be9091e10f1b4baa37843cd41c965b0f9b41',
          '0235b7b545398ce9692f319e6eefe114eae50f008f46d33baf19418e0f17e3bc65',
          '02ff72a2b54370c0b1501228b6a210bc36a16535cc358bf7839c85a6ae2c41725c',
          '0282ce44556f5a81c7a698dc8fdba12089740df420af93002e80a752020e5d939e',
          '0279f5b244862e27f69284befb0299909139b899d2702b3e74b4317ed5b2947e03',
          '0293d0b090906afdee07dabedf34798293246ce06ade2e3887302f289008f25f4d'
        ],
        'address_type': 'p2sh-segwit',
        'result': {
          'address': '2NCFqiBT6cswU7rkm1ZTvxBuMDdwaFUWKJj',
          'redeemScript': '522102f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b2103d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad9367221021f360d51b8eb43422fe942c837ad16e36bab87c5f7567609de9a38e205fb51ed2103a778eaee9cc18a4e5e02a78f403082d4e6f3a9c0d9edaea20b9ad86089de7fc92102a3c95e41e8272c6842df8c9da492ef5e03bbc4ca17c22ce1f88570e716e187db21032e1d465bc5cdea674337934fb861d097dd7ab20289e4d41de14a6cafcd61d30a210370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea12103878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf210248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec8942103f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac421023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e73722102e32652928f21764e02822d39ffd1075c428e372a06fe7247023d5b60f1d0159621020e002818c48b1d1766f6196e09db90f51e155bbd49be0ad743d1fa6b7e8efcae2103725d482f0c77f4feb1ecbea28f036b30889f462222002e88aa8f8346dce9447421031fa2798d9f40bc2746f91f300460be9091e10f1b4baa37843cd41c965b0f9b41210235b7b545398ce9692f319e6eefe114eae50f008f46d33baf19418e0f17e3bc652102ff72a2b54370c0b1501228b6a210bc36a16535cc358bf7839c85a6ae2c41725c210282ce44556f5a81c7a698dc8fdba12089740df420af93002e80a752020e5d939e210279f5b244862e27f69284befb0299909139b899d2702b3e74b4317ed5b2947e03210293d0b090906afdee07dabedf34798293246ce06ade2e3887302f289008f25f4d0114ae',
          'descriptor': 'sh(wsh(multi(2,02f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b,03d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad93672,021f360d51b8eb43422fe942c837ad16e36bab87c5f7567609de9a38e205fb51ed,03a778eaee9cc18a4e5e02a78f403082d4e6f3a9c0d9edaea20b9ad86089de7fc9,02a3c95e41e8272c6842df8c9da492ef5e03bbc4ca17c22ce1f88570e716e187db,032e1d465bc5cdea674337934fb861d097dd7ab20289e4d41de14a6cafcd61d30a,0370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea1,03878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf,0248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec894,03f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac4,023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e7372,02e32652928f21764e02822d39ffd1075c428e372a06fe7247023d5b60f1d01596,020e002818c48b1d1766f6196e09db90f51e155bbd49be0ad743d1fa6b7e8efcae,03725d482f0c77f4feb1ecbea28f036b30889f462222002e88aa8f8346dce94474,031fa2798d9f40bc2746f91f300460be9091e10f1b4baa37843cd41c965b0f9b41,0235b7b545398ce9692f319e6eefe114eae50f008f46d33baf19418e0f17e3bc65,02ff72a2b54370c0b1501228b6a210bc36a16535cc358bf7839c85a6ae2c41725c,0282ce44556f5a81c7a698dc8fdba12089740df420af93002e80a752020e5d939e,0279f5b244862e27f69284befb0299909139b899d2702b3e74b4317ed5b2947e03,0293d0b090906afdee07dabedf34798293246ce06ade2e3887302f289008f25f4d)))#28tx9y39'
        }
      },
      {
        'm': 4,
        'keys': [
          '02f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b',
          '03d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad93672',
          '021f360d51b8eb43422fe942c837ad16e36bab87c5f7567609de9a38e205fb51ed',
          '03a778eaee9cc18a4e5e02a78f403082d4e6f3a9c0d9edaea20b9ad86089de7fc9',
          '02a3c95e41e8272c6842df8c9da492ef5e03bbc4ca17c22ce1f88570e716e187db',
          '032e1d465bc5cdea674337934fb861d097dd7ab20289e4d41de14a6cafcd61d30a',
          '0370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea1',
          '03878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf',
          '0248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec894',
          '03f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac4',
          '023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e7372',
          '02e32652928f21764e02822d39ffd1075c428e372a06fe7247023d5b60f1d01596',
          '020e002818c48b1d1766f6196e09db90f51e155bbd49be0ad743d1fa6b7e8efcae',
          '03725d482f0c77f4feb1ecbea28f036b30889f462222002e88aa8f8346dce94474'
        ],
        'address_type': 'p2sh-segwit',
        'result': {
          'address': '2N5YHZJYNqXqCwiX2FTQ9ZgwCoW4qksY2CE',
          'redeemScript': '542102f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b2103d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad9367221021f360d51b8eb43422fe942c837ad16e36bab87c5f7567609de9a38e205fb51ed2103a778eaee9cc18a4e5e02a78f403082d4e6f3a9c0d9edaea20b9ad86089de7fc92102a3c95e41e8272c6842df8c9da492ef5e03bbc4ca17c22ce1f88570e716e187db21032e1d465bc5cdea674337934fb861d097dd7ab20289e4d41de14a6cafcd61d30a210370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea12103878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf210248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec8942103f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac421023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e73722102e32652928f21764e02822d39ffd1075c428e372a06fe7247023d5b60f1d0159621020e002818c48b1d1766f6196e09db90f51e155bbd49be0ad743d1fa6b7e8efcae2103725d482f0c77f4feb1ecbea28f036b30889f462222002e88aa8f8346dce944745eae',
          'descriptor': 'sh(wsh(multi(4,02f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b,03d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad93672,021f360d51b8eb43422fe942c837ad16e36bab87c5f7567609de9a38e205fb51ed,03a778eaee9cc18a4e5e02a78f403082d4e6f3a9c0d9edaea20b9ad86089de7fc9,02a3c95e41e8272c6842df8c9da492ef5e03bbc4ca17c22ce1f88570e716e187db,032e1d465bc5cdea674337934fb861d097dd7ab20289e4d41de14a6cafcd61d30a,0370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea1,03878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf,0248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec894,03f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac4,023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e7372,02e32652928f21764e02822d39ffd1075c428e372a06fe7247023d5b60f1d01596,020e002818c48b1d1766f6196e09db90f51e155bbd49be0ad743d1fa6b7e8efcae,03725d482f0c77f4feb1ecbea28f036b30889f462222002e88aa8f8346dce94474)))#a880m646'
        }
      },
      {
        'm': 4,
        'keys': [
          '02f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b',
          '03d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad93672',
          '021f360d51b8eb43422fe942c837ad16e36bab87c5f7567609de9a38e205fb51ed',
          '03a778eaee9cc18a4e5e02a78f403082d4e6f3a9c0d9edaea20b9ad86089de7fc9',
          '02a3c95e41e8272c6842df8c9da492ef5e03bbc4ca17c22ce1f88570e716e187db',
          '032e1d465bc5cdea674337934fb861d097dd7ab20289e4d41de14a6cafcd61d30a',
          '0370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea1',
          '03878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf',
          '0248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec894',
          '03f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac4',
          '023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e7372',
          '02e32652928f21764e02822d39ffd1075c428e372a06fe7247023d5b60f1d01596',
          '020e002818c48b1d1766f6196e09db90f51e155bbd49be0ad743d1fa6b7e8efcae',
          '03725d482f0c77f4feb1ecbea28f036b30889f462222002e88aa8f8346dce94474'
        ],
        'address_type': 'bech32',
        'result': {
          'address': 'bcrt1qwn0zfduv4tu2jga3dl4a3r87dpk3da6ke5t2uhy306ynlrpg5eas47sw6n',
          'redeemScript': '542102f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b2103d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad9367221021f360d51b8eb43422fe942c837ad16e36bab87c5f7567609de9a38e205fb51ed2103a778eaee9cc18a4e5e02a78f403082d4e6f3a9c0d9edaea20b9ad86089de7fc92102a3c95e41e8272c6842df8c9da492ef5e03bbc4ca17c22ce1f88570e716e187db21032e1d465bc5cdea674337934fb861d097dd7ab20289e4d41de14a6cafcd61d30a210370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea12103878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf210248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec8942103f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac421023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e73722102e32652928f21764e02822d39ffd1075c428e372a06fe7247023d5b60f1d0159621020e002818c48b1d1766f6196e09db90f51e155bbd49be0ad743d1fa6b7e8efcae2103725d482f0c77f4feb1ecbea28f036b30889f462222002e88aa8f8346dce944745eae',
          'descriptor': 'wsh(multi(4,02f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b,03d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad93672,021f360d51b8eb43422fe942c837ad16e36bab87c5f7567609de9a38e205fb51ed,03a778eaee9cc18a4e5e02a78f403082d4e6f3a9c0d9edaea20b9ad86089de7fc9,02a3c95e41e8272c6842df8c9da492ef5e03bbc4ca17c22ce1f88570e716e187db,032e1d465bc5cdea674337934fb861d097dd7ab20289e4d41de14a6cafcd61d30a,0370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea1,03878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf,0248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec894,03f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac4,023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e7372,02e32652928f21764e02822d39ffd1075c428e372a06fe7247023d5b60f1d01596,020e002818c48b1d1766f6196e09db90f51e155bbd49be0ad743d1fa6b7e8efcae,03725d482f0c77f4feb1ecbea28f036b30889f462222002e88aa8f8346dce94474))#t7k5jeyy'
        }
      },
      {
        'm': 4,
        'keys': [
          '02f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b',
          '03d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad93672',
          '021f360d51b8eb43422fe942c837ad16e36bab87c5f7567609de9a38e205fb51ed',
          '03a778eaee9cc18a4e5e02a78f403082d4e6f3a9c0d9edaea20b9ad86089de7fc9',
          '02a3c95e41e8272c6842df8c9da492ef5e03bbc4ca17c22ce1f88570e716e187db',
          '032e1d465bc5cdea674337934fb861d097dd7ab20289e4d41de14a6cafcd61d30a',
          '0370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea1',
          '03878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf',
          '0248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec894',
          '03f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac4',
          '023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e7372',
          '02e32652928f21764e02822d39ffd1075c428e372a06fe7247023d5b60f1d01596',
          '020e002818c48b1d1766f6196e09db90f51e155bbd49be0ad743d1fa6b7e8efcae',
          '03725d482f0c77f4feb1ecbea28f036b30889f462222002e88aa8f8346dce94474'
        ],
        'address_type': 'legacy',
        'result': {
          'address': '2NDLRy5WPdnfPYyKYfBCfJXEce3QQhZD8ps',
          'redeemScript': '542102f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b2103d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad9367221021f360d51b8eb43422fe942c837ad16e36bab87c5f7567609de9a38e205fb51ed2103a778eaee9cc18a4e5e02a78f403082d4e6f3a9c0d9edaea20b9ad86089de7fc92102a3c95e41e8272c6842df8c9da492ef5e03bbc4ca17c22ce1f88570e716e187db21032e1d465bc5cdea674337934fb861d097dd7ab20289e4d41de14a6cafcd61d30a210370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea12103878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf210248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec8942103f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac421023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e73722102e32652928f21764e02822d39ffd1075c428e372a06fe7247023d5b60f1d0159621020e002818c48b1d1766f6196e09db90f51e155bbd49be0ad743d1fa6b7e8efcae2103725d482f0c77f4feb1ecbea28f036b30889f462222002e88aa8f8346dce944745eae',
          'descriptor': 'sh(multi(4,02f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b,03d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad93672,021f360d51b8eb43422fe942c837ad16e36bab87c5f7567609de9a38e205fb51ed,03a778eaee9cc18a4e5e02a78f403082d4e6f3a9c0d9edaea20b9ad86089de7fc9,02a3c95e41e8272c6842df8c9da492ef5e03bbc4ca17c22ce1f88570e716e187db,032e1d465bc5cdea674337934fb861d097dd7ab20289e4d41de14a6cafcd61d30a,0370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea1,03878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf,0248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec894,03f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac4,023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e7372,02e32652928f21764e02822d39ffd1075c428e372a06fe7247023d5b60f1d01596,020e002818c48b1d1766f6196e09db90f51e155bbd49be0ad743d1fa6b7e8efcae,03725d482f0c77f4feb1ecbea28f036b30889f462222002e88aa8f8346dce94474))#kcuhkkas'
        }
      },
      {
        'm': 1,
        'keys': [
          '02f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b',
          '03d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad93672'
        ],
        'address_type': 'BECH32',
        'error': `Unknown address type 'BECH32'.`
      },
      {
        'm': 4,
        'n': 1,
        'error': 'Invalid m and n values.'
      },
      {
        'm': 4,
        'keys': [
          '02f293c4d026a536a082453f8327f305ae0a0c59350b396205e15fbec2af67390b',
          '03d7b6a7e972f6e1a532f9f49a7cc35055a0ffd7cec5f81728f6a3fdf4dad93672',
          '021f360d51b8eb43422fe942c837ad16e36bab87c5f7567609de9a38e205fb51ed',
          '03a778eaee9cc18a4e5e02a78f403082d4e6f3a9c0d9edaea20b9ad86089de7fc9',
          '02a3c95e41e8272c6842df8c9da492ef5e03bbc4ca17c22ce1f88570e716e187db',
          '032e1d465bc5cdea674337934fb861d097dd7ab20289e4d41de14a6cafcd61d30a',
          '0370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea1',
          '03878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf',
          '0248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec894',
          '03f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac4',
          '023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e7372',
          '02e32652928f21764e02822d39ffd1075c428e372a06fe7247023d5b60f1d01596',
          '020e002818c48b1d1766f6196e09db90f51e155bbd49be0ad743d1fa6b7e8efcae',
          '03725d482f0c77f4feb1ecbea28f036b30889f462222002e88aa8f8346dce94474',
          '0370fd35da88778a805ce9acc88c0020e3b14cacaa30f99d829207e1896d782ea1',
          '03878a4b831af4fee069964448ccca999071633fcc751d296e8c5325167274febf',
          '0248f8621596029568070dda40bc1e3ace78df320b5ebf0d6a431536e9af3ec894',
          '03f757260835b7e439b244a9b10f5645966d7dcff9d2648c400a0d6827f4a64ac4',
          '023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e7372',
          '023b3972554e123985b6c3d8575e6fd3384f59a58ef91e0d39ba5905dad49e7372'
        ],
        'address_type': 'legacy',
        'error': 'Script size is too large'
      }
    ];

    for (const test of data) {
        try {
          const result = test.address_type ? await nclient.execute('createmultisig', [test.m, test.keys, test.address_type]) : await nclient.execute('createmultisig', [test.m, test.keys, test.address_type]);
          assert.deepStrictEqual(result, test.result);
        } catch (e) {
          assert.strictEqual(e.message, test.error);
        }
    }
  });

  it('should rpc getblockhash', async () => {
    const info = await nclient.execute('getblockhash', [node.chain.tip.height]);
    assert.strictEqual(util.revHex(node.chain.tip.hash), info);
  });

  it('should rpc getblockfilter', async () => {
    const hash = await nclient.execute('getblockhash', [node.chain.tip.height]);
    const info = await nclient.execute('getblockfilter', [hash, 'BASIC']);
    const indexer = node.filterIndexers.get('BASIC');
    const filter = await indexer.getFilter(node.chain.tip.hash);
    const expected = filter.toJSON();

    assert.strictEqual(expected.filter, info.filter);
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
      const waitForConnection = new Promise((resolve, reject) => {
        node.pool.once('peer open', async (peer) => {
          resolve(peer);
        });
      });

      await node.connect();
      await peer.open();
      await peer.connect();

      await waitForConnection;
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

    it('should rpc getnodeaddresses', async () => {
      const newHosts = [
        {
          'time': 1655305701,
          'services': 1033,
          'host': '102.91.5.101',
          'port': 38333
        },
        {
          'time': 1655958090,
          'services': 1033,
          'host': '197.149.96.171',
          'port': 38333
        },
        {
          'time': 1655834706,
          'services': 1033,
          'host': '190.104.161.74',
          'port': 38331
        },
        {
          'time': 1655621666,
          'services': 1033,
          'host': '151.34.40.226',
          'port': 38333
        },
        {
          'time': 1655965074,
          'services': 67109901,
          'host': '178.128.80.131',
          'port': 3333
        },
        {
          'time': 1656003055,
          'services': 1033,
          'host': '31.14.40.18',
          'port': 38333
        },
        {
          'time': 1654268543,
          'services': 1033,
          'host': '102.89.34.71',
          'port': 38333
        },
        {
          'time': 1655009945,
          'services': 1033,
          'host': '183.90.36.72',
          'port': 38333
        },
        {
          'time': 1655109959,
          'services': 1033,
          'host': '151.46.58.162',
          'port': 38333
        },
        {
          'time': 1653921720,
          'services': 1033,
          'host': '5.24.225.133',
          'port': 38333
        }
      ];

      let addr = NetAddress.fromJSON(newHosts[0]);
      let isHostAdded = node.pool.hosts.add(addr);

      assert(isHostAdded);

      let hosts = await nclient.execute('getnodeaddresses');

      assert.strictEqual(hosts.length, 1);

      assert.strictEqual(addr.host, hosts[0].host);
      assert.strictEqual(addr.port, hosts[0].port);
      assert.strictEqual(addr.services, hosts[0].services);
      assert.strictEqual(addr.time, hosts[0].time);

      // count=7
      const newHostsCount = newHosts.length;

      for (let i = 1; i < newHostsCount; i++) {
        addr = NetAddress.fromJSON(newHosts[i]);
        isHostAdded = node.pool.hosts.add(addr);
        assert(isHostAdded);
      }

      hosts = await nclient.execute('getnodeaddresses', [7]);

      assert.strictEqual(hosts.length, 7);
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

    it('should rpc getblockbyheight', async () => {
      // Getting block height of chain tip
      const blockheight = node.chain.tip.height;
      const blockHash = node.chain.tip.hash;

      // verbose=0 details=0
      let blockInfo;
      blockInfo = await nclient.execute('getblockbyheight', [blockheight, 0, 0]);
      const block = Block.fromRaw(Buffer.from(blockInfo, 'hex'));
      assert.bufferEqual(blockHash, block.hash());

      // verbose=1 details=0
      blockInfo = await nclient.execute('getblockbyheight', [blockheight, 1, 0]);
      const properties = [
        'hash', 'confirmations', 'strippedsize',
        'size', 'weight', 'height', 'version',
        'versionHex', 'merkleroot', 'coinbase',
        'tx', 'time', 'mediantime', 'nonce',
        'bits', 'difficulty', 'chainwork',
        'nTx', 'previousblockhash', 'nextblockhash'
      ];
      for (const property of properties)
        assert(property in blockInfo);

      assert.strictEqual(typeof blockInfo.tx[0], 'string');
      assert.strictEqual(util.revHex(blockHash), blockInfo.hash);

      // verbose=1 details=1
      blockInfo = await nclient.execute('getblockbyheight', [blockheight, 1, 1]);
      for (const property of properties)
        assert(property in blockInfo);

      assert.strictEqual(typeof blockInfo.tx[0], 'object');
      assert.strictEqual(util.revHex(blockHash), blockInfo.hash);
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

  describe('utilities', function() {
    it('should decoderawtransaction', async () => {
      // 0-in, 2-out
      const rawTX1 =
        '0100000000024e61bc00000000001976a914fbdd46898a6d70a682cbd34420cc' +
        'f0b6bb64493788acf67e4929010000001976a9141b002b6fc0f457bf8d092722' +
        '510fce9f37f0423b88ac00000000';
      const result = await nclient.execute('decoderawtransaction', [rawTX1]);
      assert.strictEqual(result.vin.length, 0);
      assert.strictEqual(result.vout.length, 2);
    });

    it('should estimate fee rate', async () => {
      const result = await nclient.execute('estimatesmartfee', [6]);
      assert.deepStrictEqual(result, {
        blocks: 6,
        feerate: -1
      });
    });
  });
});
