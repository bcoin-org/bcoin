/* eslint-disable quotes */
/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const KeyProvider = require('../lib/descriptor/keyprovider');
const assert = require('bsert');

const keys = [
  {
    "input": "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1",
    "pubkey": "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd",
    "privkey": "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1",
    "hasprivatekey": true,
    "pubkeysize": 33
  },
  {
    "input": "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
    "pubkey": "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
    "privkey": null,
    "hasprivatekey": false,
    "pubkeysize": 33
  },
  {
    "input": "[d34db33f/44'/0'/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1'/1'/*'",
    "pubkey": "[d34db33f/44'/0'/0']tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1'/1'/*'",
    "privkey": null,
    "hasprivatekey": false,
    "pubkeysize": 33,
    "network": "testnet"
  },
  {
    "input": "[01234567/10/20]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0",
    "pubkey": "[01234567/10/20]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0",
    "privkey": "[01234567/10/20]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0",
    "hasprivatekey": true,
    "pubkeysize": 33
  },
  {
    "input": "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss",
    "pubkey": "04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235",
    "privkey": "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss",
    "hasprivatekey": true,
    "pubkeysize": 65
  }
];

describe('KeyProvider', () => {
  for (const data of keys) {
    it(`should create a KeyProvider object for ${data.input}`, () => {
      const provider = KeyProvider.fromString(data.input, data.network);
      assert.strictEqual(provider.toString(), data.pubkey);
      assert.strictEqual(provider.toPrivateString(), data.privkey);
      assert.strictEqual(provider.hasPrivateKey(), data.hasprivatekey);
      assert.strictEqual(provider.getSize(), data.pubkeysize);
    });
  }
});
