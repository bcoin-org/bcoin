'use strict';

const random = require('bcrypto/lib/random');
const bench = require('./bench');
const WalletDB = require('../lib/wallet/walletdb');
const MTX = require('../lib/primitives/mtx');
const Input = require('../lib/primitives/input');
const Output = require('../lib/primitives/output');
const Script = require('../lib/script/script');
const {rimraf, testdir} = require('../test/util/common');

const ITERATIONS = 1000;

(async () => {
  for (const memory of [true, false]) {
    console.log(`Memory: ${memory}`);

    const location = testdir('txdb');

    // Create walletDB and wallet
    const wdb = new WalletDB({
      memory,
      location
    });
    await wdb.open();
    const wallet = await wdb.create();
    const addr = await wallet.receiveAddress();
    const script = Script.fromAddress(addr);

    {
      // Fill txdb with unspent coins
      const fund = new MTX();
      const input = new Input();
      // Make this a non-coinbase TX so we can spend right away
      input.prevout.hash = random.randomBytes(32);
      fund.inputs.push(input);
      const output = new Output();
      output.value = 15000;
      output.script = script;
      for (let i = 1; i <= ITERATIONS; i++) {
        fund.outputs.push(output);
      }

      // Confirm
      const dummyBlock = {
        height: 0,
        hash: Buffer.alloc(32),
        time: Date.now()
      };
      await wdb.addTX(fund.toTX(), dummyBlock);
    }

    // Self-send small TXs so txdb is filled
    // with spent coins
    console.log(' Filling txdb...');
    for (let i = 1; i <= ITERATIONS; i++) {
      await wallet.send({
        outputs: [{
          address: addr,
          value: 10000
        }]
      });
    }

    {
      const end = bench('getCredits       ');

      await wallet.getCredits(0);

      end(ITERATIONS);
    }

    {
      const end = bench('getCoins         ');

      await wallet.getCoins(0);

      end(ITERATIONS);
    }

    {
      const end = bench('getSmartCoins    ');

      await wallet.getSmartCoins(0);

      end(ITERATIONS);
    }

    {
      const end = bench('getUnspentCredits');

      await wallet.getUnspentCredits(0);

      end(ITERATIONS);
    }

    {
      const end = bench('getUnspentCoins  ');

      await wallet.getUnspentCoins(0);

      end(ITERATIONS);
    }

    await rimraf(location);
  }
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
