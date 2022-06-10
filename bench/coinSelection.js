'use strict';

const assert = require('bsert');
const random = require('bcrypto/lib/random');
const bench = require('./bench');
const WalletDB = require('../lib/wallet/walletdb');
const MTX = require('../lib/primitives/mtx');
const Input = require('../lib/primitives/input');
const Output = require('../lib/primitives/output');
const Script = require('../lib/script/script');
const {rimraf, testdir} = require('../test/util/common');

const ITERATIONS = 1;

(async () => {
  for (const memory of [true, false]) {
    console.log(`Memory: ${memory}`);

    const location = testdir('coinselection');

    // Create walletDB and wallet
    const wdb = new WalletDB({
      memory,
      location
    });
    await wdb.open();
    const wallet = await wdb.create();
    const addr = await wallet.receiveAddress();
    const script = Script.fromAddress(addr);

    console.log('Funding wallet...');
    {
      // Fund wallet
      const fund = new MTX();
      const input = new Input();
      // Make this a non-coinbase TX so we can spend right away
      input.prevout.hash = random.randomBytes(32);
      fund.inputs.push(input);
      for (let i = 0; i < 10000; i++) {
        const output = new Output();
        output.value = Math.floor(1000 * Math.random() + 1000);
        output.script = script;
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
    console.log('Done funding!!');

    // Now send entire balance, forcing the wallet
    // to spend all its coins. In this test we can ignore
    // size limits, so enormous amount of inputs is OK.
    const {unconfirmed} = await wallet.getBalance();

    console.log('Fetching coins from DB');
    const coins = await wallet.getSmartCoins(0);
    console.log('Done fetching coins from DB!!');

    const values = [];
    for (let i = 1; i <= 50; i++) {
      values.push(Math.floor(i * unconfirmed / 100));
    }

    {
      const end = bench('New Selection    ');

      for (let i = 0; i < 50; i++) {
        const testMTX = new MTX();
        testMTX.addOutput(addr, values[i]);
        await testMTX.fund(coins, {
          changeAddress: addr,
          useSelectByValue: true
        });
        const [tx] = testMTX.commit();

        assert(tx.getOutputValue() >= values[i]);
      }

      end(ITERATIONS);
    }

    {
      const end = bench('Old Selection    ');

      for (let i = 0; i < 50; i++) {
        const testMTX = new MTX();
        testMTX.addOutput(addr, values[i]);
        await testMTX.fund(coins, {
          changeAddress: addr
        });
        const [tx] = testMTX.commit();

        assert(tx.getOutputValue() >= values[i]);
      }

      end(ITERATIONS);
    }

    await rimraf(location);
  }
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
