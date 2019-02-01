'use strict';

const bench = require('./bench');
const random = require('bcrypto/lib/random');
const WalletDB = require('../lib/wallet/walletdb');
const MTX = require('../lib/primitives/mtx');
const Outpoint = require('../lib/primitives/outpoint');

function dummy() {
  const hash = random.randomBytes(32);
  return new Outpoint(hash, 0);
}

const walletdb = new WalletDB({
  name: 'wallet-test',
  db: 'memory',
  resolution: false,
  verify: false
});

(async () => {
  // Open and Create
  await walletdb.open();

  const wallet = await walletdb.create();
  const addrs = [];
  let tx;

  // Accounts
  {
    const jobs = [];
    for (let i = 0; i < 1000; i++)
      jobs.push(wallet.createAccount({}));

    const end = bench('accounts');
    const result = await Promise.all(jobs);
    end(1000);

    for (const addr of result)
      addrs.push(addr.receiveAddress());
  }

  // Keys
  {
    const jobs = [];
    for (let i = 0; i < 1000; i++) {
      for (let j = 0; j < 10; j++)
        jobs.push(wallet.createReceive(i));
    }

    const end = bench('keys');
    const result = await Promise.all(jobs);
    end(1000 * 10);

    for (const addr of result)
      addrs.push(addr.getAddress());
  }

  // TX deposit
  {
    const jobs = [];
    for (let i = 0; i < 10000; i++) {
      const mtx = new MTX();
      mtx.addOutpoint(dummy());
      mtx.addOutput(addrs[(i + 0) % addrs.length], 50460);
      mtx.addOutput(addrs[(i + 1) % addrs.length], 50460);
      mtx.addOutput(addrs[(i + 2) % addrs.length], 50460);
      mtx.addOutput(addrs[(i + 3) % addrs.length], 50460);
      tx = mtx.toTX();

      jobs.push(walletdb.addTX(tx));
    }

    const end = bench('deposit');
    await Promise.all(jobs);
    end(10000);
  }

  // TX redemption
  {
    const jobs = [];
    for (let i = 0; i < 10000; i++) {
      const mtx = new MTX();
      mtx.addTX(tx, 0);
      mtx.addTX(tx, 1);
      mtx.addTX(tx, 2);
      mtx.addTX(tx, 3);
      mtx.addOutput(addrs[(i + 0) % addrs.length], 50460);
      mtx.addOutput(addrs[(i + 1) % addrs.length], 50460);
      mtx.addOutput(addrs[(i + 2) % addrs.length], 50460);
      mtx.addOutput(addrs[(i + 3) % addrs.length], 50460);
      tx = mtx.toTX();

      jobs.push(walletdb.addTX(tx));
    }

    const end = bench('redemption');
    await Promise.all(jobs);
    end(10000);
  }

  // Balance
  {
    const end = bench('balance');
    await wallet.getBalance();
    end(1);
  }

  // Coins
  {
    const end = bench('coins');
    await wallet.getCoins();
    end(1);
  }

  // Create
  {
    const end = bench('create');
    const options = {
      rate: 10000,
      outputs: [{
        value: 50460,
        address: addrs[0]
      }]
    };
    await wallet.createTX(options);
    end(1);
  }
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
