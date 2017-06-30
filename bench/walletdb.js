'use strict';

const bench = require('./bench');
const random = require('../lib/crypto/random');
const WalletDB = require('../lib/wallet/walletdb');
const MTX = require('../lib/primitives/mtx');
const Outpoint = require('../lib/primitives/outpoint');
let walletdb;

function dummy() {
  let hash = random.randomBytes(32).toString('hex');
  return new Outpoint(hash, 0);
}

walletdb = new WalletDB({
  name: 'wallet-test',
  db: 'memory',
  resolution: false,
  verify: false
});

async function runBench() {
  let i, j, wallet, addrs, jobs, end;
  let result, tx, mtx, options;

  // Open and Create
  await walletdb.open();
  wallet = await walletdb.create();
  addrs = [];

  // Accounts
  jobs = [];
  for (i = 0; i < 1000; i++)
    jobs.push(wallet.createAccount({}));

  end = bench('accounts');
  result = await Promise.all(jobs);
  end(1000);

  for (i = 0; i < result.length; i++)
    addrs.push(result[i].receive.getAddress());

  // Keys
  jobs = [];
  for (i = 0; i < 1000; i++) {
    for (j = 0; j < 10; j++)
      jobs.push(wallet.createReceive(i));
  }

  end = bench('keys');
  result = await Promise.all(jobs);
  end(1000 * 10);

  for (i = 0; i < result.length; i++)
    addrs.push(result[i].getAddress());

  // TX deposit
  jobs = [];
  for (i = 0; i < 10000; i++) {
    mtx = new MTX();
    mtx.addOutpoint(dummy());
    mtx.addOutput(addrs[(i + 0) % addrs.length], 50460);
    mtx.addOutput(addrs[(i + 1) % addrs.length], 50460);
    mtx.addOutput(addrs[(i + 2) % addrs.length], 50460);
    mtx.addOutput(addrs[(i + 3) % addrs.length], 50460);
    tx = mtx.toTX();

    jobs.push(walletdb.addTX(tx));
  }

  end = bench('deposit');
  result = await Promise.all(jobs);
  end(10000);

  // TX redemption
  jobs = [];
  for (i = 0; i < 10000; i++) {
    mtx = new MTX();
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

  end = bench('redemption');
  result = await Promise.all(jobs);
  end(10000);

  // Balance
  end = bench('balance');
  result = await wallet.getBalance();
  end(1);

  // Coins
  end = bench('coins');
  result = await wallet.getCoins();
  end(1);

  // Create
  end = bench('create');
  options = {
    rate: 10000,
    outputs: [{
      value: 50460,
      address: addrs[0]
    }]
  };
  await wallet.createTX(options);
  end(1);
}

runBench().then(process.exit);
