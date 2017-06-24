'use strict';

var bench = require('./bench');
var co = require('../lib/utils/co');
var crypto = require('../lib/crypto/crypto');
var WalletDB = require('../lib/wallet/walletdb');
var MTX = require('../lib/primitives/mtx');
var Outpoint = require('../lib/primitives/outpoint');
var walletdb;

function dummy() {
  var hash = crypto.randomBytes(32).toString('hex');
  return new Outpoint(hash, 0);
}

walletdb = new WalletDB({
  name: 'wallet-test',
  db: 'memory',
  resolution: false,
  verify: false
});

async function runBench() {
  var i, j, wallet, addrs, jobs, end;
  var result, tx, mtx, options;

  // Open and Create
  yield walletdb.open();
  wallet = yield walletdb.create();
  addrs = [];

  // Accounts
  jobs = [];
  for (i = 0; i < 1000; i++)
    jobs.push(wallet.createAccount({}));

  end = bench('accounts');
  result = yield Promise.all(jobs);
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
  result = yield Promise.all(jobs);
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
  result = yield Promise.all(jobs);
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
  result = yield Promise.all(jobs);
  end(10000);

  // Balance
  end = bench('balance');
  result = yield wallet.getBalance();
  end(1);

  // Coins
  end = bench('coins');
  result = yield wallet.getCoins();
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
  yield wallet.createTX(options);
  end(1);
}

runBench().then(process.exit);
