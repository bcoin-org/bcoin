'use strict';

var BN = require('bn.js');
var bcoin = require('../').set('main');
var constants = bcoin.constants;
var util = bcoin.util;
var assert = require('assert');
var scriptTypes = constants.scriptTypes;
var bench = require('./bench');
var co = require('../lib/utils/co');
var crypto = require('../lib/crypto/crypto');

bcoin.cache();

function dummy() {
  var hash = crypto.randomBytes(32).toString('hex');
  return {
    prevout: {
      hash: hash,
      index: 0
    },
    coin: {
      version: 1,
      height: 0,
      value: 50460 * 4,
      script: new bcoin.script(),
      coinbase: false,
      hash: hash,
      index: 0
    },
    script: new bcoin.script(),
    witness: new bcoin.witness(),
    sequence: 0xffffffff
  };
}

var walletdb = new bcoin.walletdb({
  name: 'wallet-test',
  // location: __dirname + '/../walletdb-bench',
  // db: 'leveldb'
  db: 'memory',
  resolution: false,
  verify: false
});

var runBench = co(function* runBench() {
  var i, j, wallet, addrs, jobs, end;
  var result, tx, options;

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

  // Addresses
  jobs = [];
  for (i = 0; i < 1000; i++) {
    for (j = 0; j < 10; j++)
      jobs.push(wallet.createReceive(i));
  }

  end = bench('addrs');
  result = yield Promise.all(jobs);
  end(1000 * 10);

  for (i = 0; i < result.length; i++)
    addrs.push(result[i].getAddress());

  // TX deposit
  jobs = [];
  for (i = 0; i < 10000; i++) {
    tx = bcoin.mtx()
      .addInput(dummy())
      .addOutput(addrs[(i + 0) % addrs.length], 50460)
      .addOutput(addrs[(i + 1) % addrs.length], 50460)
      .addOutput(addrs[(i + 2) % addrs.length], 50460)
      .addOutput(addrs[(i + 3) % addrs.length], 50460)
      .toTX();

    jobs.push(walletdb.addTX(tx));
  }

  end = bench('deposit');
  result = yield Promise.all(jobs);
  end(10000);

  // TX redemption
  jobs = [];
  for (i = 0; i < 10000; i++) {
    tx = bcoin.mtx()
      .addInput(tx, 0)
      .addInput(tx, 1)
      .addInput(tx, 2)
      .addInput(tx, 3)
      .addOutput(addrs[(i + 0) % addrs.length], 50460)
      .addOutput(addrs[(i + 1) % addrs.length], 50460)
      .addOutput(addrs[(i + 2) % addrs.length], 50460)
      .addOutput(addrs[(i + 3) % addrs.length], 50460)
      .toTX();

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
});

runBench().then(process.exit);
