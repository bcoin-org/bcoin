'use strict';

var assert = require('assert');
var encoding = require('../lib/utils/encoding');
var crypto = require('../lib/crypto/crypto');
var co = require('../lib/utils/co');
var MempoolEntry = require('../lib/mempool/mempoolentry');
var Mempool = require('../lib/mempool/mempool');
var Chain = require('../lib/blockchain/chain');
var WalletDB = require('../lib/wallet/walletdb');
var MTX = require('../lib/primitives/mtx');
var Coin = require('../lib/primitives/coin');
var KeyRing = require('../lib/primitives/keyring');
var Address = require('../lib/primitives/address');
var Outpoint = require('../lib/primitives/outpoint');
var Script = require('../lib/script/script');
var Witness = require('../lib/script/witness');
var Block = require('../lib/primitives/block');
var opcodes = Script.opcodes;
var cob = co.cob;

describe('Mempool', function() {
  var chain, mempool, walletdb, wallet, cached;

  this.timeout(5000);

  chain = new Chain({
    name: 'mp-chain',
    db: 'memory'
  });

  mempool = new Mempool({
    chain: chain,
    name: 'mempool-test',
    db: 'memory'
  });

  walletdb = new WalletDB({
    name: 'mempool-wallet-test',
    db: 'memory',
    verify: true
  });

  function dummy(prev, prevHash) {
    var fund, coin, entry;

    if (!prevHash)
      prevHash = encoding.ONE_HASH.toString('hex');

    coin = new Coin();
    coin.height = 0;
    coin.value = 0;
    coin.script = prev;
    coin.hash = prevHash;
    coin.index = 0;

    fund = new MTX();
    fund.addCoin(coin);
    fund.addOutput(prev, 70000);

    entry = MempoolEntry.fromTX(fund.toTX(), fund.view, 0);

    mempool.trackEntry(entry, fund.view);

    return Coin.fromTX(fund, 0, -1);
  }

  it('should open mempool', cob(function* () {
    yield mempool.open();
    chain.state.flags |= Script.flags.VERIFY_WITNESS;
  }));

  it('should open walletdb', cob(function* () {
    yield walletdb.open();
  }));

  it('should open wallet', cob(function* () {
    wallet = yield walletdb.create();
  }));

  it('should handle incoming orphans and TXs', cob(function* () {
    var kp = KeyRing.generate();
    var w = wallet;
    var t1, t2, t3, t4, f1, fake, prev, sig, balance, txs;

    t1 = new MTX();
    t1.addOutput(w.getAddress(), 50000);
    t1.addOutput(w.getAddress(), 10000);

    prev = Script.fromPubkey(kp.publicKey);
    t1.addCoin(dummy(prev));
    sig = t1.signature(0, prev, 70000, kp.privateKey, Script.hashType.ALL, 0);
    t1.inputs[0].script = new Script([sig]);

    // balance: 51000
    yield w.sign(t1);
    t1 = t1.toTX();

    t2 = new MTX();
    t2.addTX(t1, 0); // 50000
    t2.addOutput(w.getAddress(), 20000);
    t2.addOutput(w.getAddress(), 20000);

    // balance: 49000
    yield w.sign(t2);
    t2 = t2.toTX();

    t3 = new MTX();
    t3.addTX(t1, 1); // 10000
    t3.addTX(t2, 0); // 20000
    t3.addOutput(w.getAddress(), 23000);

    // balance: 47000
    yield w.sign(t3);
    t3 = t3.toTX();

    t4 = new MTX();
    t4.addTX(t2, 1); // 24000
    t4.addTX(t3, 0); // 23000
    t4.addOutput(w.getAddress(), 11000);
    t4.addOutput(w.getAddress(), 11000);

    // balance: 22000
    yield w.sign(t4);
    t4 = t4.toTX();

    f1 = new MTX();
    f1.addTX(t4, 1); // 11000
    f1.addOutput(new Address(), 9000);

    // balance: 11000
    yield w.sign(f1);
    f1 = f1.toTX();

    fake = new MTX();
    fake.addTX(t1, 1); // 1000 (already redeemed)
    fake.addOutput(w.getAddress(), 6000); // 6000 instead of 500

    // Script inputs but do not sign
    yield w.template(fake);

    // Fake signature
    fake.inputs[0].script.set(0, encoding.ZERO_SIG);
    fake.inputs[0].script.compile();
    fake = fake.toTX();
    // balance: 11000

    yield mempool.addTX(fake);
    yield mempool.addTX(t4);

    balance = mempool.getBalance();
    assert.equal(balance, 70000); // note: funding balance

    yield mempool.addTX(t1);

    balance = mempool.getBalance();
    assert.equal(balance, 60000);

    yield mempool.addTX(t2);

    balance = mempool.getBalance();
    assert.equal(balance, 50000);

    yield mempool.addTX(t3);

    balance = mempool.getBalance();
    assert.equal(balance, 22000);

    yield mempool.addTX(f1);

    balance = mempool.getBalance();
    assert.equal(balance, 20000);

    txs = mempool.getHistory();
    assert(txs.some(function(tx) {
      return tx.hash('hex') === f1.hash('hex');
    }));
  }));

  it('should handle locktime', cob(function* () {
    var w = wallet;
    var kp = KeyRing.generate();
    var tx, prev, prevHash, sig;

    tx = new MTX();
    tx.addOutput(w.getAddress(), 50000);
    tx.addOutput(w.getAddress(), 10000);

    prev = Script.fromPubkey(kp.publicKey);
    prevHash = crypto.randomBytes(32).toString('hex');

    tx.addCoin(dummy(prev, prevHash));
    tx.setLocktime(200);

    chain.tip.height = 200;

    sig = tx.signature(0, prev, 70000, kp.privateKey, Script.hashType.ALL, 0);
    tx.inputs[0].script = new Script([sig]);

    tx = tx.toTX();

    yield mempool.addTX(tx);
    chain.tip.height = 0;
  }));

  it('should handle invalid locktime', cob(function* () {
    var w = wallet;
    var kp = KeyRing.generate();
    var tx, prev, prevHash, sig, err;

    tx = new MTX();
    tx.addOutput(w.getAddress(), 50000);
    tx.addOutput(w.getAddress(), 10000);

    prev = Script.fromPubkey(kp.publicKey);
    prevHash = crypto.randomBytes(32).toString('hex');

    tx.addCoin(dummy(prev, prevHash));
    tx.setLocktime(200);
    chain.tip.height = 200 - 1;

    sig = tx.signature(0, prev, 70000, kp.privateKey, Script.hashType.ALL, 0);
    tx.inputs[0].script = new Script([sig]);
    tx = tx.toTX();

    try {
      yield mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);

    chain.tip.height = 0;
  }));

  it('should not cache a malleated wtx with mutated sig', cob(function* () {
    var w = wallet;
    var kp = KeyRing.generate();
    var tx, prev, prevHash, prevs, sig, err;

    kp.witness = true;

    tx = new MTX();
    tx.addOutput(w.getAddress(), 50000);
    tx.addOutput(w.getAddress(), 10000);

    prev = Script.fromProgram(0, kp.getKeyHash());
    prevHash = crypto.randomBytes(32).toString('hex');

    tx.addCoin(dummy(prev, prevHash));

    prevs = Script.fromPubkeyhash(kp.getKeyHash());

    sig = tx.signature(0, prevs, 70000, kp.privateKey, Script.hashType.ALL, 1);
    sig[sig.length - 1] = 0;

    tx.inputs[0].witness = new Witness([sig, kp.publicKey]);
    tx = tx.toTX();

    try {
      yield mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!mempool.hasReject(tx.hash()));
  }));

  it('should not cache a malleated tx with unnecessary witness', cob(function* () {
    var w = wallet;
    var kp = KeyRing.generate();
    var tx, prev, prevHash, sig, err;

    tx = new MTX();
    tx.addOutput(w.getAddress(), 50000);
    tx.addOutput(w.getAddress(), 10000);

    prev = Script.fromPubkey(kp.publicKey);
    prevHash = crypto.randomBytes(32).toString('hex');

    tx.addCoin(dummy(prev, prevHash));

    sig = tx.signature(0, prev, 70000, kp.privateKey, Script.hashType.ALL, 0);
    tx.inputs[0].script = new Script([sig]);
    tx.inputs[0].witness.push(new Buffer(0));
    tx = tx.toTX();

    try {
      yield mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!mempool.hasReject(tx.hash()));
  }));

  it('should not cache a malleated wtx with wit removed', cob(function* () {
    var w = wallet;
    var kp = KeyRing.generate();
    var tx, prev, prevHash, err;

    kp.witness = true;

    tx = new MTX();
    tx.addOutput(w.getAddress(), 50000);
    tx.addOutput(w.getAddress(), 10000);

    prev = Script.fromProgram(0, kp.getKeyHash());
    prevHash = crypto.randomBytes(32).toString('hex');

    tx.addCoin(dummy(prev, prevHash));

    tx = tx.toTX();

    try {
      yield mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(err.malleated);
    assert(!mempool.hasReject(tx.hash()));
  }));

  it('should cache non-malleated tx without sig', cob(function* () {
    var w = wallet;
    var kp = KeyRing.generate();
    var tx, prev, prevHash, err;

    tx = new MTX();
    tx.addOutput(w.getAddress(), 50000);
    tx.addOutput(w.getAddress(), 10000);

    prev = Script.fromPubkey(kp.publicKey);
    prevHash = crypto.randomBytes(32).toString('hex');

    tx.addCoin(dummy(prev, prevHash));

    tx = tx.toTX();

    try {
      yield mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!err.malleated);
    assert(mempool.hasReject(tx.hash()));
    cached = tx;
  }));

  it('should clear reject cache', cob(function* () {
    var w = wallet;
    var tx, input;

    tx = new MTX();
    tx.addOutpoint(new Outpoint());
    tx.addOutput(w.getAddress(), 50000);
    tx = tx.toTX();

    assert(mempool.hasReject(cached.hash()));
    yield mempool.addBlock({ height: 1 }, [tx]);
    assert(!mempool.hasReject(cached.hash()));
  }));

  it('should destroy mempool', cob(function* () {
    yield mempool.close();
  }));
});
