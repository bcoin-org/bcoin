/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('assert');
const encoding = require('../lib/utils/encoding');
const random = require('../lib/crypto/random');
const MempoolEntry = require('../lib/mempool/mempoolentry');
const Mempool = require('../lib/mempool/mempool');
const Chain = require('../lib/blockchain/chain');
const MTX = require('../lib/primitives/mtx');
const Coin = require('../lib/primitives/coin');
const KeyRing = require('../lib/primitives/keyring');
const Address = require('../lib/primitives/address');
const Outpoint = require('../lib/primitives/outpoint');
const Script = require('../lib/script/script');
const Witness = require('../lib/script/witness');
const MemWallet = require('./util/memwallet');

describe('Mempool', function() {
  const chain = new Chain({ db: 'memory' });
  const mempool = new Mempool({ chain: chain, db: 'memory' });
  const wallet = new MemWallet();
  let cached;

  this.timeout(5000);

  function dummy(prev, prevHash) {
    if (!prevHash)
      prevHash = encoding.ONE_HASH.toString('hex');

    const coin = new Coin();
    coin.height = 0;
    coin.value = 0;
    coin.script = prev;
    coin.hash = prevHash;
    coin.index = 0;

    const fund = new MTX();
    fund.addCoin(coin);
    fund.addOutput(prev, 70000);

    const entry = MempoolEntry.fromTX(fund.toTX(), fund.view, 0);

    mempool.trackEntry(entry, fund.view);

    return Coin.fromTX(fund, 0, -1);
  }

  it('should open mempool', async () => {
    await mempool.open();
    chain.state.flags |= Script.flags.VERIFY_WITNESS;
  });

  it('should handle incoming orphans and TXs', async () => {
    const kp = KeyRing.generate();
    const w = wallet;

    let t1 = new MTX();
    t1.addOutput(w.getAddress(), 50000);
    t1.addOutput(w.getAddress(), 10000);

    const prev = Script.fromPubkey(kp.publicKey);
    t1.addCoin(dummy(prev));
    const sig = t1.signature(
      0, prev, 70000, kp.privateKey, Script.hashType.ALL, 0);
    t1.inputs[0].script = new Script([sig]);

    // balance: 51000
    w.sign(t1);
    t1 = t1.toTX();

    let t2 = new MTX();
    t2.addTX(t1, 0); // 50000
    t2.addOutput(w.getAddress(), 20000);
    t2.addOutput(w.getAddress(), 20000);

    // balance: 49000
    w.sign(t2);
    t2 = t2.toTX();

    let t3 = new MTX();
    t3.addTX(t1, 1); // 10000
    t3.addTX(t2, 0); // 20000
    t3.addOutput(w.getAddress(), 23000);

    // balance: 47000
    w.sign(t3);
    t3 = t3.toTX();

    let t4 = new MTX();
    t4.addTX(t2, 1); // 24000
    t4.addTX(t3, 0); // 23000
    t4.addOutput(w.getAddress(), 11000);
    t4.addOutput(w.getAddress(), 11000);

    // balance: 22000
    w.sign(t4);
    t4 = t4.toTX();

    let f1 = new MTX();
    f1.addTX(t4, 1); // 11000
    f1.addOutput(new Address(), 9000);

    // balance: 11000
    w.sign(f1);
    f1 = f1.toTX();

    let fake = new MTX();
    fake.addTX(t1, 1); // 1000 (already redeemed)
    fake.addOutput(w.getAddress(), 6000); // 6000 instead of 500

    // Script inputs but do not sign
    w.template(fake);

    // Fake signature
    fake.inputs[0].script.set(0, encoding.ZERO_SIG);
    fake.inputs[0].script.compile();
    fake = fake.toTX();
    // balance: 11000

    await mempool.addTX(fake);
    await mempool.addTX(t4);

    let balance = mempool.getBalance();
    assert.equal(balance, 70000); // note: funding balance

    await mempool.addTX(t1);

    balance = mempool.getBalance();
    assert.equal(balance, 60000);

    await mempool.addTX(t2);

    balance = mempool.getBalance();
    assert.equal(balance, 50000);

    await mempool.addTX(t3);

    balance = mempool.getBalance();
    assert.equal(balance, 22000);

    await mempool.addTX(f1);

    balance = mempool.getBalance();
    assert.equal(balance, 20000);

    const txs = mempool.getHistory();
    assert(txs.some((tx) => {
      return tx.hash('hex') === f1.hash('hex');
    }));
  });

  it('should handle locktime', async () => {
    const w = wallet;
    const kp = KeyRing.generate();

    let tx = new MTX();
    tx.addOutput(w.getAddress(), 50000);
    tx.addOutput(w.getAddress(), 10000);

    const prev = Script.fromPubkey(kp.publicKey);
    const prevHash = random.randomBytes(32).toString('hex');

    tx.addCoin(dummy(prev, prevHash));
    tx.setLocktime(200);

    chain.tip.height = 200;

    const sig = tx.signature(
      0, prev, 70000, kp.privateKey, Script.hashType.ALL, 0);
    tx.inputs[0].script = new Script([sig]);

    tx = tx.toTX();

    await mempool.addTX(tx);
    chain.tip.height = 0;
  });

  it('should handle invalid locktime', async () => {
    const w = wallet;
    const kp = KeyRing.generate();

    let tx = new MTX();
    tx.addOutput(w.getAddress(), 50000);
    tx.addOutput(w.getAddress(), 10000);

    const prev = Script.fromPubkey(kp.publicKey);
    const prevHash = random.randomBytes(32).toString('hex');

    tx.addCoin(dummy(prev, prevHash));
    tx.setLocktime(200);
    chain.tip.height = 200 - 1;

    const sig = tx.signature(
      0, prev, 70000, kp.privateKey, Script.hashType.ALL, 0);
    tx.inputs[0].script = new Script([sig]);
    tx = tx.toTX();

    let err;
    try {
      await mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);

    chain.tip.height = 0;
  });

  it('should not cache a malleated wtx with mutated sig', async () => {
    const w = wallet;
    const kp = KeyRing.generate();

    kp.witness = true;

    let tx = new MTX();
    tx.addOutput(w.getAddress(), 50000);
    tx.addOutput(w.getAddress(), 10000);

    const prev = Script.fromProgram(0, kp.getKeyHash());
    const prevHash = random.randomBytes(32).toString('hex');

    tx.addCoin(dummy(prev, prevHash));

    const prevs = Script.fromPubkeyhash(kp.getKeyHash());

    const sig = tx.signature(
      0, prevs, 70000, kp.privateKey, Script.hashType.ALL, 1);
    sig[sig.length - 1] = 0;

    tx.inputs[0].witness = new Witness([sig, kp.publicKey]);
    tx = tx.toTX();

    let err;
    try {
      await mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!mempool.hasReject(tx.hash()));
  });

  it('should not cache a malleated tx with unnecessary witness', async () => {
    const w = wallet;
    const kp = KeyRing.generate();

    let tx = new MTX();
    tx.addOutput(w.getAddress(), 50000);
    tx.addOutput(w.getAddress(), 10000);

    const prev = Script.fromPubkey(kp.publicKey);
    const prevHash = random.randomBytes(32).toString('hex');

    tx.addCoin(dummy(prev, prevHash));

    const sig = tx.signature(
      0, prev, 70000, kp.privateKey, Script.hashType.ALL, 0);
    tx.inputs[0].script = new Script([sig]);
    tx.inputs[0].witness.push(Buffer.alloc(0));
    tx = tx.toTX();

    let err;
    try {
      await mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!mempool.hasReject(tx.hash()));
  });

  it('should not cache a malleated wtx with wit removed', async () => {
    const w = wallet;
    const kp = KeyRing.generate();

    kp.witness = true;

    let tx = new MTX();
    tx.addOutput(w.getAddress(), 50000);
    tx.addOutput(w.getAddress(), 10000);

    const prev = Script.fromProgram(0, kp.getKeyHash());
    const prevHash = random.randomBytes(32).toString('hex');

    tx.addCoin(dummy(prev, prevHash));

    tx = tx.toTX();

    let err;
    try {
      await mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(err.malleated);
    assert(!mempool.hasReject(tx.hash()));
  });

  it('should cache non-malleated tx without sig', async () => {
    const w = wallet;
    const kp = KeyRing.generate();

    let tx = new MTX();
    tx.addOutput(w.getAddress(), 50000);
    tx.addOutput(w.getAddress(), 10000);

    const prev = Script.fromPubkey(kp.publicKey);
    const prevHash = random.randomBytes(32).toString('hex');

    tx.addCoin(dummy(prev, prevHash));

    tx = tx.toTX();

    let err;
    try {
      await mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!err.malleated);
    assert(mempool.hasReject(tx.hash()));
    cached = tx;
  });

  it('should clear reject cache', async () => {
    const w = wallet;

    let tx = new MTX();
    tx.addOutpoint(new Outpoint());
    tx.addOutput(w.getAddress(), 50000);
    tx = tx.toTX();

    assert(mempool.hasReject(cached.hash()));
    await mempool.addBlock({ height: 1 }, [tx]);
    assert(!mempool.hasReject(cached.hash()));
  });

  it('should destroy mempool', async () => {
    await mempool.close();
  });
});
