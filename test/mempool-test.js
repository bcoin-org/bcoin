/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const encoding = require('../lib/utils/encoding');
const random = require('../lib/crypto/random');
const MempoolEntry = require('../lib/mempool/mempoolentry');
const Mempool = require('../lib/mempool/mempool');
const WorkerPool = require('../lib/workers/workerpool');
const Chain = require('../lib/blockchain/chain');
const MTX = require('../lib/primitives/mtx');
const Coin = require('../lib/primitives/coin');
const KeyRing = require('../lib/primitives/keyring');
const Address = require('../lib/primitives/address');
const Outpoint = require('../lib/primitives/outpoint');
const Script = require('../lib/script/script');
const Witness = require('../lib/script/witness');
const MemWallet = require('./util/memwallet');
const ALL = Script.hashType.ALL;

const workers = new WorkerPool({
  enabled: true
});

const chain = new Chain({
  db: 'memory',
  workers
});

const mempool = new Mempool({
  chain,
  db: 'memory',
  workers
});

const wallet = new MemWallet();

let cachedTX = null;

function dummyInput(script, hash) {
  const coin = new Coin();
  coin.height = 0;
  coin.value = 0;
  coin.script = script;
  coin.hash = hash;
  coin.index = 0;

  const fund = new MTX();
  fund.addCoin(coin);
  fund.addOutput(script, 70000);

  const [tx, view] = fund.commit();

  const entry = MempoolEntry.fromTX(tx, view, 0);

  mempool.trackEntry(entry, view);

  return Coin.fromTX(fund, 0, -1);
}

describe('Mempool', function() {
  this.timeout(5000);

  it('should open mempool', async () => {
    await mempool.open();
    chain.state.flags |= Script.flags.VERIFY_WITNESS;
  });

  it('should handle incoming orphans and TXs', async () => {
    const key = KeyRing.generate();

    const t1 = new MTX();
    t1.addOutput(wallet.getAddress(), 50000);
    t1.addOutput(wallet.getAddress(), 10000);

    const script = Script.fromPubkey(key.publicKey);

    t1.addCoin(dummyInput(script, encoding.ONE_HASH.toString('hex')));

    const sig = t1.signature(0, script, 70000, key.privateKey, ALL, 0);

    t1.inputs[0].script = Script.fromItems([sig]);

    // balance: 51000
    wallet.sign(t1);

    const t2 = new MTX();
    t2.addTX(t1, 0); // 50000
    t2.addOutput(wallet.getAddress(), 20000);
    t2.addOutput(wallet.getAddress(), 20000);

    // balance: 49000
    wallet.sign(t2);

    const t3 = new MTX();
    t3.addTX(t1, 1); // 10000
    t3.addTX(t2, 0); // 20000
    t3.addOutput(wallet.getAddress(), 23000);

    // balance: 47000
    wallet.sign(t3);

    const t4 = new MTX();
    t4.addTX(t2, 1); // 24000
    t4.addTX(t3, 0); // 23000
    t4.addOutput(wallet.getAddress(), 11000);
    t4.addOutput(wallet.getAddress(), 11000);

    // balance: 22000
    wallet.sign(t4);

    const f1 = new MTX();
    f1.addTX(t4, 1); // 11000
    f1.addOutput(new Address(), 9000);

    // balance: 11000
    wallet.sign(f1);

    const fake = new MTX();
    fake.addTX(t1, 1); // 1000 (already redeemed)
    fake.addOutput(wallet.getAddress(), 6000); // 6000 instead of 500

    // Script inputs but do not sign
    wallet.template(fake);

    // Fake signature
    const input = fake.inputs[0];
    input.script.setData(0, encoding.ZERO_SIG);
    input.script.compile();
    // balance: 11000

    {
      await mempool.addTX(fake.toTX());
      await mempool.addTX(t4.toTX());

      const balance = mempool.getBalance();
      assert.strictEqual(balance, 70000);
    }

    {
      await mempool.addTX(t1.toTX());

      const balance = mempool.getBalance();
      assert.strictEqual(balance, 60000);
    }

    {
      await mempool.addTX(t2.toTX());

      const balance = mempool.getBalance();
      assert.strictEqual(balance, 50000);
    }

    {
      await mempool.addTX(t3.toTX());

      const balance = mempool.getBalance();
      assert.strictEqual(balance, 22000);
    }

    {
      await mempool.addTX(f1.toTX());

      const balance = mempool.getBalance();
      assert.strictEqual(balance, 20000);
    }

    const txs = mempool.getHistory();
    assert(txs.some((tx) => {
      return tx.hash('hex') === f1.hash('hex');
    }));
  });

  it('should handle locktime', async () => {
    const key = KeyRing.generate();

    const tx = new MTX();
    tx.addOutput(wallet.getAddress(), 50000);
    tx.addOutput(wallet.getAddress(), 10000);

    const prev = Script.fromPubkey(key.publicKey);
    const prevHash = random.randomBytes(32).toString('hex');

    tx.addCoin(dummyInput(prev, prevHash));
    tx.setLocktime(200);

    chain.tip.height = 200;

    const sig = tx.signature(0, prev, 70000, key.privateKey, ALL, 0);
    tx.inputs[0].script = Script.fromItems([sig]);

    await mempool.addTX(tx.toTX());
    chain.tip.height = 0;
  });

  it('should handle invalid locktime', async () => {
    const key = KeyRing.generate();

    const tx = new MTX();
    tx.addOutput(wallet.getAddress(), 50000);
    tx.addOutput(wallet.getAddress(), 10000);

    const prev = Script.fromPubkey(key.publicKey);
    const prevHash = random.randomBytes(32).toString('hex');

    tx.addCoin(dummyInput(prev, prevHash));
    tx.setLocktime(200);
    chain.tip.height = 200 - 1;

    const sig = tx.signature(0, prev, 70000, key.privateKey, ALL, 0);
    tx.inputs[0].script = Script.fromItems([sig]);

    let err;
    try {
      await mempool.addTX(tx.toTX());
    } catch (e) {
      err = e;
    }

    assert(err);

    chain.tip.height = 0;
  });

  it('should not cache a malleated wtx with mutated sig', async () => {
    const key = KeyRing.generate();

    key.witness = true;

    const tx = new MTX();
    tx.addOutput(wallet.getAddress(), 50000);
    tx.addOutput(wallet.getAddress(), 10000);

    const prev = Script.fromProgram(0, key.getKeyHash());
    const prevHash = random.randomBytes(32).toString('hex');

    tx.addCoin(dummyInput(prev, prevHash));

    const prevs = Script.fromPubkeyhash(key.getKeyHash());

    const sig = tx.signature(0, prevs, 70000, key.privateKey, ALL, 1);
    sig[sig.length - 1] = 0;

    tx.inputs[0].witness = new Witness([sig, key.publicKey]);

    let err;
    try {
      await mempool.addTX(tx.toTX());
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!mempool.hasReject(tx.hash()));
  });

  it('should not cache a malleated tx with unnecessary witness', async () => {
    const key = KeyRing.generate();

    const tx = new MTX();
    tx.addOutput(wallet.getAddress(), 50000);
    tx.addOutput(wallet.getAddress(), 10000);

    const prev = Script.fromPubkey(key.publicKey);
    const prevHash = random.randomBytes(32).toString('hex');

    tx.addCoin(dummyInput(prev, prevHash));

    const sig = tx.signature(0, prev, 70000, key.privateKey, ALL, 0);
    tx.inputs[0].script = Script.fromItems([sig]);
    tx.inputs[0].witness.push(Buffer.alloc(0));

    let err;
    try {
      await mempool.addTX(tx.toTX());
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!mempool.hasReject(tx.hash()));
  });

  it('should not cache a malleated wtx with wit removed', async () => {
    const key = KeyRing.generate();

    key.witness = true;

    const tx = new MTX();
    tx.addOutput(wallet.getAddress(), 50000);
    tx.addOutput(wallet.getAddress(), 10000);

    const prev = Script.fromProgram(0, key.getKeyHash());
    const prevHash = random.randomBytes(32).toString('hex');

    tx.addCoin(dummyInput(prev, prevHash));

    let err;
    try {
      await mempool.addTX(tx.toTX());
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(err.malleated);
    assert(!mempool.hasReject(tx.hash()));
  });

  it('should cache non-malleated tx without sig', async () => {
    const key = KeyRing.generate();

    const tx = new MTX();
    tx.addOutput(wallet.getAddress(), 50000);
    tx.addOutput(wallet.getAddress(), 10000);

    const prev = Script.fromPubkey(key.publicKey);
    const prevHash = random.randomBytes(32).toString('hex');

    tx.addCoin(dummyInput(prev, prevHash));

    let err;
    try {
      await mempool.addTX(tx.toTX());
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!err.malleated);
    assert(mempool.hasReject(tx.hash()));

    cachedTX = tx;
  });

  it('should clear reject cache', async () => {
    const tx = new MTX();
    tx.addOutpoint(new Outpoint());
    tx.addOutput(wallet.getAddress(), 50000);

    assert(mempool.hasReject(cachedTX.hash()));

    await mempool.addBlock({ height: 1 }, [tx.toTX()]);

    assert(!mempool.hasReject(cachedTX.hash()));
  });

  it('should destroy mempool', async () => {
    await mempool.close();
  });
});
