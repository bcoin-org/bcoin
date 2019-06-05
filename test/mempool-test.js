/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const random = require('bcrypto/lib/random');
const common = require('../lib/blockchain/common');
const Block = require('../lib/primitives/block');
const MempoolEntry = require('../lib/mempool/mempoolentry');
const Mempool = require('../lib/mempool/mempool');
const AddrIndexer = require('../lib/mempool/addrindexer');
const WorkerPool = require('../lib/workers/workerpool');
const Chain = require('../lib/blockchain/chain');
const MTX = require('../lib/primitives/mtx');
const Coin = require('../lib/primitives/coin');
const KeyRing = require('../lib/primitives/keyring');
const Address = require('../lib/primitives/address');
const Outpoint = require('../lib/primitives/outpoint');
const Input = require('../lib/primitives/input');
const Script = require('../lib/script/script');
const Opcode = require('../lib/script/opcode');
const opcodes = Script.opcodes;
const Witness = require('../lib/script/witness');
const MemWallet = require('./util/memwallet');
const BlockStore = require('../lib/blockstore/level');
const {BufferSet} = require('buffer-map');

const ALL = Script.hashType.ALL;
const VERIFY_NONE = common.flags.VERIFY_NONE;

const ONE_HASH = Buffer.alloc(32, 0x00);
ONE_HASH[0] = 0x01;

const workers = new WorkerPool({
  enabled: true,
  size: 2
});

const blocks = new BlockStore({
  memory: true
});

const chain = new Chain({
  memory: true,
  workers,
  blocks
});

const mempool = new Mempool({
  chain,
  memory: true,
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

async function getMockBlock(chain, txs = [], cb = true) {
  if (cb) {
    const raddr = KeyRing.generate().getAddress();
    const mtx = new MTX();
    mtx.addInput(new Input());
    mtx.addOutput(raddr, 0);

    txs = [mtx.toTX(), ...txs];
  }

  const now = Math.floor(Date.now() / 1000);
  const time = chain.tip.time <= now ? chain.tip.time + 1 : now;

  const block = new Block();
  block.txs = txs;
  block.prevBlock = chain.tip.hash;
  block.time = time;
  block.bits = await chain.getTarget(block.time, chain.tip);

  return block;
}

describe('Mempool', function() {
  this.timeout(5000);

  it('should open mempool', async () => {
    await workers.open();
    await blocks.open();
    await chain.open();
    await mempool.open();
    chain.state.flags |= Script.flags.VERIFY_WITNESS;
  });

  it('should handle incoming orphans and TXs', async () => {
    this.timeout(20000);
    const key = KeyRing.generate();

    const t1 = new MTX();
    t1.addOutput(wallet.getAddress(), 50000);
    t1.addOutput(wallet.getAddress(), 10000);

    const script = Script.fromPubkey(key.publicKey);

    t1.addCoin(dummyInput(script, ONE_HASH));

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
    input.script.setData(0, Buffer.alloc(73, 0x00));
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
      return tx.hash().equals(f1.hash());
    }));
  });

  it('should get spend coins and reflect in coinview', async () => {
    const wallet = new MemWallet();
    const script = Script.fromAddress(wallet.getAddress());
    const dummyCoin = dummyInput(script, random.randomBytes(32));

    // spend first output
    const mtx1 = new MTX();
    mtx1.addOutput(wallet.getAddress(), 50000);
    mtx1.addCoin(dummyCoin);
    wallet.sign(mtx1);

    // spend second tx
    const tx1 = mtx1.toTX();
    const coin1 = Coin.fromTX(tx1, 0, -1);
    const mtx2 = new MTX();

    mtx2.addOutput(wallet.getAddress(), 10000);
    mtx2.addOutput(wallet.getAddress(), 30000); // 10k fee..
    mtx2.addCoin(coin1);

    wallet.sign(mtx2);

    const tx2 = mtx2.toTX();

    await mempool.addTX(tx1);

    {
      const view = await mempool.getCoinView(tx2);
      assert(view.hasEntry(coin1));
    }

    await mempool.addTX(tx2);

    // we should not have coins available in the mempool for these txs.
    {
      const view = await mempool.getCoinView(tx1);
      const sview = await mempool.getSpentView(tx1);

      assert(!view.hasEntry(dummyCoin));
      assert(sview.hasEntry(dummyCoin));
    }

    {
      const view = await mempool.getCoinView(tx2);
      const sview = await mempool.getSpentView(tx2);
      assert(!view.hasEntry(coin1));
      assert(sview.hasEntry(coin1));
    }
  });

  it('should handle locktime', async () => {
    const key = KeyRing.generate();

    const tx = new MTX();
    tx.addOutput(wallet.getAddress(), 50000);
    tx.addOutput(wallet.getAddress(), 10000);

    const prev = Script.fromPubkey(key.publicKey);
    const prevHash = random.randomBytes(32);

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
    const prevHash = random.randomBytes(32);

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
    const prevHash = random.randomBytes(32);

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
    const prevHash = random.randomBytes(32);

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

  it('should cache a non-malleated tx with non-empty stack', async () => {
    // Wrap in P2SH, so we pass standardness checks.
    const key = KeyRing.generate();

    {
      const script = new Script();
      script.pushOp(opcodes.OP_1);
      script.compile();
      key.script = script;
    }

    const wallet = new MemWallet();
    const script = Script.fromAddress(wallet.getAddress());
    const dummyCoin = dummyInput(script, random.randomBytes(32));

    // spend first output
    const t1 = new MTX();
    t1.addOutput(key.getAddress(), 50000);
    t1.addCoin(dummyCoin);
    wallet.sign(t1);

    const t2 = new MTX();
    t2.addCoin(Coin.fromTX(t1, 0, 0));
    t2.addOutput(wallet.getAddress(), 40000);

    {
      const script = new Script();
      script.pushOp(opcodes.OP_1);
      script.pushData(key.script.toRaw());
      script.compile();

      t2.inputs[0].script = script;
    }

    await mempool.addTX(t1.toTX());

    let err;
    try {
      await mempool.addTX(t2.toTX());
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!err.malleated);
    assert(mempool.hasReject(t2.hash()));
  });

  it('should not cache a malleated wtx with wit removed', async () => {
    const key = KeyRing.generate();

    key.witness = true;

    const tx = new MTX();
    tx.addOutput(wallet.getAddress(), 50000);
    tx.addOutput(wallet.getAddress(), 10000);

    const prev = Script.fromProgram(0, key.getKeyHash());
    const prevHash = random.randomBytes(32);

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
    const prevHash = random.randomBytes(32);

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
    await chain.close();
    await blocks.close();
    await workers.close();
  });

  describe('Index', function () {
    const workers = new WorkerPool({
      enabled: true,
      size: 2
    });

    const blocks = new BlockStore({
      memory: true
    });

    const chain = new Chain({
      memory: true,
      workers,
      blocks
    });

    const mempool = new Mempool({
      chain,
      workers,
      memory: true,
      indexAddress: true
    });

    before(async () => {
      await blocks.open();
      await mempool.open();
      await chain.open();
      await workers.open();
    });

    after(async () => {
      await workers.close();
      await chain.close();
      await mempool.close();
      await blocks.close();
    });

    // Number of coins available in
    // chaincoins (100k satoshi per coin).
    const N = 100;
    const chaincoins = new MemWallet();
    const wallet = new MemWallet();

    it('should create coins in chain', async () => {
      const mtx = new MTX();
      mtx.addInput(new Input());

      for (let i = 0; i < N; i++) {
        const addr = chaincoins.createReceive().getAddress();
        mtx.addOutput(addr, 100000);
      }

      const cb = mtx.toTX();
      const block = await getMockBlock(chain, [cb], false);
      const entry = await chain.add(block, VERIFY_NONE);

      await mempool._addBlock(entry, block.txs);

      // Add 100 blocks so we don't get
      // premature spend of coinbase.
      for (let i = 0; i < 100; i++) {
        const block = await getMockBlock(chain);
        const entry = await chain.add(block, VERIFY_NONE);

        await mempool._addBlock(entry, block.txs);
      }

      chaincoins.addTX(cb);
    });

    it('should spend txs and coins in the mempool', async () => {
      // Verify coins are removed from the coin index.
      const coin = chaincoins.getCoins()[0];
      const addr = wallet.createReceive().getAddress();

      const mtx1 = new MTX();

      mtx1.addCoin(coin);
      mtx1.addOutput(addr, 90000);

      chaincoins.sign(mtx1);

      const tx1 = mtx1.toTX();

      chaincoins.addTX(tx1, -1);
      wallet.addTX(tx1, -1);

      {
        const missing = await mempool.addTX(tx1);
        assert.strictEqual(missing, null);
      }

      assert(mempool.hasCoin(tx1.hash(), 0));

      {
        const txs = mempool.getTXByAddress(addr);
        const metas = mempool.getMetaByAddress(addr);

        assert.strictEqual(txs.length, 1);
        assert.strictEqual(metas.length, 1);

        assert.bufferEqual(txs[0].hash(), tx1.hash());
      }

      const mtx2 = new MTX();

      mtx2.addTX(tx1, 0, -1);
      mtx2.addOutput(addr, 80000);

      wallet.sign(mtx2);

      const tx2 = mtx2.toTX();

      {
        const missing = await mempool.addTX(tx2);
        assert.strictEqual(missing, null);
      }

      wallet.addTX(tx2, -1);

      assert(!mempool.hasCoin(tx1.hash(), 0));
      assert(mempool.hasCoin(tx2.hash(), 0));

      {
        const txs = mempool.getTXByAddress(addr);

        assert.strictEqual(txs.length, 2);
      }
    });

    it('should spend resolved orphans', async () => {
      const coin = chaincoins.getCoins()[0];
      const addr = wallet.createReceive().getAddress();

      const pmtx = new MTX();

      pmtx.addOutput(addr, 90000);
      pmtx.addCoin(coin);

      chaincoins.sign(pmtx);

      const parentTX = pmtx.toTX();

      const cmtx = new MTX();

      cmtx.addTX(pmtx.toTX(), 0, -1);
      cmtx.addOutput(addr, 80000);

      wallet.sign(cmtx);

      const childTX = cmtx.toTX();

      {
        // Create orphan tx.
        const missing = await mempool.addTX(childTX);

        // We only have one input missing.
        assert.strictEqual(missing.length, 1);
      }

      {
        const txs = mempool.getTXByAddress(addr);

        assert.strictEqual(txs.length, 0);
      }

      {
        // Orphans are not coins.
        const childCoin = mempool.getCoin(childTX.hash(), 0);
        assert.strictEqual(childCoin, null);
      }

      {
        // Orphans should be resolved.
        const missing = await mempool.addTX(parentTX);
        assert.strictEqual(missing, null);

        // Coins should be available once they are resolved.
        const parentCoin = mempool.getCoin(parentTX.hash(), 0);

        // We spent this.
        assert.strictEqual(parentCoin, null);

        const childCoin = mempool.getCoin(childTX.hash(), 0);
        assert(childCoin);
      }

      {
        const txs = mempool.getTXByAddress(addr);
        assert.strictEqual(txs.length, 2);
      }

      // Update coins in wallets.
      for (const tx of [parentTX, childTX]) {
        chaincoins.addTX(tx);
        wallet.addTX(tx);
      }
    });

    it('should remove double spend tx from mempool', async () => {
      const coin = chaincoins.getCoins()[0];
      const addr = wallet.createReceive().getAddress();
      const randomAddress = KeyRing.generate().getAddress();

      // We check double spending our mempool tx.
      const mtx1 = new MTX();

      mtx1.addCoin(coin);
      mtx1.addOutput(addr, 90000);

      chaincoins.sign(mtx1);

      // This will double spend in block.
      const mtx2 = new MTX();

      mtx2.addCoin(coin);
      mtx2.addOutput(randomAddress, 90000);

      chaincoins.sign(mtx2);

      const tx1 = mtx1.toTX();
      const tx2 = mtx2.toTX();

      {
        const missing = await mempool.addTX(tx1);
        assert.strictEqual(missing, null);
      }

      {
        const txs = mempool.getTXByAddress(addr);
        assert.strictEqual(txs.length, 1);
      }

      assert(mempool.hasCoin(tx1.hash(), 0));

      const block = await getMockBlock(chain, [tx2]);
      const entry = await chain.add(block, VERIFY_NONE);

      await mempool._addBlock(entry, block.txs);

      {
        const txs = mempool.getTXByAddress(addr);
        assert.strictEqual(txs.length, 0);
      }

      assert(!mempool.hasCoin(tx1.hash(), 0));

      chaincoins.addTX(tx2);
    });

    it('should remove confirmed txs from mempool', async () => {
      const coin = chaincoins.getCoins()[0];
      const addr = wallet.createReceive().getAddress();

      const mtx = new MTX();

      mtx.addCoin(coin);
      mtx.addOutput(addr, 90000);

      chaincoins.sign(mtx);

      const tx = mtx.toTX();

      await mempool.addTX(tx);

      assert(mempool.hasCoin(tx.hash(), 0));

      {
        const txs = mempool.getTXByAddress(addr);
        assert.strictEqual(txs.length, 1);
      }

      const block = await getMockBlock(chain, [tx]);
      const entry = await chain.add(block, VERIFY_NONE);

      await mempool._addBlock(entry, block.txs);

      {
        const txs = mempool.getTXByAddress(addr);
        assert.strictEqual(txs.length, 0);
      }

      assert(!mempool.hasCoin(tx.hash(), 0));

      chaincoins.addTX(tx);
      wallet.addTX(tx);
    });
  });

  describe('AddrIndexer', function () {
    it('will not get key for witness program v1', function() {
      const addrindex = new AddrIndexer();

      // Create a witness program version 1 with
      // 40 byte data push.
      const script = new Script();
      script.push(Opcode.fromSmall(1));
      script.push(Opcode.fromData(Buffer.alloc(40)));
      script.compile();
      const addr = Address.fromScript(script);

      const key = addrindex.getKey(addr);

      assert.strictEqual(key, null);
    });

    it('will get key for witness program v0', function() {
      const addrindex = new AddrIndexer();

      // Create a witness program version 0 with
      // 32 byte data push.
      const script = new Script();
      script.push(Opcode.fromSmall(0));
      script.push(Opcode.fromData(Buffer.alloc(32)));
      script.compile();
      const addr = Address.fromScript(script);

      const key = addrindex.getKey(addr);

      assert.bufferEqual(key, Buffer.from('0a' + '00'.repeat(32), 'hex'));
    });
  });

  describe('Mempool persistent cache', function () {
    const workers = new WorkerPool({
      enabled: true,
      size: 2
    });

    const blocks = new BlockStore({
      memory: true
    });

    const chain = new Chain({
      memory: true,
      workers,
      blocks
    });

    const mempool = new Mempool({
      chain,
      workers,
      memory: true,
      indexAddress: true,
      persistent: true
    });

    before(async () => {
      await blocks.open();
      await mempool.open();
      await chain.open();
      await workers.open();
    });

    after(async () => {
      await workers.close();
      await chain.close();
      await mempool.close();
      await blocks.close();
    });

    // Number of coins available in
    // chaincoins (100k satoshi per coin).
    const N = 100;
    const chaincoins = new MemWallet();
    const wallet = new MemWallet();

    it('should create txs in chain', async () => {
      const mtx = new MTX();
      mtx.addInput(new Input());

      for (let i = 0; i < N; i++) {
        const addr = chaincoins.createReceive().getAddress();
        mtx.addOutput(addr, 100000);
      }

      const cb = mtx.toTX();
      const block = await getMockBlock(chain, [cb], false);
      const entry = await chain.add(block, VERIFY_NONE);

      await mempool._addBlock(entry, block.txs);

      // Add 100 blocks so we don't get premature
      // spend of coinbase.
      for (let i = 0; i < 100; i++) {
        const block = await getMockBlock(chain);
        const entry = await chain.add(block, VERIFY_NONE);

        await mempool._addBlock(entry, block.txs);
      }

      chaincoins.addTX(cb);
    });

    it('should restore txs in the mempool', async () => {
      this.timeout(20000);
      const coins = chaincoins.getCoins();

      assert.strictEqual(coins.length, N);

      const addrs = [];
      const txs = 20;
      const spend = 5;

      for (let i = 0; i < txs; i++)
        addrs.push(wallet.createReceive().getAddress());

      const mempoolTXs = new BufferSet();
      const mempoolCoins = new BufferSet();

      // Send 15 txs to the wallet.
      for (let i = 0; i < txs - spend; i++) {
        const mtx = new MTX();

        mtx.addCoin(coins[i]);
        mtx.addOutput(addrs[i], 90000);

        chaincoins.sign(mtx);

        const tx = mtx.toTX();
        const missing = await mempool.addTX(tx);

        assert.strictEqual(missing, null);
        assert(mempool.hasCoin(tx.hash(), 0));

        // Indexer checks.
        {
          const txs = mempool.getTXByAddress(addrs[i]);

          assert.strictEqual(txs.length, 1);
          assert.bufferEqual(txs[0].hash(), tx.hash());
        }

        wallet.addTX(tx);

        mempoolTXs.add(tx.hash());
        mempoolCoins.add(Outpoint.fromTX(tx, 0).toKey());
      }

      // Spend first 5 coins from the mempool.
      for (let i = 0; i < spend; i++) {
        const coin = wallet.getCoins()[0];
        const addr = addrs[txs - spend + i];
        const mtx = new MTX();

        mtx.addCoin(coin);
        mtx.addOutput(addr, 80000);

        wallet.sign(mtx);

        const tx = mtx.toTX();
        const missing = await mempool.addTX(tx);

        assert.strictEqual(missing, null);
        assert(!mempool.hasCoin(coin.hash, 0));
        assert(mempool.hasCoin(tx.hash(), 0));

        {
          const txs = mempool.getTXByAddress(addr);
          assert.strictEqual(txs.length, 1);
        }

        {
          const txs = mempool.getTXByAddress(addrs[i]);
          assert.strictEqual(txs.length, 2);
        }

        mempoolTXs.add(tx.hash());
        mempoolCoins.delete(coin.toKey());
        mempoolCoins.add(Outpoint.fromTX(tx, 0).toKey());

        wallet.addTX(tx);
      }

      const verifyMempoolState = (mempool) => {
        // Verify general state of the mempool.
        assert.strictEqual(mempool.map.size, txs);
        assert.strictEqual(mempool.spents.size, txs);

        assert.strictEqual(mempool.addrindex.map.size, txs);

        // Verify txs are same.
        for (const val of mempoolTXs.values())
          assert(mempool.getTX(val));

        for (const opkey of mempoolCoins.values()) {
          const outpoint = Outpoint.fromRaw(opkey);
          assert(mempool.hasCoin(outpoint.hash, outpoint.index));
        }

        // Coins in these txs are spent.
        for (let i = 0; i < spend; i++) {
          const addr = addrs[i];

          const txs = mempool.getTXByAddress(addr);
          assert.strictEqual(txs.length, 2);
        }

        // These txs are untouched.
        for (let i = spend; i < txs - spend; i++) {
          const addr = addrs[i];

          const txs = mempool.getTXByAddress(addr);
          assert.strictEqual(txs.length, 1);
        }

        // These are txs spending mempool txs.
        for (let i = txs - spend; i < txs; i++) {
          const addr = addrs[i];

          const txs = mempool.getTXByAddress(addr);
          assert.strictEqual(txs.length, 1);
        }
      };

      verifyMempoolState(mempool);

      // Hack to get in memory cache in new mempool.
      const cache = mempool.cache;

      // We need to manually sync because when first block
      // was mined there were no mempool txs.
      await cache.sync(chain.tip.hash);

      // Apply batch to the memdb.
      await cache.flush();
      await mempool.close();

      let err;
      {
        const mempool = new Mempool({
          chain,
          workers,
          memory: true,
          indexAddress: true,
          persistent: true
        });

        mempool.cache = cache;

        await mempool.open();

        try {
          verifyMempoolState(mempool);
        } catch (e) {
          err = e;
        } finally {
          await cache.wipe();
          await mempool.close();
        }
      }

      // Reopen for after cleanup.
      await mempool.open();

      if (err)
        throw err;
    });
  });
});
