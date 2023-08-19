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

      assert.bufferEqual(key, Buffer.from('00' + '00'.repeat(32), 'hex'));
    });

    it('will get key for witness program v1', function() {
      const addrindex = new AddrIndexer();

      // Create a witness program version 1 with
      // 32 byte data push.
      const script = new Script();
      script.push(Opcode.fromSmall(1));
      script.push(Opcode.fromData(Buffer.alloc(32)));
      script.compile();
      const addr = Address.fromScript(script);

      const key = addrindex.getKey(addr);

      assert.bufferEqual(key, Buffer.from('01' + '00'.repeat(32), 'hex'));
    });

    it('will get key for witness program v15', function() {
      const addrindex = new AddrIndexer();

      // Create a witness program version 15 with
      // 32 byte data push.
      const script = new Script();
      script.push(Opcode.fromSmall(15));
      script.push(Opcode.fromData(Buffer.alloc(32)));
      script.compile();
      const addr = Address.fromScript(script);

      const key = addrindex.getKey(addr);

      assert.bufferEqual(key, Buffer.from('0f' + '00'.repeat(32), 'hex'));
    });

    it('will get key for P2PKH', function() {
      const addrindex = new AddrIndexer();

      const script = Script.fromPubkeyhash(Buffer.alloc(20));
      const addr = Address.fromScript(script);

      const key = addrindex.getKey(addr);

      assert.bufferEqual(key, Buffer.from('80' + '00'.repeat(20), 'hex'));
    });

    it('will get key for P2SH', function() {
      const addrindex = new AddrIndexer();

      const script = Script.fromScripthash(Buffer.alloc(20));
      const addr = Address.fromScript(script);

      const key = addrindex.getKey(addr);

      assert.bufferEqual(key, Buffer.from('85' + '00'.repeat(20), 'hex'));
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

  describe('Replace-by-fee', function () {
    const blocks = new BlockStore({
      memory: true
    });

    const chain = new Chain({
      memory: true,
      blocks
    });

    const mempool = new Mempool({
      chain,
      memory: true
    });

    before(async () => {
      await blocks.open();
      await mempool.open();
      await chain.open();
    });

    after(async () => {
      await chain.close();
      await mempool.close();
      await blocks.close();
    });

    beforeEach(async () => {
      await mempool.reset();
      assert.strictEqual(mempool.map.size, 0);
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

    it('should not accept RBF tx', async() => {
      mempool.options.replaceByFee = false;

      const mtx = new MTX();
      const coin = chaincoins.getCoins()[0];
      mtx.addCoin(coin);
      mtx.inputs[0].sequence = 0xfffffffd;

      const addr = wallet.createReceive().getAddress();
      mtx.addOutput(addr, 90000);

      chaincoins.sign(mtx);

      assert(mtx.verify());
      const tx = mtx.toTX();

      await assert.rejects(async () => {
        await mempool.addTX(tx);
      }, {
        type: 'VerifyError',
        reason: 'replace-by-fee'
      });

      assert(!mempool.hasCoin(tx.hash(), 0));
      assert.strictEqual(mempool.map.size, 0);
    });

    it('should accept RBF tx with RBF option enabled', async() => {
      mempool.options.replaceByFee = true;

      const mtx = new MTX();
      const coin = chaincoins.getCoins()[0];
      mtx.addCoin(coin);
      mtx.inputs[0].sequence = 0xfffffffd;

      const addr = wallet.createReceive().getAddress();
      mtx.addOutput(addr, coin.value - 1000);

      chaincoins.sign(mtx);

      assert(mtx.verify());
      const tx = mtx.toTX();

      await mempool.addTX(tx);

      assert(mempool.hasCoin(tx.hash(), 0));
      assert.strictEqual(mempool.map.size, 1);
    });

    it('should reject double spend without RBF from mempool', async() => {
      mempool.options.replaceByFee = true;

      const coin = chaincoins.getCoins()[0];

      const mtx1 = new MTX();
      const mtx2 = new MTX();
      mtx1.addCoin(coin);
      mtx2.addCoin(coin);

      const addr1 = wallet.createReceive().getAddress();
      mtx1.addOutput(addr1, coin.value - 1000);

      const addr2 = wallet.createReceive().getAddress();
      mtx2.addOutput(addr2, coin.value - 1000);

      chaincoins.sign(mtx1);
      chaincoins.sign(mtx2);

      assert(mtx1.verify());
      assert(mtx2.verify());
      const tx1 = mtx1.toTX();
      const tx2 = mtx2.toTX();

      assert(!tx1.isRBF());

      await mempool.addTX(tx1);

      await assert.rejects(async () => {
        await mempool.addTX(tx2);
      }, {
        type: 'VerifyError',
        reason: 'bad-txns-inputs-spent'
      });

      assert(mempool.hasCoin(tx1.hash(), 0));
      assert.strictEqual(mempool.map.size, 1);
    });

    it('should reject replacement with lower fee rate', async() => {
      mempool.options.replaceByFee = true;

      const coin = chaincoins.getCoins()[0];

      const mtx1 = new MTX();
      const mtx2 = new MTX();
      mtx1.addCoin(coin);
      mtx2.addCoin(coin);

      mtx1.inputs[0].sequence = 0xfffffffd;

      const addr1 = wallet.createReceive().getAddress();
      mtx1.addOutput(addr1, coin.value - 1000); // 1000 satoshi fee

      const addr2 = wallet.createReceive().getAddress();
      mtx2.addOutput(addr2, coin.value - 900); // 900 satoshi fee

      chaincoins.sign(mtx1);
      chaincoins.sign(mtx2);

      assert(mtx1.verify());
      assert(mtx2.verify());
      const tx1 = mtx1.toTX();
      const tx2 = mtx2.toTX();

      assert(tx1.isRBF());

      await mempool.addTX(tx1);

      await assert.rejects(async () => {
        await mempool.addTX(tx2);
      }, {
        type: 'VerifyError',
        reason: 'insufficient fee: must not reduce total mempool fee rate'
      });

      // Try again with higher fee
      const mtx3 = new MTX();
      mtx3.addCoin(coin);
      mtx3.addOutput(addr2, coin.value - 1200); // 1200 satoshi fee
      chaincoins.sign(mtx3);
      assert(mtx3.verify());
      const tx3 = mtx3.toTX();

      await mempool.addTX(tx3);

      // tx1 has been replaced by tx3
      assert(!mempool.has(tx1.hash()));
      assert(mempool.has(tx3.hash()));
    });

    it('should reject replacement that doesnt pay all child fees', async() => {
      mempool.options.replaceByFee = true;

      const addr1 = chaincoins.createReceive().getAddress();
      const addr2 = wallet.createReceive().getAddress();
      const originalCoin = chaincoins.getCoins()[0];
      let coin = originalCoin;

      // Generate chain of 10 transactions, each paying 1000 sat fee
      const childHashes = [];
      for (let i = 0; i < 10; i++) {
        const mtx = new MTX();
        mtx.addCoin(coin);
        mtx.inputs[0].sequence = 0xfffffffd;
        mtx.addOutput(addr1, coin.value - 1000);
        chaincoins.sign(mtx);
        assert(mtx.verify());
        const tx = mtx.toTX();
        await mempool.addTX(tx);

        childHashes.push(tx.hash());

        coin = Coin.fromTX(tx, 0, -1);
      }

      // Pay for all child fees
      let fee = 10 * 1000;

      // Pay for its own bandwidth (estimating tx2 size as 200 bytes)
      fee += mempool.options.minRelay * 0.2;

      // Attempt to submit a replacement for the initial parent TX
      const mtx2 = new MTX();
      mtx2.addCoin(originalCoin);
      mtx2.addOutput(addr2, originalCoin.value - fee + 100);
      chaincoins.sign(mtx2);
      assert(mtx2.verify());
      const tx2 = mtx2.toTX();

      await assert.rejects(async () => {
        await mempool.addTX(tx2);
      }, {
        type: 'VerifyError',
        reason: 'insufficient fee: must pay for fees including conflicts'
      });

      // Try again with higher fee
      const mtx3 = new MTX();
      mtx3.addCoin(originalCoin);
      mtx3.addOutput(addr2, originalCoin.value - fee);
      chaincoins.sign(mtx3);
      assert(mtx3.verify());
      const tx3 = mtx3.toTX();

      await mempool.addTX(tx3);

      // All child TXs have been replaced by tx3
      for (const hash of childHashes)
        assert(!mempool.has(hash));
      assert(mempool.has(tx3.hash()));
    });

    it('should reject replacement including new unconfirmed UTXO', async() => {
      // {confirmed coin 1}     {confirmed coin 2}
      //    |     |                      |
      //    |   tx 1                   tx 2 {output}
      //    |                                  |
      //    | +--------------------------------+
      //    | |
      //   tx 3 is invalid!

      mempool.options.replaceByFee = true;

      const coin1 = chaincoins.getCoins()[0];
      const coin2 = chaincoins.getCoins()[1];

      // tx 1 spends a confirmed coin
      const mtx1 = new MTX();
      mtx1.addCoin(coin1);
      mtx1.inputs[0].sequence = 0xfffffffd;
      const addr1 = chaincoins.createReceive().getAddress();
      mtx1.addOutput(addr1, coin1.value - 1000);
      chaincoins.sign(mtx1);
      assert(mtx1.verify());
      const tx1 = mtx1.toTX();
      assert(tx1.isRBF());
      await mempool.addTX(tx1);

      // tx 2 spends a different confirmed coin
      const mtx2 = new MTX();
      mtx2.addCoin(coin2);
      const addr2 = chaincoins.createReceive().getAddress();
      mtx2.addOutput(addr2, coin2.value - 1000);
      chaincoins.sign(mtx2);
      assert(mtx2.verify());
      const tx2 = mtx2.toTX();
      await mempool.addTX(tx2);

      // Attempt to replace tx 1 and include the unconfirmed output of tx 2
      const mtx3 = new MTX();
      mtx3.addCoin(coin1);
      const coin3 = Coin.fromTX(tx2, 0, -1);
      mtx3.addCoin(coin3);
      const addr3 = wallet.createReceive().getAddress();
      // Remember to bump the fee!
      mtx3.addOutput(addr3, coin1.value + coin3.value - 2000);
      chaincoins.sign(mtx3);
      assert(mtx3.verify());
      const tx3 = mtx3.toTX();

      await assert.rejects(async () => {
        await mempool.addTX(tx3);
      }, {
        type: 'VerifyError',
        reason: 'replacement-adds-unconfirmed'
      });
    });

    it('should reject replacement evicting too many descendants', async() => {
      mempool.options.replaceByFee = true;

      const addr1 = chaincoins.createReceive().getAddress();
      const coin0 = chaincoins.getCoins()[0];
      const coin1 = chaincoins.getCoins()[1];

      // Generate big TX with 100 outputs
      const mtx1 = new MTX();
      mtx1.addCoin(coin0);
      mtx1.addCoin(coin1);
      mtx1.inputs[0].sequence = 0xfffffffd;
      const outputValue = (coin0.value / 100) + (coin1.value / 100) - 100;
      for (let i = 0; i < 100; i++)
        mtx1.addOutput(addr1, outputValue);

      chaincoins.sign(mtx1);
      assert(mtx1.verify());
      const tx1 = mtx1.toTX();
      await mempool.addTX(tx1);

      // Spend each of those outputs individually
      let tx;
      const hashes = [];
      for (let i = 0; i < 100; i++) {
        const mtx = new MTX();
        const coin = Coin.fromTX(tx1, i, -1);
        mtx.addCoin(coin);
        mtx.addOutput(addr1, coin.value - 1000);
        chaincoins.sign(mtx);
        assert(mtx.verify());
        tx = mtx.toTX();

        hashes.push(tx.hash());

        await mempool.addTX(tx);
      }

      // Attempt to evict the whole batch by replacing the first TX (tx1)
      const mtx2 = new MTX();
      mtx2.addCoin(coin0);
      mtx2.addCoin(coin1);
      // Send with massive fee to pay for 100 evicted TXs
      mtx2.addOutput(addr1, 5000);
      chaincoins.sign(mtx2);
      assert(mtx2.verify());
      const tx2 = mtx2.toTX();

      await assert.rejects(async () => {
        await mempool.addTX(tx2);
      }, {
        type: 'VerifyError',
        reason: 'too many potential replacements'
      });

      // Manually remove one of the descendants in advance
      const entry = mempool.getEntry(tx.hash());
      mempool.evictEntry(entry);

      // Send back the same TX
      await mempool.addTX(tx2);

      // Entire mess has been replaced by tx2
      assert(mempool.has(tx2.hash()));
      assert(!mempool.has(tx1.hash()));
      for (const hash of hashes)
        assert(!mempool.has(hash));
    });

    it('should accept replacement spending an unconfirmed output', async () => {
      // {confirmed coin 1}
      //     |
      //   tx 0 {output}
      //         |   |
      //       tx 1  |
      //             |
      //           tx 2

      mempool.options.replaceByFee = true;

      const addr1 = chaincoins.createReceive().getAddress();
      const coin0 = chaincoins.getCoins()[0];

      // Generate parent tx 0
      const mtx0 = new MTX();
      mtx0.addCoin(coin0);
      mtx0.addOutput(addr1, coin0.value - 200);
      chaincoins.sign(mtx0);
      assert(mtx0.verify());
      const tx0 = mtx0.toTX();
      await mempool.addTX(tx0);

      // Spend unconfirmed output to replaceable child tx 1
      const mtx1 = new MTX();
      const coin1 = Coin.fromTX(tx0, 0, -1);
      mtx1.addCoin(coin1);
      mtx1.inputs[0].sequence = 0xfffffffd;
      mtx1.addOutput(addr1, coin1.value - 200);
      chaincoins.sign(mtx1);
      assert(mtx1.verify());
      const tx1 = mtx1.toTX();
      await mempool.addTX(tx1);

      // Send replacement tx 2
      const mtx2 = new MTX();
      mtx2.addCoin(coin1);
      mtx2.addOutput(addr1, coin1.value - 400);
      chaincoins.sign(mtx2);
      assert(mtx2.verify());
      const tx2 = mtx2.toTX();
      await mempool.addTX(tx2);

      // Unconfirmed parent tx 0 and replacement tx 2 are in mempool together
      assert(mempool.has(tx0.hash()));
      assert(!mempool.has(tx1.hash()));
      assert(mempool.has(tx2.hash()));
    });

    it('should not accept replacement for non-rbf spender of unconfirmed utxo', async () => {
      mempool.options.replaceByFee = true;

      const addr1 = chaincoins.createReceive().getAddress();
      const coin0 = chaincoins.getCoins()[0];

      // Generate parent TX
      const mtx0 = new MTX();
      mtx0.addCoin(coin0);
      mtx0.addOutput(addr1, coin0.value - 200);
      chaincoins.sign(mtx0);
      assert(mtx0.verify());
      const tx0 = mtx0.toTX();
      await mempool.addTX(tx0);

      // Spend unconfirmed output to non-replaceable child
      const mtx1 = new MTX();
      const coin1 = Coin.fromTX(tx0, 0, -1);
      mtx1.addCoin(coin1);
      mtx1.inputs[0].sequence = 0xffffffff; // not replaceable
      mtx1.addOutput(addr1, coin1.value - 200);
      chaincoins.sign(mtx1);
      assert(mtx1.verify());
      const tx1 = mtx1.toTX();
      await mempool.addTX(tx1);

      // Send attempted replacement
      const mtx2 = new MTX();
      mtx2.addCoin(coin1);
      mtx2.addOutput(addr1, coin1.value - 400);
      chaincoins.sign(mtx2);
      assert(mtx2.verify());
      const tx2 = mtx2.toTX();

      await assert.rejects(async () => {
        await mempool.addTX(tx2);
      }, {
        type: 'VerifyError',
        reason: 'bad-txns-inputs-spent'
      });
    });

    it('should not accept replacement that evicts its own inputs', async () => {
      // {confirmed coin 1}
      //     |
      //   tx 0 {output}
      //          |   |
      //          | tx 1 {output}
      //          |         |
      //          | +-------+
      //          | |
      //         tx 2 is invalid!

      mempool.options.replaceByFee = true;

      const addr1 = chaincoins.createReceive().getAddress();
      const coin0 = chaincoins.getCoins()[0];

      // Generate tx 0 which spends a confirmed coin
      const mtx0 = new MTX();
      mtx0.addCoin(coin0);
      mtx0.addOutput(addr1, coin0.value - 200);
      chaincoins.sign(mtx0);
      assert(mtx0.verify());
      const tx0 = mtx0.toTX();
      await mempool.addTX(tx0);

      // Generate tx 1 which spends an output of tx 0
      const mtx1 = new MTX();
      const coin1 = Coin.fromTX(tx0, 0, -1);
      mtx1.addCoin(coin1);
      mtx1.inputs[0].sequence = 0xfffffffd;
      mtx1.addOutput(addr1, coin1.value - 200);
      chaincoins.sign(mtx1);
      assert(mtx1.verify());
      const tx1 = mtx1.toTX();
      await mempool.addTX(tx1);

      // Send tx 2 which attempts to:
      //   - replace tx 1 by spending an output of tx 0
      //   - ALSO spend an output of tx 1
      // This is obviously invalid because if tx 1 is replaced,
      // its output no longer exists so it can not be spent by tx 2.
      const mtx2 = new MTX();
      mtx2.addCoin(coin1);
      const coin2 = Coin.fromTX(tx1, 0, -1);
      mtx2.addCoin(coin2);
      mtx2.addOutput(addr1, coin2.value + coin1.value - 1000);
      chaincoins.sign(mtx2);
      assert(mtx2.verify());
      const tx2 = mtx2.toTX();

      await assert.rejects(async () => {
        await mempool.addTX(tx2);
      }, {
        type: 'VerifyError',
        reason: 'replacement-adds-unconfirmed'
      });

      assert(mempool.has(tx0.hash()));
      assert(mempool.has(tx1.hash()));
      assert(!mempool.has(tx2.hash()));
    });
  });
});
