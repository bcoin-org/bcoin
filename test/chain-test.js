/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const {BloomFilter} = require('bfilter');
const BN = require('bcrypto/lib/bn.js');
const consensus = require('../lib/protocol/consensus');
const Coin = require('../lib/primitives/coin');
const Script = require('../lib/script/script');
const Chain = require('../lib/blockchain/chain');
const ChainDB = require('../lib/blockchain/chaindb');
const ChainEntry = require('../lib/blockchain/chainentry');
const WorkerPool = require('../lib/workers/workerpool');
const Miner = require('../lib/mining/miner');
const {Selector, MTX} = require('../lib/primitives/mtx');
const MemWallet = require('./util/memwallet');
const Network = require('../lib/protocol/network');
const Output = require('../lib/primitives/output');
const common = require('../lib/blockchain/common');
const nodejsUtil = require('util');
const Opcode = require('../lib/script/opcode');
const BlockStore = require('../lib/blockstore/level');
const opcodes = Script.opcodes;

const ZERO_KEY = Buffer.alloc(33, 0x00);

const ONE_HASH = Buffer.alloc(32, 0x00);
ONE_HASH[0] = 0x01;

const network = Network.get('regtest');

const workers = new WorkerPool({
  enabled: true,
  size: 2
});

const blocks = new BlockStore({
  memory: true,
  network
});

const chain = new Chain({
  memory: true,
  blocks,
  network,
  workers
});

const miner = new Miner({
  chain,
  version: 4,
  workers
});

const cpu = miner.cpu;

const wallet = new MemWallet({
  network,
  witness: false
});

const witWallet = new MemWallet({
  network,
  witness: true
});

let tip1 = null;
let tip2 = null;

async function addBlock(block, flags) {
  let entry;

  try {
    entry = await chain.add(block, flags);
  } catch (e) {
    assert.strictEqual(e.type, 'VerifyError');
    return e.reason;
  }

  if (!entry)
    return 'bad-prevblk';

  return 'OK';
}

async function mineBlock(job, flags) {
  const block = await job.mineAsync();
  return await addBlock(block, flags);
}

async function mineCSV(fund) {
  const job = await cpu.createJob();
  const spend = new MTX();

  spend.addOutput({
    script: [
      Opcode.fromInt(1),
      Opcode.fromSymbol('checksequenceverify')
    ],
    value: 10000
  });

  spend.addTX(fund, 0);
  spend.setLocktime(chain.height);

  wallet.sign(spend);

  const [tx, view] = spend.commit();

  job.addTX(tx, view);
  job.refresh();

  return await job.mineAsync();
}

chain.on('connect', (entry, block) => {
  wallet.addBlock(entry, block.txs);
});

chain.on('disconnect', (entry, block) => {
  wallet.removeBlock(entry, block.txs);
});

describe('Chain', function() {
  this.timeout(process.browser ? 1200000 : 60000);

  before(async () => {
    await blocks.open();
    await chain.open();
    await miner.open();
    await workers.open();

    miner.addresses.length = 0;
    miner.addAddress(wallet.getReceive());
  });

  after(async () => {
    await workers.close();
    await miner.close();
    await chain.close();
    await blocks.close();
  });

  it('should mine 200 blocks', async () => {
    for (let i = 0; i < 200; i++) {
      const block = await cpu.mineBlock();
      assert(block);
      assert(await chain.add(block));
    }

    assert.strictEqual(chain.height, 200);
  });

  it('should be full and recent', async () => {
    assert(chain.isFull());
    assert(await chain.isRecent());
  });

  it('should mine competing chains', async () => {
    for (let i = 0; i < 10; i++) {
      const job1 = await cpu.createJob(tip1);
      const job2 = await cpu.createJob(tip2);

      const mtx = await wallet.create({
        outputs: [{
          address: wallet.getAddress(),
          value: 10 * 1e8
        }]
      });

      job1.addTX(mtx.toTX(), mtx.view);
      job2.addTX(mtx.toTX(), mtx.view);

      job1.refresh();
      job2.refresh();

      const blk1 = await job1.mineAsync();
      const blk2 = await job2.mineAsync();

      const hash1 = blk1.hash();
      const hash2 = blk2.hash();

      assert(await chain.add(blk1));
      assert(await chain.add(blk2));

      assert.bufferEqual(chain.tip.hash, hash1);

      tip1 = await chain.getEntry(hash1);
      tip2 = await chain.getEntry(hash2);

      assert(tip1);
      assert(tip2);

      assert(!await chain.isMainChain(tip2));
    }
  });

  it('should have correct chain value', () => {
    assert.strictEqual(chain.db.state.value, 897500000000);
    assert.strictEqual(chain.db.state.coin, 220);
    assert.strictEqual(chain.db.state.tx, 221);
  });

  it('should have correct wallet balance', async () => {
    assert.strictEqual(wallet.balance, 897500000000);
  });

  it('should handle a reorg', async () => {
    assert.strictEqual(chain.height, 210);

    const entry = await chain.getEntry(tip2.hash);
    assert(entry);
    assert.strictEqual(chain.height, entry.height);

    const block = await cpu.mineBlock(entry);
    assert(block);

    let forked = false;
    chain.once('reorganize', () => {
      forked = true;
    });

    assert(await chain.add(block));

    assert(forked);
    assert.bufferEqual(chain.tip.hash, block.hash());
    assert(chain.tip.chainwork.gt(tip1.chainwork));
  });

  it('should have correct chain value', () => {
    assert.strictEqual(chain.db.state.value, 900000000000);
    assert.strictEqual(chain.db.state.coin, 221);
    assert.strictEqual(chain.db.state.tx, 222);
  });

  it('should have correct wallet balance', async () => {
    assert.strictEqual(wallet.balance, 900000000000);
  });

  it('should check main chain', async () => {
    const result = await chain.isMainChain(tip1);
    assert(!result);
  });

  it('should mine a block after a reorg', async () => {
    const block = await cpu.mineBlock();

    assert(await chain.add(block));

    const hash = block.hash();
    const entry = await chain.getEntry(hash);

    assert(entry);
    assert.bufferEqual(chain.tip.hash, entry.hash);

    const result = await chain.isMainChain(entry);
    assert(result);
  });

  it('should prevent double spend on new chain', async () => {
    const mtx = await wallet.create({
      outputs: [{
        address: wallet.getAddress(),
        value: 10 * 1e8
      }]
    });

    {
      const job = await cpu.createJob();

      job.addTX(mtx.toTX(), mtx.view);
      job.refresh();

      const block = await job.mineAsync();

      assert(await chain.add(block));
    }

    {
      const job = await cpu.createJob();

      assert(mtx.outputs.length > 1);
      mtx.outputs.pop();

      job.addTX(mtx.toTX(), mtx.view);
      job.refresh();

      assert.strictEqual(await mineBlock(job),
        'bad-txns-inputs-missingorspent');
    }
  });

  it('should fail to connect coins on an alternate chain', async () => {
    const block = await chain.getBlock(tip1.hash);
    const cb = block.txs[0];
    const mtx = new MTX();

    mtx.addTX(cb, 0);
    mtx.addOutput(wallet.getAddress(), 10 * 1e8);

    wallet.sign(mtx);

    const job = await cpu.createJob();
    job.addTX(mtx.toTX(), mtx.view);
    job.refresh();

    assert.strictEqual(await mineBlock(job), 'bad-txns-inputs-missingorspent');
  });

  it('should have correct chain value', () => {
    assert.strictEqual(chain.db.state.value, 905000000000);
    assert.strictEqual(chain.db.state.coin, 224);
    assert.strictEqual(chain.db.state.tx, 225);
  });

  it('should get coin', async () => {
    const mtx = await wallet.send({
      outputs: [
        {
          address: wallet.getAddress(),
          value: 1e8
        },
        {
          address: wallet.getAddress(),
          value: 1e8
        },
        {
          address: wallet.getAddress(),
          value: 1e8
        }
      ]
    });

    const job = await cpu.createJob();
    job.addTX(mtx.toTX(), mtx.view);
    job.refresh();

    const block = await job.mineAsync();
    assert(await chain.add(block));

    const tx = block.txs[1];
    const output = Coin.fromTX(tx, 2, chain.height);

    const coin = await chain.getCoin(tx.hash(), 2);

    assert.bufferEqual(coin.toRaw(), output.toRaw());
  });

  it('should have correct wallet balance', async () => {
    assert.strictEqual(wallet.balance, 907500000000);
    assert.strictEqual(wallet.receiveDepth, 15);
    assert.strictEqual(wallet.changeDepth, 14);
    assert.strictEqual(wallet.txs, 226);
  });

  it('should get tips and remove chains', async () => {
    {
      const tips = await chain.getTipEntries();

      let index = -1;

      for (let i = 0; i < tips.length; i++) {
        if (tips[i].hash.equals(chain.tip.hash))
          index = i;
      }

      assert.notStrictEqual(index, -1);
      assert.strictEqual(tips.length, 4);

      let count = 0;

      for (const entry of tips) {
        if (await chain.db.hasInvalid(entry.hash))
          count += 1;
      }

      assert.strictEqual(count, 2);
    }

    await chain.db.removeChains();

    {
      const tips = await chain.getTipEntries();

      let index = -1;

      for (let i = 0; i < tips.length; i++) {
        if (tips[i].hash.equals(chain.tip.hash))
          index = i;
      }

      assert.notStrictEqual(index, -1);
      assert.strictEqual(tips.length, 1);
    }
  });

  it('should rescan for transactions', async () => {
    let total = 0;

    await chain.scan(0, wallet.filter, async (block, txs) => {
      total += txs.length;
    });

    assert.strictEqual(total, 226);
  });

  it('should activate csv', async () => {
    const deployments = network.deployments;

    miner.options.version = -1;

    assert.strictEqual(chain.height, 214);

    const prev = await chain.getPrevious(chain.tip);
    const state = await chain.getState(prev, deployments.csv);
    assert.strictEqual(state, 1);

    for (let i = 0; i < 417; i++) {
      const block = await cpu.mineBlock();
      assert(await chain.add(block));
      switch (chain.height) {
        case 288: {
          const prev = await chain.getPrevious(chain.tip);
          const state = await chain.getState(prev, deployments.csv);
          assert.strictEqual(state, 1);
          break;
        }
        case 432: {
          const prev = await chain.getPrevious(chain.tip);
          const state = await chain.getState(prev, deployments.csv);
          assert.strictEqual(state, 2);
          break;
        }
        case 576: {
          const prev = await chain.getPrevious(chain.tip);
          const state = await chain.getState(prev, deployments.csv);
          assert.strictEqual(state, 3);
          break;
        }
      }
    }

    assert.strictEqual(chain.height, 631);
    assert(chain.state.hasCSV());
    assert(chain.state.hasWitness());

    const cache = await chain.db.getStateCache();
    assert.deepStrictEqual(cache, chain.db.stateCache);
    assert.strictEqual(chain.db.stateCache.updates.length, 0);
    assert(await chain.db.verifyDeployments());
  });

  it('should have activated segwit', async () => {
    const deployments = network.deployments;
    const prev = await chain.getPrevious(chain.tip);
    const state = await chain.getState(prev, deployments.segwit);
    assert.strictEqual(state, 3);
  });

  it('should test csv', async () => {
    const tx = (await chain.getBlock(chain.height - 100)).txs[0];
    const csvBlock = await mineCSV(tx);

    assert(await chain.add(csvBlock));

    const csv = csvBlock.txs[1];

    const spend = new MTX();

    spend.addOutput({
      script: [
        Opcode.fromInt(2),
        Opcode.fromSymbol('checksequenceverify')
      ],
      value: 10000
    });

    spend.addTX(csv, 0);
    spend.setSequence(0, 1, false);

    const job = await cpu.createJob();

    job.addTX(spend.toTX(), spend.view);
    job.refresh();

    const block = await job.mineAsync();

    assert(await chain.add(block));
  });

  it('should fail csv with bad sequence', async () => {
    const csv = (await chain.getBlock(chain.height - 100)).txs[0];
    const spend = new MTX();

    spend.addOutput({
      script: [
        Opcode.fromInt(1),
        Opcode.fromSymbol('checksequenceverify')
      ],
      value: 1 * 1e8
    });

    spend.addTX(csv, 0);
    spend.setSequence(0, 1, false);

    const job = await cpu.createJob();
    job.addTX(spend.toTX(), spend.view);
    job.refresh();

    assert.strictEqual(await mineBlock(job),
      'mandatory-script-verify-flag-failed');
  });

  it('should emit bad block with id and set invalid', async () => {
    let called = false;

    chain.once('bad block', (err, id) => {
      assert.equal(err.type, 'VerifyError');
      assert.equal(err.reason, 'bad-txns-inputs-missingorspent');
      assert.strictEqual(id, 0);
      called = true;
    });

    const spend = new MTX();
    spend.addInput({
      prevout: {
        hash: Buffer.alloc(32, 0x00),
        index: 0
      }
    });
    const addr = 'bcrt1qngw83fg8dz0k749cg7k3emc7v98wy0c7azaa6h';
    spend.addOutput(addr, 100000);

    const job = await cpu.createJob();
    job.addTX(spend.toTX(), spend.view);
    job.refresh();
    const block = await job.mineAsync();

    assert(!await chain.hasInvalid(block));

    try {
      await chain.add(block, common.flags.DEFAULT_FLAGS, 0);
    } catch (err) {
      assert(err);
    }

    assert(called);
    assert(!chain.ids.has(block.hash()));
    assert(await chain.hasInvalid(block));
  });

  it('should mine a block', async () => {
    const block = await cpu.mineBlock();
    assert(block);
    assert(await chain.add(block));
  });

  it('should fail csv lock checks', async () => {
    const tx = (await chain.getBlock(chain.height - 100)).txs[0];
    const csvBlock = await mineCSV(tx);

    assert(await chain.add(csvBlock));

    const csv = csvBlock.txs[1];

    const spend = new MTX();

    spend.addOutput({
      script: [
        Opcode.fromInt(2),
        Opcode.fromSymbol('checksequenceverify')
      ],
      value: 1 * 1e8
    });

    spend.addTX(csv, 0);
    spend.setSequence(0, 2, false);

    const job = await cpu.createJob();
    job.addTX(spend.toTX(), spend.view);
    job.refresh();

    assert.strictEqual(await mineBlock(job), 'bad-txns-nonfinal');
  });

  it('should have correct wallet balance', async () => {
    assert.strictEqual(wallet.balance, 1412499980000);
  });

  it('should fail to connect bad bits', async () => {
    const job = await cpu.createJob();
    job.attempt.bits = 553713663;
    assert.strictEqual(await mineBlock(job), 'bad-diffbits');
  });

  it('should fail to connect bad MTP', async () => {
    const mtp = await chain.getMedianTime(chain.tip);
    const job = await cpu.createJob();
    job.attempt.time = mtp - 1;
    assert.strictEqual(await mineBlock(job), 'time-too-old');
  });

  it('should fail to connect bad time', async () => {
    const job = await cpu.createJob();
    const now = network.now() + 3 * 60 * 60;
    job.attempt.time = now;
    assert.strictEqual(await mineBlock(job), 'time-too-new');
  });

  it('should fail to connect bad locktime', async () => {
    const job = await cpu.createJob();
    const tx = await wallet.send({ locktime: 100000 });
    job.pushTX(tx.toTX());
    job.refresh();
    assert.strictEqual(await mineBlock(job), 'bad-txns-nonfinal');
  });

  it('should fail to connect bad work', async () => {
    const job = await cpu.createJob();
    const block = await job.mineAsync();

    const target = BN.fromString(
      '7fffff0000000000000000000000000000000000000000000000000000000000',
      16, 'be');

    let num = new BN(block.hash(), 'le');

    while (num.lte(target)) {
      block.nonce += 1;
      block.refresh();
      num = new BN(block.hash(), 'le');
    }

    await assert.rejects(async () => {
      await chain.add(block);
    }, {
      type: 'VerifyError',
      reason: 'high-hash'
    });
  });

  it('should fail to connect bad prevblk', async () => {
    const job = await cpu.createJob();
    job.attempt.prevBlock = Buffer.alloc(32, 0xff);
    const block = await job.mineAsync();

    await assert.rejects(async () => {
      await chain.add(block);
    }, {
      type: 'VerifyError',
      reason: 'bad-prevblk'
    });
  });

  it('should fail to connect bad cb height', async () => {
    const bip34height = network.block.bip34height;
    const job = await cpu.createJob();

    job.attempt.height = 10;
    job.attempt.refresh();

    try {
      network.block.bip34height = 0;
      assert.strictEqual(await mineBlock(job), 'bad-cb-height');
    } finally {
      network.block.bip34height = bip34height;
    }
  });

  it('should fail to connect bad witness nonce size', async () => {
    const block = await cpu.mineBlock();
    const tx = block.txs[0];
    const input = tx.inputs[0];
    input.witness.set(0, Buffer.allocUnsafe(33));
    block.refresh(true);
    assert.strictEqual(await addBlock(block), 'bad-witness-nonce-size');
  });

  it('should fail to connect bad witness nonce', async () => {
    const block = await cpu.mineBlock();
    const tx = block.txs[0];
    const input = tx.inputs[0];
    input.witness.set(0, ONE_HASH);
    block.refresh(true);
    assert.strictEqual(await addBlock(block), 'bad-witness-merkle-match');
  });

  it('should fail to connect bad witness commitment', async () => {
    const flags = common.flags.DEFAULT_FLAGS & ~common.flags.VERIFY_POW;
    const block = await cpu.mineBlock();
    const tx = block.txs[0];
    const output = tx.outputs[1];

    assert(output.script.isCommitment());

    const commit = Buffer.from(output.script.getData(1));
    commit.fill(0, 10);
    output.script.setData(1, commit);
    output.script.compile();

    block.refresh(true);
    block.merkleRoot = block.createMerkleRoot();

    assert.strictEqual(await addBlock(block, flags),
      'bad-witness-merkle-match');
  });

  it('should fail to connect unexpected witness', async () => {
    const flags = common.flags.DEFAULT_FLAGS & ~common.flags.VERIFY_POW;
    const block = await cpu.mineBlock();
    const tx = block.txs[0];
    const output = tx.outputs[1];

    assert(output.script.isCommitment());

    tx.outputs.pop();

    block.refresh(true);
    block.merkleRoot = block.createMerkleRoot();

    assert.strictEqual(await addBlock(block, flags), 'unexpected-witness');
  });

  it('should add wit addrs to miner', async () => {
    miner.addresses.length = 0;
    miner.addAddress(witWallet.getReceive());
    assert.strictEqual(witWallet.getReceive().getType(), 'witness');
  });

  it('should mine 2000 witness blocks', async () => {
    for (let i = 0; i < 2001; i++) {
      const block = await cpu.mineBlock();
      assert(block);
      assert(await chain.add(block));
    }

    assert.strictEqual(chain.height, 2636);
  });

  it('should mine a witness tx', async () => {
    const prev = await chain.getBlock(chain.height - 2000);
    const cb = prev.txs[0];
    const mtx = new MTX();

    mtx.addTX(cb, 0);
    mtx.addOutput(witWallet.getAddress(), 1000);

    witWallet.sign(mtx);

    const job = await cpu.createJob();
    job.addTX(mtx.toTX(), mtx.view);
    job.refresh();

    const block = await job.mineAsync();

    assert(await chain.add(block));
  });

  if (process.browser)
    return;

  it('should mine fail to connect too much weight', async () => {
    const start = chain.height - 2000;
    const end = chain.height - 200;
    const job = await cpu.createJob();

    for (let i = start; i <= end; i++) {
      const block = await chain.getBlock(i);
      const cb = block.txs[0];

      const mtx = new MTX();
      mtx.addTX(cb, 0);

      for (let j = 0; j < 16; j++)
        mtx.addOutput(witWallet.getAddress(), 1);

      witWallet.sign(mtx);

      job.pushTX(mtx.toTX());
    }

    job.refresh();

    assert.strictEqual(await mineBlock(job), 'bad-blk-weight');
  });

  it('should mine fail to connect too much size', async () => {
    const start = chain.height - 2000;
    const end = chain.height - 200;
    const job = await cpu.createJob();

    for (let i = start; i <= end; i++) {
      const block = await chain.getBlock(i);
      const cb = block.txs[0];

      const mtx = new MTX();
      mtx.addTX(cb, 0);

      for (let j = 0; j < 20; j++)
        mtx.addOutput(witWallet.getAddress(), 1);

      witWallet.sign(mtx);

      job.pushTX(mtx.toTX());
    }

    job.refresh();

    assert.strictEqual(await mineBlock(job), 'bad-blk-length');
  });

  it('should mine a big block', async () => {
    const start = chain.height - 2000;
    const end = chain.height - 200;
    const job = await cpu.createJob();

    for (let i = start; i <= end; i++) {
      const block = await chain.getBlock(i);
      const cb = block.txs[0];

      const mtx = new MTX();
      mtx.addTX(cb, 0);

      for (let j = 0; j < 15; j++)
        mtx.addOutput(witWallet.getAddress(), 1);

      witWallet.sign(mtx);

      job.pushTX(mtx.toTX());
    }

    job.refresh();

    assert.strictEqual(await mineBlock(job), 'OK');
  });

  it('should fail to connect bad versions', async () => {
    for (let i = 0; i <= 3; i++) {
      const job = await cpu.createJob();
      job.attempt.version = i;
      assert.strictEqual(await mineBlock(job), 'bad-version');
    }
  });

  it('should fail to connect bad amount', async () => {
    const job = await cpu.createJob();

    job.attempt.fees += 1;
    job.refresh();
    assert.strictEqual(await mineBlock(job), 'bad-cb-amount');
  });

  it('should fail to connect premature cb spend', async () => {
    const job = await cpu.createJob();
    const block = await chain.getBlock(chain.height - 98);
    const cb = block.txs[0];
    const mtx = new MTX();

    mtx.addTX(cb, 0);
    mtx.addOutput(witWallet.getAddress(), 1);

    witWallet.sign(mtx);

    job.addTX(mtx.toTX(), mtx.view);
    job.refresh();

    assert.strictEqual(await mineBlock(job),
      'bad-txns-premature-spend-of-coinbase');
  });

  it('should fail to connect vout belowout', async () => {
    const job = await cpu.createJob();
    const block = await chain.getBlock(chain.height - 99);
    const cb = block.txs[0];
    const mtx = new MTX();

    mtx.addTX(cb, 0);
    mtx.addOutput(witWallet.getAddress(), 1e8);

    witWallet.sign(mtx);

    job.pushTX(mtx.toTX());
    job.refresh();

    assert.strictEqual(await mineBlock(job),
      'bad-txns-in-belowout');
  });

  it('should fail to connect outtotal toolarge', async () => {
    const job = await cpu.createJob();
    const block = await chain.getBlock(chain.height - 99);
    const cb = block.txs[0];
    const mtx = new MTX();

    mtx.addTX(cb, 0);

    const value = Math.floor(consensus.MAX_MONEY / 2);

    mtx.addOutput(witWallet.getAddress(), value);
    mtx.addOutput(witWallet.getAddress(), value);
    mtx.addOutput(witWallet.getAddress(), value);

    witWallet.sign(mtx);

    job.pushTX(mtx.toTX());
    job.refresh();

    assert.strictEqual(await mineBlock(job),
      'bad-txns-txouttotal-toolarge');
  });

  it('should fail to connect total fee toolarge', async () => {
    const job = await cpu.createJob();
    const outputs = [{ address: wallet.getAddress(), value: 0 }];

    Selector.MAX_FEE = 50 * consensus.COIN;
    const maxFee = Selector.MAX_FEE;
    const maxMoney = consensus.MAX_MONEY;

    try {
      const tx1 = await wallet.send({
        outputs: outputs,
        hardFee: Selector.MAX_FEE
      });
      job.pushTX(tx1.toTX());

      const tx2 = await wallet.send({
        outputs: outputs,
        hardFee: Selector.MAX_FEE
      });
      job.pushTX(tx2.toTX());

      consensus.MAX_MONEY = tx1.getFee() + tx2.getFee() - 1;

      job.refresh();
      assert.strictEqual(await mineBlock(job),
        'bad-txns-accumulated-fee-outofrange');
    } finally {
      Selector.MAX_FEE = maxFee;
      consensus.MAX_MONEY = maxMoney;
    }
  });

  it('should mine 111 multisig blocks', async () => {
    const flags = common.flags.DEFAULT_FLAGS & ~common.flags.VERIFY_POW;

    const redeem = new Script();
    redeem.pushInt(20);

    for (let i = 0; i < 20; i++)
      redeem.pushData(ZERO_KEY);

    redeem.pushInt(20);
    redeem.pushOp(opcodes.OP_CHECKMULTISIG);

    redeem.compile();

    const script = Script.fromScripthash(redeem.hash160());

    for (let i = 0; i < 111; i++) {
      const block = await cpu.mineBlock();
      const cb = block.txs[0];
      const val = cb.outputs[0].value;

      cb.outputs[0].value = 0;

      for (let j = 0; j < Math.min(100, val); j++) {
        const output = new Output();
        output.script = script.clone();
        output.value = 1;

        cb.outputs.push(output);
      }

      block.refresh(true);
      block.merkleRoot = block.createMerkleRoot();

      assert(await chain.add(block, flags));
    }

    assert.strictEqual(chain.height, 2749);
  });

  it('should fail to connect too many sigops', async () => {
    const start = chain.height - 110;
    const end = chain.height - 100;
    const job = await cpu.createJob();

    const script = new Script();

    script.pushInt(20);

    for (let i = 0; i < 20; i++)
      script.pushData(ZERO_KEY);

    script.pushInt(20);
    script.pushOp(opcodes.OP_CHECKMULTISIG);

    script.compile();

    for (let i = start; i <= end; i++) {
      const block = await chain.getBlock(i);
      const cb = block.txs[0];

      if (cb.outputs.length === 2)
        continue;

      const mtx = new MTX();

      for (let j = 2; j < cb.outputs.length; j++) {
        mtx.addTX(cb, j);
        mtx.inputs[j - 2].script.fromItems([script.toRaw()]);
      }

      mtx.addOutput(witWallet.getAddress(), 1);

      job.pushTX(mtx.toTX());
    }

    job.refresh();

    assert.strictEqual(await mineBlock(job), 'bad-blk-sigops');
  });

  it('should inspect ChainEntry', async () => {
    const fmt = nodejsUtil.format(tip1);
    assert(typeof fmt === 'string');
    assert(fmt.includes('hash'));
    assert(fmt.includes('version'));
    assert(fmt.includes('chainwork'));
  });

  describe('Pruning', function() {
    const network = Network.get('regtest');
    let blocks, chain, miner, cpu = null;

    beforeEach(async () => {
      blocks = new BlockStore({memory: true, network});
      chain = new Chain({network, blocks, maxTips: 10});
      miner = new Miner({chain});
      cpu = miner.cpu;

      await blocks.open();
      await chain.open();
      await miner.open();
    });

    afterEach(async () => {
      await miner.close();
      await chain.close();
      await blocks.close();
    });

    it('will limit and prune number of tips', async () => {
      const genesis = await chain.getEntry(network.genesis.hash);
      let tip = genesis;
      let forks = 0;

      // Create the baseline number of forks.
      while (forks < 10) {
        for (let i = 0; i < 100; i++) {
          const block = await cpu.mineBlock(tip);
          const {entry} = await chain.addHeader(block.toHeaders());

          tip = entry;
        }

        forks += 1;
        tip = genesis;
      }

      let tips = await chain.getTipEntries();
      assert.equal(tips.length, 10);

      // Add additional forks that will be pruned.
      while (forks < 20) {
        for (let i = 0; i < 95; i++) {
          const block = await cpu.mineBlock(tip);
          const {entry} = await chain.addHeader(block.toHeaders());

          tip = entry;
        }

        forks += 1;
        tip = genesis;
      }

      let fork = genesis;

      // Create forks that branch off another fork
      // and should be pruned.
      while (forks < 30) {
        for (let i = 0; i < 10; i++) {
          const block = await cpu.mineBlock(tip);
          const {entry} = await chain.addHeader(block.toHeaders());

          tip = entry;

          if (forks === 20 && i === 5)
            fork = entry;
        }

        forks += 1;
        tip = fork;
      }

      tips = await chain.getTipEntries();
      assert.equal(tips.length, 30);

      await chain.pruneTips();

      tips = await chain.getTipEntries();
      assert.equal(tips.length, 10);
    });
  });

  describe('SPV', function() {
    let network, blocks, miner, cpu = null;
    let chain, spvchain = null;

    function toMerkle(block) {
      return block.toMerkle(new BloomFilter());
    }

    async function mineCompeting(depth) {
      let tip1, tip2 = null;

      for (let i = 0; i < depth; i++) {
        const job1 = await cpu.createJob(tip1);
        const job2 = await cpu.createJob(tip2);

        const blk1 = await job1.mineAsync();
        const blk2 = await job2.mineAsync();

        const hash1 = blk1.hash();
        const hash2 = blk2.hash();

        assert(await chain.add(blk1));
        assert(await chain.add(blk2));

        assert(await spvchain.add(toMerkle(blk1)));
        assert(await spvchain.add(toMerkle(blk2)));

        assert.bufferEqual(chain.tip.hash, hash1);
        assert.bufferEqual(spvchain.tip.hash, hash1);

        tip1 = await chain.getEntry(hash1);
        tip2 = await chain.getEntry(hash2);

        assert(tip1);
        assert(tip2);

        assert(!await chain.isMainChain(tip2));
        assert(!await spvchain.isMainChain(tip2));
      }

      return [tip1, tip2];
    }

    beforeEach(async () => {
      network = Network.get('regtest');
      blocks = new BlockStore({memory: true, network});
      chain = new Chain({memory: true, blocks, network});
      miner = new Miner({chain, version: 4});
      cpu = miner.cpu;

      spvchain = new Chain({
        memory: true,
        blocks,
        network,
        spv: true,
        maxTips: 10
      });

      await blocks.open();
      await chain.open();
      await spvchain.open();
      await miner.open();
    });

    afterEach(async () => {
      await miner.close();
      await chain.close();
      await spvchain.close();
      await blocks.close();
    });

    it('should add blocks and headers', async () => {
      for (let i = 0; i < 200; i++) {
        const block = await cpu.mineBlock();
        assert(block);
        assert(await chain.add(block));
        assert(await spvchain.add(toMerkle(block)));
      }

      assert.strictEqual(chain.height, 200);
      assert.strictEqual(spvchain.height, 200);
    });

    it('should add competing chains', async () => {
      const [tip1, tip2] = await mineCompeting(10);
      assert.equal(tip1.height, 10);
      assert.equal(tip2.height, 10);
    });

    it('should handle a reorg', async () => {
      const [tip1, tip2] = await mineCompeting(3);
      assert.equal(chain.height, 3);
      assert.equal(spvchain.height, 3);

      const entry = await chain.getEntry(tip2.hash);
      assert(entry);
      assert.strictEqual(chain.height, entry.height);

      const block = await cpu.mineBlock(entry);
      assert(block);

      let forked = false;
      spvchain.once('reorganize', () => {
        forked = true;
      });

      assert(await spvchain.add(toMerkle(block)));

      assert(forked);
      assert.bufferEqual(spvchain.tip.hash, block.hash());
      assert(spvchain.tip.chainwork.gt(tip1.chainwork));
    });

    it('should check mainchain', async () => {
      const [tip1, tip2] = await mineCompeting(1);
      assert(await chain.isMainChain(tip1));
      assert(!await chain.isMainChain(tip2));
    });

    it('should fail to connect bad bits', async () => {
      const job = await cpu.createJob();
      job.attempt.bits = 553713663;
      const block = await job.mineAsync();

      await assert.rejects(async () => {
        await spvchain.add(toMerkle(block));
      }, {
        type: 'VerifyError',
        reason: 'bad-diffbits'
      });
    });

    it('should fail to connect bad work', async () => {
      const job = await cpu.createJob();
      const block = await job.mineAsync();

      const target = BN.fromString(
        '7fffff0000000000000000000000000000000000000000000000000000000000',
        16, 'be');

      let num = new BN(block.hash(), 'le');

      while (num.lte(target)) {
        block.nonce += 1;
        block.refresh();
        num = new BN(block.hash(), 'le');
      }

      await assert.rejects(async () => {
        await spvchain.add(toMerkle(block));
      }, {
        type: 'VerifyError',
        reason: 'high-hash'
      });
    });

    it('should fail to connect bad mtp', async () => {
      const mtp = await chain.getMedianTime(chain.tip);
      const job = await cpu.createJob();
      job.attempt.time = mtp - 1;
      const block = await job.mineAsync();

      await assert.rejects(async () => {
        await spvchain.add(toMerkle(block));
      }, {
        type: 'VerifyError',
        reason: 'time-too-old'
      });
    });

    it('should fail to connect bad versions', async () => {
      for (let i = 0; i < 1351; i++) {
        const block = await cpu.mineBlock();
        assert(block);
        assert(await chain.add(block));
        assert(await spvchain.add(toMerkle(block)));
      }

      assert.strictEqual(chain.height, 1351);

      for (let i = 0; i <= 3; i++) {
        const job = await cpu.createJob();
        job.attempt.version = i;
        const block = await job.mineAsync();

        await assert.rejects(async () => {
          await spvchain.add(toMerkle(block));
        }, {
          type: 'VerifyError',
          reason: 'bad-version'
        });
      }
    });

    it('should get tips and remove chains', async () => {
      const [tip1, tip2] = await mineCompeting(5);
      assert.equal(tip1.height, 5);
      assert.equal(tip2.height, 5);

      async function checkTips(tips, count) {
        let index = -1;
        for (let i = 0; i < tips.length; i++) {
          if (tips[i].hash.equals(spvchain.tip.hash))
            index = i;
        }

        assert.notStrictEqual(index, -1);
        assert.strictEqual(tips.length, count);

        for (const entry of tips)
          assert(!await spvchain.db.hasInvalid(entry.hash));
      }

      const tips = await chain.db.getTipEntries();
      await checkTips(tips, 2);

      await chain.db.removeChains();

      const tips2 = await chain.db.getTipEntries();
      await checkTips(tips2, 1);
    });

    it('will limit and prune number of tips', async () => {
      const genesis = await chain.getEntry(network.genesis.hash);
      let tip = genesis;
      let forks = 0;

      while (forks < 10) {
        for (let i = 0; i < 100; i++) {
          const block = await cpu.mineBlock(tip);
          const header = block.toHeaders();
          const {entry} = await chain.addHeader(header);
          await spvchain.addHeader(header);

          tip = entry;
        }

        forks += 1;
        tip = genesis;
      }

      let tips = await spvchain.getTipEntries();
      assert.equal(tips.length, 10);

      while (forks < 20) {
        for (let i = 0; i < 95; i++) {
          const block = await cpu.mineBlock(tip);
          const header = block.toHeaders();
          const {entry} = await chain.addHeader(header);
          await spvchain.addHeader(header);

          tip = entry;
        }

        forks += 1;
        tip = genesis;
      }

      tips = await spvchain.getTipEntries();
      assert.equal(tips.length, 20);

      await spvchain.pruneTips();

      tips = await spvchain.getTipEntries();
      assert.equal(tips.length, 10);
    });
  });

  describe('Locator/Ancestor', function() {
    let blocks, chain, miner, cpu = null;

    const expected = [
      1000, 999, 998, 997, 996, 995, 994, 993, 992, 991, 990, 989,
      987, 983, 975, 959, 927, 863, 735, 479, 0
    ];

    const mined = [];

    async function check(locator) {
      assert.equal(locator.length, 21);

      let count = 0;

      for (const hash of locator) {
        const entry = await chain.getEntry(hash);
        assert.equal(entry.height, expected[count]);
        count += 1;
      }
    }

    before(async () => {
      blocks = new BlockStore({memory: true, network});
      chain = new Chain({memory: true, blocks, network});
      miner = new Miner({chain, version: 4});
      cpu = miner.cpu;
      await blocks.open();
      await chain.open();
      await miner.open();

      for (let i = 0; i < 1000; i++) {
        const block = await cpu.mineBlock();
        assert(block);
        assert(await chain.add(block));
        mined.push(block);
      }

      assert.strictEqual(chain.height, 1000);
    });

    after(async () => {
      await miner.close();
      await chain.close();
      await blocks.close();
    });

    it('should get correct hop count', () => {
      let height = 262144 - 1;
      let count = 0;

      while (height) {
        height = ChainDB.getSkipHeight(height);
        count += 1;
      }

      assert.equal(count, 10);
    });

    it('should get locator on main chain', async () => {
      const locator = await chain.getLocator();
      await check(locator);
    });

    it('should get locator on non-main chain', async () => {
      const chain = new Chain({memory: true, blocks, network});
      await chain.open();

      try {
        for (const block of mined)
          await chain.addHeader(block.toHeaders());

        const best = chain.mostWork();
        const locator = await chain.getLocator(best.hash);
        await check(locator);
      } finally {
        await chain.close();
      }
    });

    it('should get next path entries', async () => {
      let entries = null;
      const tip = chain.tip;
      assert.equal(tip.height, 1000);

      entries = await chain.db.getNextPath(tip, 100, 10);
      assert.equal(entries.length, 10);

      for (let i = 0; i < 10; i++)
        assert.equal(entries[i].height, 101 + i);

      entries = await chain.db.getNextPath(tip, 995, 10);
      assert.equal(entries.length, 5);

      for (let i = 0; i < 5; i++)
        assert.equal(entries[i].height, 996 + i);

      entries = await chain.db.getNextPath(tip, 1010, 10);
      assert.equal(entries.length, 0);

      entries = await chain.db.getNextPath(tip, -1, 10);
      assert.equal(entries.length, 0);

      entries = await chain.db.getNextPath(tip, 0, -10);
      assert.equal(entries.length, 0);
    });
  });

  describe('Best/Forks', function() {
    /**
     * Legend: Uppercase indicates header and block
     * data, and lowercase indicates only the header.
     */

    const addr = 'bcrt1qngw83fg8dz0k749cg7k3emc7v98wy0c7azaa6h';
    let blocks, chain, miner, cpu, mined, genesis = null;

    beforeEach(async () => {
      mined = {};
      blocks = new BlockStore({memory: true, network});
      chain = new Chain({memory: true, blocks, network});
      miner = new Miner({chain, version: 4});
      cpu = miner.cpu;
      await blocks.open();
      await chain.open();
      await miner.open();
      genesis = chain.tip;
    });

    afterEach(async () => {
      await blocks.close();
      await chain.close();
      await miner.close();
    });

    async function addHeaders(tip, key, number, invalid) {
      for (let i = 0; i < number; i++) {
        let block = null;
        if (i === invalid) {
          const mtx = new MTX();
          mtx.addInput({
            prevout: {
              hash: Buffer.alloc(32, 0x00),
              index: 0
            }
          });
          mtx.addOutput(addr, 100000);

          const job = await cpu.createJob(tip);
          job.addTX(mtx.toTX(), mtx.view);
          job.refresh();
          block = await job.mineAsync();
        } else {
          block = await cpu.mineBlock(tip);
        }
        assert(block);
        assert(await chain.addHeader(block.toHeaders()));

        if (!mined[key])
          mined[key] = [];

        mined[key].push(block);

        tip = ChainEntry.fromBlock(block, tip);
      }
    }

    async function addBlocks(key, start, end, skip) {
      for (let i = start; i < end; i++) {
        if (i !== skip)
          await chain.add(mined[key][i]);
      }
    }

    it('should find last common ancestor', async () => {
      /**
       * Given these chains:
       *
       *     u-v-w-x-y-z
       *    /
       *     l-m-n-o-p-q-r-s-t
       *    /
       * a-b-c-d-e-f-g-h-i-j-k
       *
       * The common ancestor would be b.
       */

      let entry = null;

      // Add headers a-k
      await addHeaders(genesis, 'b-k', 10);

      // Add headers l-t and u-z.
      const b = await chain.getEntry(mined['b-k'][0].hash());
      await addHeaders(b, 'l-t', 9);
      await addHeaders(b, 'u-z', 6);

      const t = await chain.getEntry(mined['l-t'][8].hash());
      const z = await chain.getEntry(mined['u-z'][5].hash());

      entry = await chain.commonAncestor(t, z);
      assert.bufferEqual(entry.hash, b.hash);

      entry = await chain.commonAncestor(z, t);
      assert.bufferEqual(entry.hash, b.hash);

      const unlinked = new ChainEntry();
      entry = await chain.commonAncestor(t, unlinked);
      assert.equal(entry, null);
      entry = await chain.commonAncestor(unlinked, z);
      assert.equal(entry, null);
    });

    it('will select best w/ mid missing', async () => {
      /**
       * Given these chains:
       *
       *   X-Y-z
       *  /
       *   P-Q-R-s-T-U-V-W
       *  /
       * A-B-C-d-E-F-G-H-I-J-K
       *  \
       *   L-M-n-o
       *
       * The best chain would be:
       *
       * A-P-Q-R
       */

      await addHeaders(genesis, 'b-k', 10);
      await addHeaders(genesis, 'l-o', 4);
      await addHeaders(genesis, 'p-w', 8);
      await addHeaders(genesis, 'x-z', 3);

      // Add blocks B to K except D.
      await addBlocks('b-k', 0, 10, 2);

      // Add blocks L and M (not N and O).
      await addBlocks('l-o', 0, 2);

      // Add blocks P to W except S.
      await addBlocks('p-w', 0, 8, 3);

      // Add blocks X and Y (not Z).
      await addBlocks('x-z', 0, 2);

      const R = mined['p-w'][2].hash();

      assert(chain.tip.hash.equals(R));
    });

    it('will select best w/ tail missing', async () => {
      /** Given these chains:
       *
       *   L-M-N-O-P-Q-R-s
       *  /
       * A-B-C-D-E-F-G
       *  \
       *   H-I-J-K
       *
       * The best chain would be:
       *
       * A-L-M-N-O-P-Q-R
       */

      await addHeaders(genesis, 'b-g', 6);
      await addHeaders(genesis, 'h-k', 4);
      await addHeaders(genesis, 'l-s', 8);

      // Add blocks B to G.
      await addBlocks('b-g', 0, 6);

      // Blocks H to K are not added, as not there
      // isn't enough chainwork.

      // Add blocks L to R (not S).
      await addBlocks('l-s', 0, 7);

      const R = mined['l-s'][6].hash();
      assert(chain.tip.hash.equals(R));
    });

    it('will connect with multiple tails', async () => {
      /** Given these chains:
       *
       *             P-Q-R
       *            /
       *             N-O
       *            /
       *     J-k-L-M
       *    /
       * A-B-C-D-E
       *      \
       *       f-g-h-i
       *
       * The best chain would intially be:
       *
       * A-B-C-D-E
       *
       * And when K is added, the best would be:
       *
       * A-B-J-K-L-M-P-Q-R
       *
       */

      // Add headers and blocks b-e.
      await addHeaders(genesis, 'b-e', 4);
      await addBlocks('b-e', 0, 4);

      // Chain tip should initially be E.
      const E = mined['b-e'][3].hash();
      assert(chain.tip.hash.equals(E));

      // Add headers f-i.
      const c = await chain.getEntry(mined['b-e'][1].hash());
      await addHeaders(c, 'f-i', 4);

      // Add headers j-m.
      const b = await chain.getEntry(mined['b-e'][0].hash());
      await addHeaders(b, 'j-m', 4);

      // Add headers n-o and p-r.
      const m = await chain.getEntry(mined['j-m'][3].hash());
      await addHeaders(m, 'n-o', 2);
      await addHeaders(m, 'p-r', 3);

      // Add blocks J to M (except K).
      await addBlocks('j-m', 0, 4, 1);

      // Add blocks N to O and P to R.
      await addBlocks('n-o', 0, 2);
      await addBlocks('p-r', 0, 3);

      // Chain tip should remain unchanged.
      assert(chain.tip.hash.equals(E));

      // Add final block K (from j-m).
      await chain.add(mined['j-m'][1]);

      // Chain tip should now be R.
      const R = mined['p-r'][2].hash();
      assert(chain.tip.hash.equals(R));
    });

    it('will retry after connect failure', async () => {
      /** Given these chains:
       *
       *             P-Q-R
       *            /
       *             N-O
       *            /
       *     J-k-L-M
       *    /
       * A-B-C-D-E
       *
       * The best chain would intially be:
       *
       * A-B-C-D-E
       *
       * When P has invalid coin spend and K is added,
       * the best would be:
       *
       * A-B-J-K-L-M-N-O
       *
       */

      // Add headers and blocks b-e.
      await addHeaders(genesis, 'b-e', 4);
      await addBlocks('b-e', 0, 4);

      // Chain tip should initially be E.
      const E = mined['b-e'][3].hash();
      assert(chain.tip.hash.equals(E));

      // Add headers j-m.
      const b = await chain.getEntry(mined['b-e'][0].hash());
      await addHeaders(b, 'j-m', 4);

      // Add headers n-o and p-r (invalid p).
      const m = await chain.getEntry(mined['j-m'][3].hash());
      await addHeaders(m, 'n-o', 2);
      await addHeaders(m, 'p-r', 3, 0);

      // Add blocks J to M (except K).
      await addBlocks('j-m', 0, 4, 1);

      // Add blocks N to O and P to R.
      await addBlocks('n-o', 0, 2);
      await addBlocks('p-r', 0, 3);

      // Chain tip should remain unchanged.
      assert(chain.tip.hash.equals(E));

      // Check that P will fail.
      let called = false;
      chain.once('bad block', (err) => {
        const P = mined['p-r'][0].hash();
        assert(err.hash.equals(P));
        called = true;
      });

      // Add final block K (from j-m).
      await chain.add(mined['j-m'][1]);

      // Chain tip should now be O and P should have failed.
      const O = mined['n-o'][1].hash();
      assert(chain.tip.hash.equals(O));
      assert(called);
    });

    it('will return to best chain on failure', async () => {
      /** Given these chains:
       *
       *     F-G-H-I
       *    /
       * A-B-C-D-E
       *
       * The chain will initially start at A-B-C-D-E, and when
       * F-G-H is added, it will return back to A-B-C-D-E when there is
       * a verification error with H.
       *
       */

      // Add headers and blocks b-e.
      await addHeaders(genesis, 'b-e', 4);
      await addBlocks('b-e', 0, 4);

      // Chain tip should initially be E.
      const E = mined['b-e'][3].hash();
      assert(chain.tip.hash.equals(E));

      // Add headers f-i (invalid h)
      const b = await chain.getEntry(mined['b-e'][0].hash());
      await addHeaders(b, 'f-i', 4, 2);

      // Check that H will fail.
      let called = false;
      chain.once('bad block', (err) => {
        const H = mined['f-i'][2].hash();
        assert(err.hash.equals(H));
        called = true;
      });

      // Add blocks F-I (invalid H)
      await addBlocks('f-i', 0, 4);

      // Chain tip should still be E, and H should have failed.
      assert(chain.tip.hash.equals(E));
      assert(called);
    });

    it('will restore chain tip if no other linked chains', async () => {
      /** Given these chains:
       *
       *               m-n
       *              /
       * A-B-C-D-E-F-G-h-i
       *            \
       *             j-k-l
       *
       * It will remove alternatives to:
       *
       * A-B-C-D-E-F-G
       */

      let best = null;

      // Add headers b-i.
      await addHeaders(genesis, 'b-i', 8);

      // Add headers j-l
      const f = await chain.getEntry(mined['b-i'][4].hash());
      await addHeaders(f, 'j-l', 3);

      // Add headers m-n
      const g = await chain.getEntry(mined['b-i'][5].hash());
      await addHeaders(g, 'm-n', 2);

      // Add blocks B-G
      await addBlocks('b-i', 0, 6);

      // Verify chain is as expected.
      best = chain.mostWork();
      assert.equal(best.height, 8);
      assert.equal(chain.tip.height, 6);

      // Will remove alternative chains.
      await chain.db.removeChains();

      // The most work entry should still exist.
      best = chain.mostWork();
      assert.equal(best.height, 6);
      assert.equal(chain.tip.height, 6);

      // There should be the correct number of tips.
      const tips = await chain.getTipEntries();
      assert.equal(tips.length, 1);
      assert.deepEqual(tips[0], best);
    });

    it('will keep in-memory most work entry', async () => {
      /** Given these chains:
       *
       *   m-n-o
       *  /
       *   h-i-j
       *  /
       * a-b-c-d
       *  \
       *   e-f-g
       *  \
       *   j-k-l
       */

      async function checkConsistency() {
        const best = chain.mostWork();
        assert.equal(best.height, 3);
        await chain.db.setMostWork();
        const best2 = chain.mostWork();
        assert.bufferEqual(best.hash, best2.hash);
      }

      // Check genesis block.
      assert.equal(chain.mostWork().height, 0);
      assert.bufferEqual(chain.mostWork().hash, network.genesis.hash);

      // Add headers b-d.
      await addHeaders(genesis, 'b-d', 3);
      const d = await chain.getEntry(mined['b-d'][2].hash());
      const best = chain.mostWork();
      assert.bufferEqual(best.hash, d.hash);
      await checkConsistency();

      // Add headers e-g.
      await addHeaders(genesis, 'e-g', 3);
      await checkConsistency();

      // Add headers h-j.
      await addHeaders(genesis, 'h-j', 3);
      await checkConsistency();

      // Add headers j-l.
      await addHeaders(genesis, 'j-l', 3);
      await checkConsistency();

      // Add headers m-o.
      await addHeaders(genesis, 'm-o', 3);
      await checkConsistency();

      // And check update on reset.
      await chain.reset(0);
      assert.equal(chain.mostWork().height, 0);
    });
  });
});
