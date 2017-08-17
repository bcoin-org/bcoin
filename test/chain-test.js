/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const ScriptNum = require('../lib/script/scriptnum');
const consensus = require('../lib/protocol/consensus');
const encoding = require('../lib/utils/encoding');
const Coin = require('../lib/primitives/coin');
const Script = require('../lib/script/script');
const Chain = require('../lib/blockchain/chain');
const WorkerPool = require('../lib/workers/workerpool');
const Miner = require('../lib/mining/miner');
const MTX = require('../lib/primitives/mtx');
const MemWallet = require('./util/memwallet');
const Network = require('../lib/protocol/network');
const Output = require('../lib/primitives/output');
const common = require('../lib/blockchain/common');
const opcodes = Script.opcodes;

const network = Network.get('regtest');

const workers = new WorkerPool({
  enabled: true
});

const chain = new Chain({
  db: 'memory',
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
      ScriptNum.encode(1),
      Script.opcodes.OP_CHECKSEQUENCEVERIFY
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
  this.timeout(45000);

  it('should open chain and miner', async () => {
    await chain.open();
    await miner.open();
  });

  it('should add addrs to miner', async () => {
    miner.addresses.length = 0;
    miner.addAddress(wallet.getReceive());
  });

  it('should mine 200 blocks', async () => {
    for (let i = 0; i < 200; i++) {
      const block = await cpu.mineBlock();
      assert(block);
      assert(await chain.add(block));
    }

    assert.strictEqual(chain.height, 200);
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

      const hash1 = blk1.hash('hex');
      const hash2 = blk2.hash('hex');

      assert(await chain.add(blk1));
      assert(await chain.add(blk2));

      assert.strictEqual(chain.tip.hash, hash1);

      tip1 = await chain.db.getEntry(hash1);
      tip2 = await chain.db.getEntry(hash2);

      assert(tip1);
      assert(tip2);

      assert(!await tip2.isMainChain());
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

    const entry = await chain.db.getEntry(tip2.hash);
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
    assert.strictEqual(chain.tip.hash, block.hash('hex'));
    assert(chain.tip.chainwork.cmp(tip1.chainwork) > 0);
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
    const result = await tip1.isMainChain();
    assert(!result);
  });

  it('should mine a block after a reorg', async () => {
    const block = await cpu.mineBlock();

    assert(await chain.add(block));

    const hash = block.hash('hex');
    const entry = await chain.db.getEntry(hash);

    assert(entry);
    assert.strictEqual(chain.tip.hash, entry.hash);

    const result = await entry.isMainChain();
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
    const block = await chain.db.getBlock(tip1.hash);
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

    const coin = await chain.db.getCoin(tx.hash('hex'), 2);

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
      const tips = await chain.db.getTips();

      assert.notStrictEqual(tips.indexOf(chain.tip.hash), -1);
      assert.strictEqual(tips.length, 2);
    }

    await chain.db.removeChains();

    {
      const tips = await chain.db.getTips();

      assert.notStrictEqual(tips.indexOf(chain.tip.hash), -1);
      assert.strictEqual(tips.length, 1);
    }
  });

  it('should rescan for transactions', async () => {
    let total = 0;

    await chain.db.scan(0, wallet.filter, async (block, txs) => {
      total += txs.length;
    });

    assert.strictEqual(total, 226);
  });

  it('should activate csv', async () => {
    const deployments = network.deployments;

    miner.options.version = -1;

    assert.strictEqual(chain.height, 214);

    const prev = await chain.tip.getPrevious();
    const state = await chain.getState(prev, deployments.csv);
    assert.strictEqual(state, 1);

    for (let i = 0; i < 417; i++) {
      const block = await cpu.mineBlock();
      assert(await chain.add(block));
      switch (chain.height) {
        case 288: {
          const prev = await chain.tip.getPrevious();
          const state = await chain.getState(prev, deployments.csv);
          assert.strictEqual(state, 1);
          break;
        }
        case 432: {
          const prev = await chain.tip.getPrevious();
          const state = await chain.getState(prev, deployments.csv);
          assert.strictEqual(state, 2);
          break;
        }
        case 576: {
          const prev = await chain.tip.getPrevious();
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
    const prev = await chain.tip.getPrevious();
    const state = await chain.getState(prev, deployments.segwit);
    assert.strictEqual(state, 3);
  });

  it('should test csv', async () => {
    const tx = (await chain.db.getBlock(chain.height - 100)).txs[0];
    const csvBlock = await mineCSV(tx);

    assert(await chain.add(csvBlock));

    const csv = csvBlock.txs[1];

    const spend = new MTX();

    spend.addOutput({
      script: [
        ScriptNum.encode(2),
        Script.opcodes.OP_CHECKSEQUENCEVERIFY
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
    const csv = (await chain.db.getBlock(chain.height - 100)).txs[0];
    const spend = new MTX();

    spend.addOutput({
      script: [
        ScriptNum.encode(1),
        Script.opcodes.OP_CHECKSEQUENCEVERIFY
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

  it('should mine a block', async () => {
    const block = await cpu.mineBlock();
    assert(block);
    assert(await chain.add(block));
  });

  it('should fail csv lock checks', async () => {
    const tx = (await chain.db.getBlock(chain.height - 100)).txs[0];
    const csvBlock = await mineCSV(tx);

    assert(await chain.add(csvBlock));

    const csv = csvBlock.txs[1];

    const spend = new MTX();

    spend.addOutput({
      script: [
        ScriptNum.encode(2),
        Script.opcodes.OP_CHECKSEQUENCEVERIFY
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
    const mtp = await chain.tip.getMedianTime();
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
    input.witness.compile();
    block.refresh(true);
    assert.strictEqual(await addBlock(block), 'bad-witness-nonce-size');
  });

  it('should fail to connect bad witness nonce', async () => {
    const block = await cpu.mineBlock();
    const tx = block.txs[0];
    const input = tx.inputs[0];
    input.witness.set(0, encoding.ONE_HASH);
    input.witness.compile();
    block.refresh(true);
    assert.strictEqual(await addBlock(block), 'bad-witness-merkle-match');
  });

  it('should fail to connect bad witness commitment', async () => {
    const flags = common.flags.DEFAULT_FLAGS & ~common.flags.VERIFY_POW;
    const block = await cpu.mineBlock();
    const tx = block.txs[0];
    const output = tx.outputs[1];

    assert(output.script.isCommitment());

    const commit = Buffer.from(output.script.get(1));
    commit.fill(0, 10);
    output.script.set(1, commit);
    output.script.compile();

    block.refresh(true);
    block.merkleRoot = block.createMerkleRoot('hex');

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
    block.merkleRoot = block.createMerkleRoot('hex');

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
    const prev = await chain.db.getBlock(chain.height - 2000);
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

  it('should mine fail to connect too much weight', async () => {
    const start = chain.height - 2000;
    const end = chain.height - 200;
    const job = await cpu.createJob();

    for (let i = start; i <= end; i++) {
      const block = await chain.db.getBlock(i);
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
      const block = await chain.db.getBlock(i);
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
      const block = await chain.db.getBlock(i);
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
    const block = await chain.db.getBlock(chain.height - 98);
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
    const block = await chain.db.getBlock(chain.height - 99);
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
    const block = await chain.db.getBlock(chain.height - 99);
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

  it('should mine 111 multisig blocks', async () => {
    const flags = common.flags.DEFAULT_FLAGS & ~common.flags.VERIFY_POW;

    const redeem = new Script();
    redeem.push(new ScriptNum(20));

    for (let i = 0; i < 20; i++)
      redeem.push(encoding.ZERO_KEY);

    redeem.push(new ScriptNum(20));
    redeem.push(opcodes.OP_CHECKMULTISIG);
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
      block.merkleRoot = block.createMerkleRoot('hex');

      assert(await chain.add(block, flags));
    }

    assert.strictEqual(chain.height, 2749);
  });

  it('should fail to connect too many sigops', async () => {
    const start = chain.height - 110;
    const end = chain.height - 100;
    const job = await cpu.createJob();

    const script = new Script();
    script.push(new ScriptNum(20));

    for (let i = 0; i < 20; i++)
      script.push(encoding.ZERO_KEY);

    script.push(new ScriptNum(20));
    script.push(opcodes.OP_CHECKMULTISIG);
    script.compile();

    for (let i = start; i <= end; i++) {
      const block = await chain.db.getBlock(i);
      const cb = block.txs[0];

      if (cb.outputs.length === 2)
        continue;

      const mtx = new MTX();

      for (let j = 2; j < cb.outputs.length; j++) {
        mtx.addTX(cb, j);
        mtx.inputs[j - 2].script = new Script([script.toRaw()]);
      }

      mtx.addOutput(witWallet.getAddress(), 1);

      job.pushTX(mtx.toTX());
    }

    job.refresh();

    assert.strictEqual(await mineBlock(job), 'bad-blk-sigops');
  });

  it('should cleanup', async () => {
    await miner.close();
    await chain.close();
  });
});
