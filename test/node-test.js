/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const ScriptNum = require('../lib/script/scriptnum');
const consensus = require('../lib/protocol/consensus');
const co = require('../lib/utils/co');
const Coin = require('../lib/primitives/coin');
const Script = require('../lib/script/script');
const FullNode = require('../lib/node/fullnode');
const MTX = require('../lib/primitives/mtx');
const TX = require('../lib/primitives/tx');
const Address = require('../lib/primitives/address');

const node = new FullNode({
  db: 'memory',
  apiKey: 'foo',
  network: 'regtest',
  workers: true,
  plugins: [require('../lib/wallet/plugin')]
});

const chain = node.chain;
const miner = node.miner;
const wdb = node.require('walletdb');

let wallet = null;
let tip1 = null;
let tip2 = null;
let cb1 = null;
let cb2 = null;
let tx1 = null;
let tx2 = null;

async function mineBlock(tip, tx) {
  const job = await miner.createJob(tip);

  if (!tx)
    return await job.mineAsync();

  const spend = new MTX();

  spend.addTX(tx, 0);

  spend.addOutput(wallet.getReceive(), 25 * 1e8);
  spend.addOutput(wallet.getChange(), 5 * 1e8);

  spend.setLocktime(chain.height);

  await wallet.sign(spend);

  job.addTX(spend.toTX(), spend.view);
  job.refresh();

  return await job.mineAsync();
}

async function mineCSV(fund) {
  const job = await miner.createJob();
  const spend = new MTX();

  spend.addOutput({
    script: [
      ScriptNum.encode(1),
      Script.opcodes.OP_CHECKSEQUENCEVERIFY
    ],
    value: 10 * 1e8
  });

  spend.addTX(fund, 0);
  spend.setLocktime(chain.height);

  await wallet.sign(spend);

  const [tx, view] = spend.commit();

  job.addTX(tx, view);
  job.refresh();

  return await job.mineAsync();
}

describe('Node', function() {
  this.timeout(5000);

  it('should open chain and miner', async () => {
    miner.mempool = null;
    consensus.COINBASE_MATURITY = 0;
    await node.open();
  });

  it('should open walletdb', async () => {
    wallet = await wdb.create();
    miner.addresses.length = 0;
    miner.addAddress(wallet.getReceive());
  });

  it('should mine a block', async () => {
    const block = await miner.mineBlock();
    assert(block);
    await chain.add(block);
  });

  it('should mine competing chains', async () => {
    for (let i = 0; i < 10; i++) {
      const block1 = await mineBlock(tip1, cb1);
      cb1 = block1.txs[0];

      const block2 = await mineBlock(tip2, cb2);
      cb2 = block2.txs[0];

      await chain.add(block1);

      await chain.add(block2);

      assert.strictEqual(chain.tip.hash, block1.hash('hex'));

      tip1 = await chain.db.getEntry(block1.hash('hex'));
      tip2 = await chain.db.getEntry(block2.hash('hex'));

      assert(tip1);
      assert(tip2);

      assert(!await tip2.isMainChain());

      await co.wait();
    }
  });

  it('should have correct chain value', () => {
    assert.strictEqual(chain.db.state.value, 55000000000);
    assert.strictEqual(chain.db.state.coin, 20);
    assert.strictEqual(chain.db.state.tx, 21);
  });

  it('should have correct balance', async () => {
    await co.timeout(100);

    const balance = await wallet.getBalance();
    assert.strictEqual(balance.unconfirmed, 550 * 1e8);
    assert.strictEqual(balance.confirmed, 550 * 1e8);
  });

  it('should handle a reorg', async () => {
    assert.strictEqual(wdb.state.height, chain.height);
    assert.strictEqual(chain.height, 11);

    const entry = await chain.db.getEntry(tip2.hash);
    assert(entry);
    assert.strictEqual(chain.height, entry.height);

    const block = await miner.mineBlock(entry);
    assert(block);

    let forked = false;
    chain.once('reorganize', () => {
      forked = true;
    });

    await chain.add(block);

    assert(forked);
    assert.strictEqual(chain.tip.hash, block.hash('hex'));
    assert(chain.tip.chainwork.cmp(tip1.chainwork) > 0);
  });

  it('should have correct chain value', () => {
    assert.strictEqual(chain.db.state.value, 60000000000);
    assert.strictEqual(chain.db.state.coin, 21);
    assert.strictEqual(chain.db.state.tx, 22);
  });

  it('should have correct balance', async () => {
    await co.timeout(100);

    const balance = await wallet.getBalance();
    assert.strictEqual(balance.unconfirmed, 1100 * 1e8);
    assert.strictEqual(balance.confirmed, 600 * 1e8);
  });

  it('should check main chain', async () => {
    const result = await tip1.isMainChain();
    assert(!result);
  });

  it('should mine a block after a reorg', async () => {
    const block = await mineBlock(null, cb2);

    await chain.add(block);

    const entry = await chain.db.getEntry(block.hash('hex'));
    assert(entry);
    assert.strictEqual(chain.tip.hash, entry.hash);

    const result = await entry.isMainChain();
    assert(result);
  });

  it('should prevent double spend on new chain', async () => {
    const block = await mineBlock(null, cb2);
    const tip = chain.tip;

    let err;
    try {
      await chain.add(block);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.strictEqual(err.reason, 'bad-txns-inputs-missingorspent');
    assert.strictEqual(chain.tip, tip);
  });

  it('should fail to mine block with coins on an alternate chain', async () => {
    const block = await mineBlock(null, cb1);
    const tip = chain.tip;

    let err;
    try {
      await chain.add(block);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.strictEqual(err.reason, 'bad-txns-inputs-missingorspent');
    assert.strictEqual(chain.tip, tip);
  });

  it('should have correct chain value', () => {
    assert.strictEqual(chain.db.state.value, 65000000000);
    assert.strictEqual(chain.db.state.coin, 23);
    assert.strictEqual(chain.db.state.tx, 24);
  });

  it('should get coin', async () => {
    const block1 = await mineBlock();
    await chain.add(block1);

    const block2 = await mineBlock(null, block1.txs[0]);
    await chain.add(block2);

    const tx = block2.txs[1];
    const output = Coin.fromTX(tx, 1, chain.height);

    const coin = await chain.db.getCoin(tx.hash('hex'), 1);

    assert.bufferEqual(coin.toRaw(), output.toRaw());
  });

  it('should get balance', async () => {
    await co.timeout(100);

    const balance = await wallet.getBalance();
    assert.strictEqual(balance.unconfirmed, 1250 * 1e8);
    assert.strictEqual(balance.confirmed, 750 * 1e8);

    assert(wallet.account.receiveDepth >= 7);
    assert(wallet.account.changeDepth >= 6);

    assert.strictEqual(wdb.state.height, chain.height);

    const txs = await wallet.getHistory();
    assert.strictEqual(txs.length, 45);
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

    await chain.db.scan(0, wdb.filter, async (block, txs) => {
      total += txs.length;
    });

    assert.strictEqual(total, 26);
  });

  it('should activate csv', async () => {
    const deployments = chain.network.deployments;

    const prev = await chain.tip.getPrevious();
    const state = await chain.getState(prev, deployments.csv);
    assert.strictEqual(state, 0);

    for (let i = 0; i < 417; i++) {
      const block = await miner.mineBlock();
      await chain.add(block);
      switch (chain.height) {
        case 144: {
          const prev = await chain.tip.getPrevious();
          const state = await chain.getState(prev, deployments.csv);
          assert.strictEqual(state, 1);
          break;
        }
        case 288: {
          const prev = await chain.tip.getPrevious();
          const state = await chain.getState(prev, deployments.csv);
          assert.strictEqual(state, 2);
          break;
        }
        case 432: {
          const prev = await chain.tip.getPrevious();
          const state = await chain.getState(prev, deployments.csv);
          assert.strictEqual(state, 3);
          break;
        }
      }
    }

    assert.strictEqual(chain.height, 432);
    assert(chain.state.hasCSV());

    const cache = await chain.db.getStateCache();
    assert.deepStrictEqual(cache, chain.db.stateCache);
    assert.strictEqual(chain.db.stateCache.updates.length, 0);
    assert(await chain.db.verifyDeployments());
  });

  it('should test csv', async () => {
    const tx = (await chain.db.getBlock(chain.height)).txs[0];
    const csvBlock = await mineCSV(tx);

    await chain.add(csvBlock);

    const csv = csvBlock.txs[1];

    const spend = new MTX();

    spend.addOutput({
      script: [
        ScriptNum.encode(2),
        Script.opcodes.OP_CHECKSEQUENCEVERIFY
      ],
      value: 10 * 1e8
    });

    spend.addTX(csv, 0);
    spend.setSequence(0, 1, false);

    const job = await miner.createJob();

    job.addTX(spend.toTX(), spend.view);
    job.refresh();

    const block = await job.mineAsync();

    await chain.add(block);
  });

  it('should fail csv with bad sequence', async () => {
    const csv = (await chain.db.getBlock(chain.height)).txs[1];
    const spend = new MTX();

    spend.addOutput({
      script: [
        ScriptNum.encode(1),
        Script.opcodes.OP_CHECKSEQUENCEVERIFY
      ],
      value: 10 * 1e8
    });

    spend.addTX(csv, 0);
    spend.setSequence(0, 1, false);

    const job = await miner.createJob();

    job.addTX(spend.toTX(), spend.view);
    job.refresh();

    const block = await job.mineAsync();

    let err;
    try {
      await chain.add(block);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(err.reason, 'mandatory-script-verify-flag-failed');
  });

  it('should mine a block', async () => {
    const block = await miner.mineBlock();
    assert(block);
    await chain.add(block);
  });

  it('should fail csv lock checks', async () => {
    const tx = (await chain.db.getBlock(chain.height)).txs[0];
    const csvBlock = await mineCSV(tx);

    await chain.add(csvBlock);

    const csv = csvBlock.txs[1];

    const spend = new MTX();

    spend.addOutput({
      script: [
        ScriptNum.encode(2),
        Script.opcodes.OP_CHECKSEQUENCEVERIFY
      ],
      value: 10 * 1e8
    });

    spend.addTX(csv, 0);
    spend.setSequence(0, 2, false);

    const job = await miner.createJob();

    job.addTX(spend.toTX(), spend.view);
    job.refresh();

    const block = await job.mineAsync();

    let err;
    try {
      await chain.add(block);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.strictEqual(err.reason, 'bad-txns-nonfinal');
  });

  it('should rescan for transactions', async () => {
    await wdb.rescan(0);
    assert.strictEqual(wallet.txdb.state.confirmed, 1289250000000);
  });

  it('should reset miner mempool', async () => {
    miner.mempool = node.mempool;
  });

  it('should not get a block template', async () => {
    const json = await node.rpc.call({
      method: 'getblocktemplate'
    }, {});
    assert(json.error);
    assert.strictEqual(json.error.code, -8);
  });

  it('should get a block template', async () => {
    const json = await node.rpc.call({
      method: 'getblocktemplate',
      params: [
        {rules: ['segwit']}
      ],
      id: '1'
    }, {});

    assert.typeOf(json.result, 'object');
    assert.typeOf(json.result.curtime, 'number');
    assert.typeOf(json.result.mintime, 'number');
    assert.typeOf(json.result.maxtime, 'number');
    assert.typeOf(json.result.expires, 'number');

    assert.deepStrictEqual(json, {
      result: {
        capabilities: ['proposal'],
        mutable: ['time', 'transactions', 'prevblock'],
        version: 536870912,
        rules: ['csv', '!segwit', 'testdummy'],
        vbavailable: {},
        vbrequired: 0,
        height: 437,
        previousblockhash: node.chain.tip.rhash(),
        target:
          '7fffff0000000000000000000000000000000000000000000000000000000000',
        bits: '207fffff',
        noncerange: '00000000ffffffff',
        curtime: json.result.curtime,
        mintime: json.result.mintime,
        maxtime: json.result.maxtime,
        expires: json.result.expires,
        sigoplimit: 80000,
        sizelimit: 4000000,
        weightlimit: 4000000,
        longpollid: node.chain.tip.rhash() + '0000000000',
        submitold: false,
        coinbaseaux: { flags: '6d696e65642062792062636f696e' },
        coinbasevalue: 1250000000,
        coinbasetxn: undefined,
        default_witness_commitment:
          '6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962'
          + 'b48bebd836974e8cf9',
        transactions: []
      },
      error: null,
      id: '1'
    });
  });

  it('should send a block template proposal', async () => {
    const attempt = await node.miner.createBlock();

    attempt.refresh();

    const block = attempt.toBlock();

    const hex = block.toRaw().toString('hex');

    const json = await node.rpc.call({
      method: 'getblocktemplate',
      params: [{
        mode: 'proposal',
        data: hex
      }]
    }, {});

    assert(!json.error);
    assert.strictEqual(json.result, null);
  });

  it('should submit a block', async () => {
    const block = await node.miner.mineBlock();
    const hex = block.toRaw().toString('hex');

    const json = await node.rpc.call({
      method: 'submitblock',
      params: [hex]
    }, {});

    assert(!json.error);
    assert.strictEqual(json.result, null);
    assert.strictEqual(node.chain.tip.hash, block.hash('hex'));
  });

  it('should validate an address', async () => {
    const addr = new Address();

    addr.network = node.network;

    const json = await node.rpc.call({
      method: 'validateaddress',
      params: [addr.toString()]
    }, {});

    assert.deepStrictEqual(json.result, {
      isvalid: true,
      address: addr.toString(),
      scriptPubKey: Script.fromAddress(addr).toJSON(),
      ismine: false,
      iswatchonly: false
    });
  });

  it('should add transaction to mempool', async () => {
    const mtx = await wallet.createTX({
      rate: 100000,
      outputs: [{
        value: 100000,
        address: wallet.getAddress()
      }]
    });

    await wallet.sign(mtx);

    assert(mtx.isSigned());

    const tx = mtx.toTX();

    await wallet.db.addTX(tx);

    const missing = await node.mempool.addTX(tx);
    assert(!missing);

    assert.strictEqual(node.mempool.map.size, 1);

    tx1 = mtx;
  });

  it('should add lesser transaction to mempool', async () => {
    const mtx = await wallet.createTX({
      rate: 1000,
      outputs: [{
        value: 50000,
        address: wallet.getAddress()
      }]
    });

    await wallet.sign(mtx);

    assert(mtx.isSigned());

    const tx = mtx.toTX();

    await wallet.db.addTX(tx);

    const missing = await node.mempool.addTX(tx);
    assert(!missing);

    assert.strictEqual(node.mempool.map.size, 2);

    tx2 = mtx;
  });

  it('should get a block template', async () => {
    node.rpc.refreshBlock();

    const json = await node.rpc.call({
      method: 'getblocktemplate',
      params: [
        {rules: ['segwit']}
      ],
      id: '1'
    }, {});

    assert(!json.error);
    assert(json.result);

    const result = json.result;

    let fees = 0;
    let weight = 0;

    for (const item of result.transactions) {
      fees += item.fee;
      weight += item.weight;
    }

    assert.strictEqual(result.transactions.length, 2);
    assert.strictEqual(fees, tx1.getFee() + tx2.getFee());
    assert.strictEqual(weight, tx1.getWeight() + tx2.getWeight());
    assert.strictEqual(result.transactions[0].hash, tx1.txid());
    assert.strictEqual(result.transactions[1].hash, tx2.txid());
    assert.strictEqual(result.coinbasevalue, 125e7 + fees);
  });

  it('should get raw transaction', async () => {
    const json = await node.rpc.call({
      method: 'getrawtransaction',
      params: [tx2.txid()],
      id: '1'
    }, {});

    assert(!json.error);
    const tx = TX.fromRaw(json.result, 'hex');
    assert.strictEqual(tx.txid(), tx2.txid());
  });

  it('should prioritise transaction', async () => {
    const json = await node.rpc.call({
      method: 'prioritisetransaction',
      params: [tx2.txid(), 0, 10000000],
      id: '1'
    }, {});

    assert(!json.error);
    assert.strictEqual(json.result, true);
  });

  it('should get a block template', async () => {
    let fees = 0;
    let weight = 0;

    node.rpc.refreshBlock();

    const json = await node.rpc.call({
      method: 'getblocktemplate',
      params: [
        {rules: ['segwit']}
      ],
      id: '1'
    }, {});

    assert(!json.error);
    assert(json.result);

    const result = json.result;

    for (const item of result.transactions) {
      fees += item.fee;
      weight += item.weight;
    }

    assert.strictEqual(result.transactions.length, 2);
    assert.strictEqual(fees, tx1.getFee() + tx2.getFee());
    assert.strictEqual(weight, tx1.getWeight() + tx2.getWeight());
    assert.strictEqual(result.transactions[0].hash, tx2.txid());
    assert.strictEqual(result.transactions[1].hash, tx1.txid());
    assert.strictEqual(result.coinbasevalue, 125e7 + fees);
  });

  it('should cleanup', async () => {
    consensus.COINBASE_MATURITY = 100;
    await node.close();
  });
});
