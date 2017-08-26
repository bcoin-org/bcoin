/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const digest = require('../lib/crypto/digest');
const Input = require('../lib/primitives/input');
const Output = require('../lib/primitives/output');
const Amount = require('../lib/btc/amount');
const Script = require('../lib/script/script');
const Address = require('../lib/primitives/address');
const FullNode = require('../lib/node/fullnode');
const Coin = require('../lib/primitives/coin');
const MTX = require('../lib/primitives/mtx');
const TX = require('../lib/primitives/tx');
const consensus = require('../lib/protocol/consensus');
const util = require('../lib/utils/util');
const encoding = require('../lib/utils/encoding');
const co = require('../lib/utils/co');
const RPC = require('../lib/http/rpc');
const RPCBase = require('../lib/http/rpcbase');
const MAGIC_STRING = RPCBase.MAGIC_STRING;
const RPCError = RPCBase.RPCError;
const errs = RPCBase.errors;

const node = new FullNode({
  network: 'regtest',
  db: 'memory',
  apiKey: 'test',
  workers: true,
  plugins: [require('../lib/wallet/plugin')]
});

const chain = node.chain;
const miner = node.miner;
const pool = node.pool;
const wdb = node.require('walletdb');

let wallet = null;
let tx1 = null;
let height = chain.height;


async function getHashRate(lookup, height) {
  let tip = await chain.tip;

  if (height != null)
    tip = await chain.db.getEntry(height);

  if (!tip)
    return 0;

  if (lookup <= 0)
    lookup = tip.height % node.network.pow.retargetInterval + 1;

  if (lookup > tip.height)
    lookup = tip.height;

  let minTime = tip.time;
  let maxTime = minTime;
  let entry = tip;

  for (let i = 0; i < lookup; i++) {
    entry = await entry.getPrevious();

  minTime = Math.min(entry.time, minTime);
  maxTime = Math.max(entry.time, maxTime);
  };

  if (minTime === maxTime)
    return 0;

  const workDiff = tip.chainwork.sub(entry.chainwork);
  const timeDiff = maxTime - minTime;
  const ps = parseInt(workDiff.toString(10) / 10) / timeDiff;

  return ps;
};

async function startBlock(tip, tx) {
  const job = await miner.createJob(tip);

  if (!tx)
    return await job.mineAsync();

  const mtx = new MTX();
  mtx.addTX(tx, 0);
  mtx.addOutput(wallet.getReceive(), 25 * 1e8);
  mtx.addOutput(wallet.getReceive(), 5 * 1e8);

  mtx.setLocktime(height);

  await wallet.sign(mtx);

  job.addTX(mtx.toTX(), mtx.view);
  job.refresh();

  return await job.mineAsync()
}

async function getSoftforks() {
  return [
    toDeployment('bip34', 2, chain.state.hasBIP34()),
    toDeployment('bip66', 3, chain.state.hasBIP66()),
    toDeployment('bip65', 4, chain.state.hasCLTV())
  ];
}

async function toDeployment(id, version, status) {
  let id = pool.id;
  let version = pool.options.version;

  return {
    id: id,
    version: version,
    reject: {
      status: status
    }
  };
}


async function toDifficulty(bits) {
 let shift = (bits >>> 24) & 0xff;
 let diff = 0x0000ffff / (bits & 0x00ffffff);

  while (shift < 29) {
    diff *= 256.0;
    shift++;
  }

  while (shift > 29)  {
    diff /= 256.0;
    shift--;
  }

  return diff;
}

async function pruneHeight(chain) {
  const pruning = (chain.options.prune !== false)

  if (!chain.options.prune)
    return chain.height;

  while (pruning % node.network.block.keepBlocks) {
    verbose = null;
  }
}


describe('RPC', function() {
  this.timeout(5000);

it('should open chain, and miner', async() => {
  miner.mempool = null;
  consensus.COINBASE_MATURITY = 0;
  await node.open();
});

it('should open walletdb', async () => {
  wallet = await wdb.create();
  miner.addresses.length = 0;
  miner.addAddress(wallet.getReceive());
});

it('should connect to the mempool', async() => {
  await pool.connect()
  node.startSync()
});

it('should relay node memory (nativeHeap / jsHeap)', async () => {
  const json = await node.rpc.call({
    method: 'getmemoryinfo'
  }, {})
});

it('should create a block template', async () => {
  const json = await node.rpc.call({
    method: 'getblocktemplate',
    params: [{rules: ['segwit']}],
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
      rules: [],
      vbavailable: {},
      vbrequired: 0,
      height: 1,
      previousblockhash: chain.tip.rhash(),
      target: '7fffff0000000000000000000000000000000000000000000000000000000000',
      bits: '207fffff',
      noncerange: '00000000ffffffff',
      curtime: json.result.curtime,
      mintime: json.result.mintime,
      maxtime: json.result.maxtime,
      expires: json.result.expires,
      sigoplimit: 20000,
      sizelimit: 1000000,
      weightlimit: undefined,
      longpollid: node.chain.tip.rhash() + '0000000000',
      submitold: false,
      coinbaseaux: { flags: '6d696e65642062792062636f696e' },
      coinbasevalue: 5000000000,
      coinbasetxn: undefined,
      default_witness_commitment: '6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962'
                                + 'b48bebd836974e8cf9',

      transactions: []
    },
    error: null,
    id: '1'
  });
});

it('should submit a block', async () => {
  const block = await miner.mineBlock();
  const hex = block.toRaw().toString('hex');

  const json = await node.rpc.call({
    method: 'submitblock',
    params: [hex]
  }, {});

  assert(!json.error);
  assert.strictEqual(json.result, null);
  assert.strictEqual(chain.tip.hash, block.hash('hex'));
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

it('should relay blockchain info (eg blocks,headers,chainwork)', async () => {
  const deployments = chain.options.network.deployments;
  const tip = chain.tip;
  const forks = {};
  const softforks = [chain.state.hasBIP34, chain.state.hasBIP66, chain.state.hasBIP65]

  const json = await node.rpc.call({
    method: 'getblockchaininfo'
  }, {});

    assert.deepStrictEqual(json.result, {
      bestblockhash: chain.tip.rhash(),
      bip9_softforks: deployments,
      blocks: chain.height,
      chain: node.network.type,
      chainwork: chain.tip.chainwork.toString('hex', 64),
      difficulty: 4.6565423739069247e-10,
      headers:chain.height,
      mediantime: await chain.tip.getMedianTime(),
      pruned: node.rpc.chain.options.prune,
      pruneheight: null,
      softforks:
      [{
        id: 'bip34',
        reject: {
        status: false,
      },
        version: 2
      },
       {
        id: 'bip66',
        reject: {
        status: false
      },
        version: 3
      },
       {
        id: 'bip65',
        reject: {
        status: false
      },
        version: 4
      }],
      verificationprogress: chain.getProgress()
  });
});


it('should relay chaintips', async () => {
  const tips = await chain.db.getTips();
  const findFork = chain.tip.isMainChain();

  const json = await node.rpc.call({
    method: 'getchaintips',
  }, {})

  const result = json.result;

  assert.deepStrictEqual(json, {
    error: null,
    id: null,
    result: [{
      branchlen: 0,
      hash: chain.tip.rhash(),
      height: chain.height,
      status: findFork ? 'active' : 'valid-headers'
    }]
  })
});


it('should relay Bestblockhash', async () => {
  const json = await node.rpc.call({
    method: 'getbestblockhash',
  }, {})
  assert.deepStrictEqual(json, {
    error: null,
    id: null,
    result: chain.tip.rhash()
  })
});


it('should relay rpc-command getMempoolInfo (getmempoolinfo)', async () => {
  const btc = Amount.btc;
  const json = await node.rpc.call({
    method: 'getmempoolinfo',

  }, {})
  assert.deepStrictEqual(json, {
    result: {
      bytes: node.mempool.getSize(),
      maxmempool: node.mempool.options.maxSize,
      mempoolminfee: btc(node.mempool.options.minRelay, true),
      size: 0,
      usage: 0
    },
    error: null,
    id: null
  })
});

it('should get entry to Mempool (getmempoolentry txid)', async () => {
  const json = await node.rpc.call({
    method: 'getmempoolentry',
    id: '1'
  }, {})
  assert(json, {
    result: {
      error: undefined
    }
  });
});


it('should relay Chainstate', async() => {
  const btc = Amount.btc;
  const json = await node.rpc.call({
    method: 'gettxoutsetinfo'
  }, {})
  assert.deepStrictEqual(json, {
    result: {
      height: chain.height,
      bestblock: chain.tip.rhash(),
      transactions: chain.db.state.tx,
      txouts: chain.db.state.coin,
      bytes_serialized: 0,
      hash_serialized: 0,
      total_amount: btc(chain.db.state.value, true)
    },
    error: null,
    id: null
  });
});


it('should rpc-method (getmininginfo)', async () => {
  const attempt = await node.miner.createBlock();
  const U32 = encoding.U32;

  attempt.refresh();

  const block = attempt.toBlock();
  const tip = chain.tip;

  const json = await node.rpc.call({
    method: 'getmininginfo'
  }, {});

  let size = 0;
  let weight = 0;
  let txs = 0;
  let diff = 0;

  assert.deepStrictEqual(json, {
    result: {
    blocks: chain.height,
    currentblocksize: size,
    currentblockweight: weight,
    currentblocktx: txs,
    difficulty: diff,
    errors: '',
    genproclimit: await node.rpc.procLimit,
    networkhashps: await getHashRate(120, chain.tip.height),
    pooledtx: pool.mempool.map.size,
    testnet: node.network !== node.network.type,
    chain: node.network.type,
    generate: false
  },
    error: null,
    id: null
})
});

it('getinfo from node', async () => {
  const btc = Amount.btc;
  const bits = node.chain.tip.bits;

  const json = await node.rpc.call({
    method: 'getinfo'
  }, {})
  assert.deepStrictEqual(json, {
    error: null,
    id: null,
    result: {
      balance: 0,
      blocks: 1,
      connections: 0,
      difficulty: 4.6565423739069247e-10,
      errors: '',
      keypoololdest: 0,
      keypoolsize: 0,
      paytxfee: btc(node.network.feeRate, true),
      protocolversion: pool.options.version,
      proxy: '',
      relayfee: btc(node.network.minRelay, true),
      testnet: node.network.type !== 'testnet',
      timeoffset: 0,
      unlocked_until: 0,
      version: 'v1.0.0-beta.14',
      walletversion: 0
    },

  });
});


it('should decode valid P2SH output data', async () => {

  const hex ='a91419a7d869032368fd1f1e26e5e73a4ad0e474960e87';
  const decoded = Script.fromRaw(hex, 'hex');
  const script = new Script();
  const addr = new Address.fromScripthash(script.hash160());

  const json = await node.rpc.call({
    method: 'decodescript',
    params: [addr.toString(addr.network)]
  }, {});
 });


/*
 * P2P RPC Calls
 */

it('should relay getNetworkInfo', async () => {
  const hosts = pool.hosts;
  const addr = new Address();
  const btc = Amount.btc;
  const locals = [
    { 'address': '2601:586:4005:d388:36f3:9aff:fe2b:e125',
      'port': 48444,
      'score': 1  }];

  addr.network = node.network;

  const json = await node.rpc.call({
    method: 'getnetworkinfo'
  }, {});
  assert.deepStrictEqual(json, {
    result: {
      connections: pool.peers.size(),
      version: 'v1.0.0-beta.14',
      subversion: pool.options.agent,
      protocolversion: pool.options.version,
      localservices: util.hex32(pool.options.services),
      localrelay: !pool.options.noRelay,
      timeoffset: node.network.time.offset,
      networkactive: pool.connected,
      networks: [],
      relayfee: btc(addr.network.minRelay, true),
      incrementalfee: 0,
      localaddresses: [],
      warnings: ''
   },
    error: null,
    id: null
  })
});


it('should cleanup', async () => {
  consensus.COINBASE_MATURITY = 100;
  await pool.disconnect();
  await node.close();
});

});

