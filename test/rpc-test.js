'use strict';

const assert = require('assert');
const Input = require('../lib/primitives/input');
const Output = require('../lib/primitives/output');
const Amount = require('../lib/btc/amount');
const Script = require('../lib/script/script');
const digest = require('../lib/crypto/digest');
const Address = require('../lib/primitives/address');
const FullNode = require('../lib/node/fullnode');
const Coin = require('../lib/primitives/coin');
const util = require('../lib/utils/util');
const Validator = require('../lib/utils/validator');
const MTX = require('../lib/primitives/mtx');
const TX = require('../lib/primitives/tx');
const consensus = require('../lib/protocol/consensus');
const RPC = require('../lib/http/rpc');
const RPCBase = require('../lib/http/rpcbase');
const RPCError = RPCBase.RPCError;
const errs = RPCBase.errors;

/**
 * getblockchaininfo
 * getbestblockhash
 * getblockcount
 * getblock
 * getblockbyheight
 * getblockhash
 * getblockheader
 * getchantips
 * getdifficulty
 * getmempoolancestors
 * getmempooldescendants
 * getmempoolentry
 * getmempoolinfo
 * gettxout
 * gettxoutsetinfo
 * pruneblockchain
 * verifychain
 *
 * invalidateblock
 * reconsiderblock
 *
 * getnetworkhashps
 * getmininginfo
 * prioritisetransaction
 * getwork
 * getworklp
 * getblocktemplate
 * submitblock
 * verifyblock
 *
 * setgenerate
 * getgenerate
 * generate
 * generatetoaddress
 *
 * estimatefee
 * estimatepriority
 * estimatesmartfee
 * estimatesmartpriority
 *
 * getinfo
 * validateaddress
 * createmultisig
 * createwitnessaddress
 * verifymessage
 * signmessagewithprivkey
 *
 * setmocktime
 *
 * getconnectioncount
 * ping
 * getpeerinfo
 * addnode
 * disconnectnode
 * getaddednodeinfo
 * getnettotals
 * getnetworkinfo
 * setban
 * listbanned
 * clearbanned
 *
 * getrawtransaction
 * createrawtransaction
 * decodedrawtransaction
 * decodescript
 * sendrawtransaction
 * signrawtransaction
 *
 * gettxoutproff
 * verifytxoutproof
 *
 * getmemoryinfo
 * setloglevel
 */

describe('RPC', function() {
  const node = new FullNode({
    network: 'regtest',
    db: 'memory',
    apiKey: 'foo',
    workers: true,
    plugins: [require('../lib/wallet/plugin')]
  });

const chain = node.chain;
const miner = node.miner;
const pool = node.pool;
const wdb = node.require('walletdb');

let wallet = null;
let tx1 = null;

async function getHashRate() {
  const addr = new Address();
  const tip = await chain.db.getEntry(height);
  await lookup = tip.height % addr.network.pow.retargetInterval + 1;

  return await tip.hash;
};


async function startBlock(tip, tx) {
  const job = await miner.createJob(tip);

  if (!tx)
    return await job.mineAsync();

  const mtx = new MTX();

  mtx.addTX(tx, 0);
  mtx.addOutput(wallet.getReceive(), 25 * 1e8);
  mtx.addOutput(wallet.getChange(), 5 * 1e8);

  mtx.setLocktime(chain.height);

  await wallet.sign(mtx);

  job.addTX(mtx.toTX(), mtx.view);
  job.refresh();

  return await job.mineAsync();
}

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

  const json = await node.rpc.call({
    method: 'getblockchaininfo',
  }, {})
    assert(json, {
      result: {
      chain: node.network.type,
      blocks: chain.height,
      headers: chain.height,
      bestblockhash: chain.tip.rhash(),
      mediantime: await chain.tip.getMedianTime(),
      verificationprogress: chain.getProgress(),
      chainwork: chain.tip.toString('hex', 64),
      pruned: node.rpc.chain.options.prune
  },
  error: null,
 });
});

it('should relay Bestblockhash', async () => {
  const json = await node.rpc.call({
    method: 'getbestblockhash',
  }, {})
  assert(json, {
    result: {
      bestblockhash: chain.tip.rhash()
    }
  })
});


it('should relay transaction output', async () => {
  const json = await node.rpc.call({
    method: 'gettxout'
  }, {})
  assert.deepStrictEqual(json, {
    result: {
      bestblock: chain.tip.rhash(),
      coinbase: false,
      confirmations: chain.height,
      value: 0,
      version: 1
    }
  })
});


it('shoud relay chainstate', async () => {
  const btc = Amount.btc;
  const json = await node.rpc.call({
    method: 'gettxoutsetinfo'
  }, {})
  assert.deepStrictEqual(json,  {
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
  })
});

it('should relay rpc-command getMempoolInfo (getmempoolinfo)', async () => {
  const btc = Amount.btc;
  const json = await node.rpc.call({
    method: 'getmempoolinfo',

  }, {})
  assert(json, {
    result: {
      size: node.mempool.size,
      bytes: node.mempool.getSize(),
      usage: node.mempool.getSize(),
      maxmempool: node.mempool.options.maxSize,
      mempoolminfee: btc(node.mempool.options.minRelay, true)
    }
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
  assert(json, {
    result: {
      height: chain.height,
      bestblock: chain.tip.rhash(),
      transaction: chain.db.state.tx,
      txouts: chain.db.state.coin,
      bytes_serialized: 0,
      hash_serialized: 0,
      total_amount: btc(chain.db.state.value, true)
    }
  });
});


it('should relay miner, (getmininginfo)', async () => {
  let size, weight, txs, diff;
  const json = await node.rpc.call({
    method: 'getmininginfo'
  }, {})
  assert(json, {
    result: {
    blocks: chain.height,
    currentblocksize: size,
    genproclimit:  node.rpc.procLimit,
    errors: '',
    chain: node.network.type
  }
})
});

it('getinfo from node', async () => {
  const addr = new Address();
  const btc = Amount.btc;

  const json = await node.rpc.call({
    method: 'getinfo',
    params: [addr.toString(addr.network)]
  }, {})
  assert(json, {
    result: {
      difficulty: chain.db.getTip(chain.tip.bits),
      paytxfee: btc(node.network.feeRate, true),
      relayfee: btc(node.network.minRelay, true),
      protocolversion: pool.options.version
    }
  });
});

it('should decode valid Script data', async () => {
  const script = new Script();
  const addr = new Address.fromScripthash(script.hash160());
  let hex = 'a91419a7d869032368fd1f1e26e5e73a4ad0e474960e87';
  let decoded;

  const json = await node.rpc.call({
    method: 'decodescript',
    params: [addr.toString(addr.network)]
  }, {});

  decoded = Script.fromRaw(hex, 'hex');
  assert(decoded.isScripthash);
 });


/*
 * Node-Related
 */

it('should prune the Blockchain', async () => {
  // TODO:
  // assert.deepStrictEqual
  // 'Cannot prune chain in SPV mode', 'Chain is Already Pruned'
  const json = await node.rpc.call({
    method: 'pruneblockchain'
  });
});


/*
 * P2P RPC Calls
 */

it('should relay getNetworkInfo', async () => {
  const hosts = pool.hosts;
  const addr = new Address();
  const btc = Amount.btc;
  addr.network = node.network;

  const json = await node.rpc.call({
    method: 'getnetworkinfo'
  }, {});
  assert(json, {
    result: {
      subversion: pool.options.agent,
      protocolversion: pool.options.version,
      localservices: util.hex32(pool.options.services),
      localrelay: !pool.options.noRelay,
      timeoffset: addr.network.time.offset,
      networkactive: pool.connected,
      connections: pool.peers.size(),
      networks: [],
      relayfee: btc(addr.network.minRelay, true),
    }
  })
});

it('should addnode', async () => {
  const json = await node.rpc.call({
    method: 'addnode'
  }, {});
});


it('should cleanup', async () => {
  consensus.COINBASE_MATURITY = 100;
  await pool.disconnect();
  await node.close();
});

});

