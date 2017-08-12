'use strict';

const assert = require('assert');
const Input = require('../lib/primitives/input');
const Output = require('../lib/primitives/output');
const KeyRing = require('../lib/primitives/keyring');
const Amount = require('../lib/btc/amount');
const Script = require('../lib/script/script');
const digest = require('../lib/crypto/digest');
const Address = require('../lib/primitives/address');
const FullNode = require('../lib/node/fullnode');
const Validator = require('../lib/utils/validator');
const util = require('../lib/utils/util');
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
  let network, json, node;
  let chain, miner, pool;
  let wallet, wdb, http;
  let tx1, tx2, tx3, cb;

  node = new FullNode({
    network: 'regtest',
    db: 'memory',
    apiKey: 'foo',
    workers: true,
    plugins: [require('../lib/wallet/plugin')]
  });

  node.open();
  chain = node.chain;
  miner = node.miner;
  pool = node.pool;

  wdb = node.require('walletdb');

  this.timeout(5000);


async function startBlock(tip, tx) {
  let tip = chain.tip;
  let job = await miner.createJob(tip);
  let mtx;

  if (!tx)
    return await job.mineAsync();

  mtx = new MTX();

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


it('should validate an address', async () => {
  let addr = new Address();
  let json;

  addr.network = node.network;

  json = await node.rpc.call({
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
  let tips = await chain.db.getTips();
  let json, block, hex;
  let headers, chainwork, bestblockhash;

  try {
    await chain.tip
  } catch (e) {
    err = e;
  }

  json = await node.rpc.call({
    method: 'getblockchaininfo',
  }, {})
    assert(json, {
      result: {
      blocks: chain.height,
      headers: chain.height,
      bestblockhash: chain.tip.rhash(),
      mediantime: await chain.tip.getMedianTime(),
      verificationprogress: chain.getProgress(),
      chainwork: chain.tip.toString('hex', 64)
  },
  error: null,
 });
});

it('should relay Bestblockhash', async () => {
  let json;

  json = await node.rpc.call({
    method: 'getbestblockhash',
  }, {})
  assert(json, {
    result: {
      bestblockhash: chain.tip.rhash()
    }
  })
});


it('should relay rpc-command getMempoolInfo (getmempoolinfo)', async () => {
  let btc = Amount.btc;
  let json;

  json = await node.rpc.call({
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
  let hash, entry;
  let json;

  entry = node.mempool.getEntry(hash);

  json = await node.rpc.call({
    method: 'getmempoolentry',
    id: '1'
  }, {})
  assert(json, {
    result: {
      error: ''
    }
  });
});

it('should relay Chainstate', async() => {
  let btc = Amount.btc;
  let json;

  json = await node.rpc.call({
    method: 'gettxoutsetinfo'
  }, {})
  assert(json, {
    result: {
      height: chain.height,
      bestblock: chain.tip.rhash(),
      transaction: chain.db.state.tx,
      txouts: chain.db.state.coin,
      bytes_serialized: null,
      hash_serialized: null,
      total_amount: btc(chain.db.state.value, true)
    }
  });
});


it('should relay miner, (getmininginfo)', async () => {
  let size, weight, txs, diff;
  let json;

  json = await node.rpc.call({
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
  let addr = new Address();
  let btc = Amount.btc;
  let json;

  json = await node.rpc.call({
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
  let valid = new Validator();
  let script = new Script();
  let addr = new Address.fromScripthash(script.hash160());
  let data = valid.buf(0);
  let hex = 'a91419a7d869032368fd1f1e26e5e73a4ad0e474960e87';
  let json, decoded;

  addr.network = node.network;

  json = await node.rpc.call({
    method: 'decodescript',
    params: [addr.toString(addr.network)]
  }, {});

  decoded = Script.fromRaw(hex, 'hex');
  assert(decoded.isScripthash);
 });

/*
 * P2P RPC Calls
 */

it('should relay getNetworkInfo', async () => {
  let hosts = pool.hosts;
  let addr = new Address();
  let btc = Amount.btc;
  let json;

  addr.network = node.network;

  json = await node.rpc.call({
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

});
