'use strict';

const assert = require('assert');
const Block = require('../lib/primitives/block');
const Headers = require('../lib/primitives/headers');
const Input = require('../lib/primitives/input');
const Output = require('../lib/primitives/output');
const KeyRing = require('../lib/primitives/keyring');
const Amount = require('../lib/btc/amount');
const Script = require('../lib/script/script');
const Address = require('../lib/primitives/address');
const FullNode = require('../lib/node/fullnode');
const TX = require('../lib/primitives/tx');
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
  let chain, miner, wdb;
  let wallet, http;
  let tx1, tx2, tx3;

  node = new FullNode({
    network: 'testnet',
    db: 'memory',
    apiKey: 'foo',
    workers: true,
    plugins: [require('../lib/wallet/plugin')]
  });

  node.open();
  chain = node.chain;
  miner = node.miner;
  wdb = node.require('walletdb');
  this.timeout(5000);


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
      blocks: node.chain.height,
      headers: node.chain.height,
      bestblockhash: node.chain.tip.rhash(),
      mediantime: await node.chain.tip.getMedianTime(),
      verificationprogress: node.chain.getProgress(),
      chainwork: node.chain.tip.toString('hex', 64)
  },
  error: null,
 });
});
});

