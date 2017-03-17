/*!
 * rpc.js - bitcoind-compatible json rpc for bcoin.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var co = require('../utils/co');
var crypto = require('../crypto/crypto');
var assert = require('assert');
var common = require('../blockchain/common');
var ec = require('../crypto/ec');
var Amount = require('../btc/amount');
var NetAddress = require('../primitives/netaddress');
var Script = require('../script/script');
var Address = require('../primitives/address');
var Block = require('../primitives/block');
var Headers = require('../primitives/headers');
var Input = require('../primitives/input');
var KeyRing = require('../primitives/keyring');
var MerkleBlock = require('../primitives/merkleblock');
var MTX = require('../primitives/mtx');
var Network = require('../protocol/network');
var Output = require('../primitives/output');
var TX = require('../primitives/tx');
var IP = require('../utils/ip');
var encoding = require('../utils/encoding');
var consensus = require('../protocol/consensus');
var Validator = require('../utils/validator');
var RPCBase = require('./rpcbase');
var pkg = require('../pkg');
var RPCError = RPCBase.RPCError;
var errs = RPCBase.errors;
var MAGIC_STRING = RPCBase.MAGIC_STRING;

/**
 * Bitcoin Core RPC
 * @alias module:http.RPC
 * @constructor
 * @param {Node} node
 */

function RPC(node) {
  if (!(this instanceof RPC))
    return new RPC(node);

  RPCBase.call(this);

  assert(node, 'RPC requires a Node.');

  this.node = node;
  this.network = node.network;
  this.chain = node.chain;
  this.mempool = node.mempool;
  this.pool = node.pool;
  this.fees = node.fees;
  this.miner = node.miner;
  this.logger = node.logger.context('rpc');

  this.mining = false;
  this.procLimit = 0;
  this.attempt = null;
  this.lastActivity = 0;
  this.boundChain = false;
  this.nonce1 = 0;
  this.nonce2 = 0;
  this.merkleMap = {};
  this.pollers = [];

  this.init();
}

util.inherits(RPC, RPCBase);

RPC.prototype.init = function init() {
  this.add('stop', this.stop);
  this.add('help', this.help);

  this.add('getblockchaininfo', this.getBlockchainInfo);
  this.add('getbestblockhash', this.getBestBlockHash);
  this.add('getblockcount', this.getBlockCount);
  this.add('getblock', this.getBlock);
  this.add('getblockhash', this.getBlockHash);
  this.add('getblockheader', this.getBlockHeader);
  this.add('getchaintips', this.getChainTips);
  this.add('getdifficulty', this.getDifficulty);
  this.add('getmempoolancestors', this.getMempoolAncestors);
  this.add('getmempooldescendants', this.getMempoolDescendants);
  this.add('getmempoolentry', this.getMempoolEntry);
  this.add('getmempoolinfo', this.getMempoolInfo);
  this.add('getrawmempool', this.getRawMempool);
  this.add('gettxout', this.getTXOut);
  this.add('gettxoutsetinfo', this.getTXOutSetInfo);
  this.add('verifychain', this.verifyChain);

  this.add('invalidateblock', this.invalidateBlock);
  this.add('reconsiderblock', this.reconsiderBlock);

  this.add('getnetworkhashps', this.getNetworkHashPS);
  this.add('getmininginfo', this.getMiningInfo);
  this.add('prioritisetransaction', this.prioritiseTransaction);
  this.add('getwork', this.getWork);
  this.add('getworklp', this.getWorkLongpoll);
  this.add('getblocktemplate', this.getBlockTemplate);
  this.add('submitblock', this.submitBlock);
  this.add('verifyblock', this.verifyBlock);

  this.add('setgenerate', this.setGenerate);
  this.add('getgenerate', this.getGenerate);
  this.add('generate', this.generate);
  this.add('generatetoaddress', this.generateToAddress);

  this.add('estimatefee', this.estimateFee);
  this.add('estimatepriority', this.estimatePriority);
  this.add('estimatesmartfee', this.estimateSmartFee);
  this.add('estimatesmartpriority', this.estimateSmartPriority);

  this.add('getinfo', this.getInfo);
  this.add('validateaddress', this.validateAddress);
  this.add('createmultisig', this.createMultisig);
  this.add('createwitnessaddress', this.createWitnessAddress);
  this.add('verifymessage', this.verifyMessage);
  this.add('signmessagewithprivkey', this.signMessageWithPrivkey);

  this.add('setmocktime', this.setMockTime);

  this.add('getconnectioncount', this.getConnectionCount);
  this.add('ping', this.ping);
  this.add('getpeerinfo', this.getPeerInfo);
  this.add('addnode', this.addNode);
  this.add('disconnectnode', this.disconnectNode);
  this.add('getaddednodeinfo', this.getAddedNodeInfo);
  this.add('getnettotals', this.getNetTotals);
  this.add('getnetworkinfo', this.getNetworkInfo);
  this.add('setban', this.setBan);
  this.add('listbanned', this.listBanned);
  this.add('clearbanned', this.clearBanned);

  this.add('getrawtransaction', this.getRawTransaction);
  this.add('createrawtransaction', this.createRawTransaction);
  this.add('decoderawtransaction', this.decodeRawTransaction);
  this.add('decodescript', this.decodeScript);
  this.add('sendrawtransaction', this.sendRawTransaction);
  this.add('signrawtransaction', this.signRawTransaction);

  this.add('gettxoutproof', this.getTXOutProof);
  this.add('verifytxoutproof', this.verifyTXOutProof);

  this.add('getmemoryinfo', this.getMemoryInfo);
  this.add('setloglevel', this.setLogLevel);
};

/*
 * Overall control/query calls
 */

RPC.prototype.getInfo = co(function* getInfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getinfo');

  return {
    version: pkg.version,
    protocolversion: this.pool.options.version,
    walletversion: 0,
    balance: 0,
    blocks: this.chain.height,
    timeoffset: this.network.time.offset,
    connections: this.pool.peers.size(),
    proxy: '',
    difficulty: toDifficulty(this.chain.tip.bits),
    testnet: this.network !== Network.main,
    keypoololdest: 0,
    keypoolsize: 0,
    unlocked_until: 0,
    paytxfee: Amount.btc(this.network.feeRate, true),
    relayfee: Amount.btc(this.network.minRelay, true),
    errors: ''
  };
});

RPC.prototype.help = co(function* _help(args, help) {
  var json;

  if (args.length === 0)
    return 'Select a command.';

  json = {
    method: args[0],
    params: []
  };

  return yield this.execute(json, true);
});

RPC.prototype.stop = co(function* stop(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'stop');

  this.node.close();

  return 'Stopping.';
});

/*
 * P2P networking
 */

RPC.prototype.getNetworkInfo = co(function* getNetworkInfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getnetworkinfo');

  return {
    version: pkg.version,
    subversion: this.pool.options.agent,
    protocolversion: this.pool.options.version,
    localservices: util.hex32(this.pool.options.services),
    localrelay: true,
    timeoffset: this.network.time.offset,
    connections: this.pool.peers.size(),
    networks: [],
    relayfee: Amount.btc(this.network.minRelay, true),
    localaddresses: [],
    warnings: ''
  };
});

RPC.prototype.addNode = co(function* addNode(args, help) {
  var valid = new Validator([args]);
  var node = valid.str(0, '');
  var cmd = valid.str(1, '');
  var addr, peer;

  if (help || args.length !== 2)
    throw new RPCError(errs.MISC_ERROR, 'addnode "node" "add|remove|onetry"');

  addr = NetAddress.fromHostname(node, this.network);

  switch (cmd) {
    case 'add':
      this.pool.hosts.add(addr);
      break;
    case 'remove':
      this.pool.hosts.remove(addr.hostname);
      break;
    case 'onetry':
      if (!this.pool.peers.get(addr.hostname)) {
        peer = this.pool.createOutbound(addr);
        this.pool.peers.add(peer);
      }
      break;
  }

  return null;
});

RPC.prototype.disconnectNode = co(function* disconnectNode(args, help) {
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var peer;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'disconnectnode "node"');

  addr = IP.fromHostname(addr, this.network.port);
  peer = this.pool.peers.get(addr.hostname);

  if (peer)
    peer.destroy();

  return null;
});

RPC.prototype.getAddedNodeInfo = co(function* getAddedNodeInfo(args, help) {
  var valid = new Validator([args]);
  var addr = valid.str(1, '');
  var out = [];
  var peer;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'getaddednodeinfo dummy ( "node" )');

  if (args.length === 2) {
    addr = IP.fromHostname(addr, this.network.port);
    peer = this.pool.peers.get(addr.hostname);
    if (!peer) {
      throw new RPCError(errs.CLIENT_NODE_NOT_ADDED,
        'Node has not been added.');
    }
    return [toAddedNode(peer)];
  }

  for (peer = this.pool.peers.head(); peer; peer = peer.next)
    out.push(toAddedNode(peer));

  return out;
});

RPC.prototype.getConnectionCount = co(function* getConnectionCount(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getconnectioncount');

  return this.pool.peers.size();
});

RPC.prototype.getNetTotals = co(function* getNetTotals(args, help) {
  var sent = 0;
  var recv = 0;
  var peer;

  if (help || args.length > 0)
    throw new RPCError(errs.MISC_ERROR, 'getnettotals');

  for (peer = this.pool.peers.head(); peer; peer = peer.next) {
    sent += peer.socket.bytesWritten;
    recv += peer.socket.bytesRead;
  }

  return {
    totalbytesrecv: recv,
    totalbytessent: sent,
    timemillis: util.ms()
  };
});

RPC.prototype.getPeerInfo = co(function* getPeerInfo(args, help) {
  var peers = [];
  var id = 0;
  var peer, offset;

  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getpeerinfo');

  for (peer = this.pool.peers.head(); peer; peer = peer.next) {
    offset = this.network.time.known[peer.hostname()];

    if (offset == null)
      offset = 0;

    peers.push({
      id: id++,
      addr: peer.hostname(),
      addrlocal: !peer.local.isNull()
        ? peer.local.hostname
        : undefined,
      services: util.hex32(peer.services),
      relaytxes: !peer.noRelay,
      lastsend: peer.lastSend / 1000 | 0,
      lastrecv: peer.lastRecv / 1000 | 0,
      bytessent: peer.socket.bytesWritten,
      bytesrecv: peer.socket.bytesRead,
      conntime: peer.ts !== 0 ? (util.ms() - peer.ts) / 1000 | 0 : 0,
      timeoffset: offset,
      pingtime: peer.lastPong !== -1
        ? (peer.lastPong - peer.lastPing) / 1000
        : -1,
      minping: peer.minPing !== -1 ? peer.minPing / 1000 : -1,
      version: peer.version,
      subver: peer.agent,
      inbound: !peer.outbound,
      startingheight: peer.height,
      besthash: peer.bestHash ? util.revHex(peer.bestHash) : null,
      bestheight: peer.bestHeight,
      banscore: peer.banScore,
      inflight: peer.blockMap.keys().map(util.revHex),
      whitelisted: false
    });
  }

  return peers;
});

RPC.prototype.ping = co(function* ping(args, help) {
  var peer;

  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'ping');

  for (peer = this.pool.peers.head(); peer; peer = peer.next)
    peer.sendPing();

  return null;
});

RPC.prototype.setBan = co(function* setBan(args, help) {
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var action = valid.str(1, '');

  if (help
      || args.length < 2
      || (action !== 'add' && action !== 'remove')) {
    throw new RPCError(errs.MISC_ERROR,
      'setban "ip(/netmask)" "add|remove" (bantime) (absolute)');
  }

  addr = NetAddress.fromHostname(addr, this.network);

  switch (action) {
    case 'add':
      this.pool.ban(addr);
      break;
    case 'remove':
      this.pool.unban(addr);
      break;
  }

  return null;
});

RPC.prototype.listBanned = co(function* listBanned(args, help) {
  var i, banned, keys, host, time;

  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'listbanned');

  banned = [];
  keys = Object.keys(this.pool.hosts.banned);

  for (i = 0; i < keys.length; i++) {
    host = keys[i];
    time = this.pool.hosts.banned[host];
    banned.push({
      address: host,
      banned_until: time + this.pool.options.banTime,
      ban_created: time,
      ban_reason: ''
    });
  }

  return banned;
});

RPC.prototype.clearBanned = co(function* clearBanned(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'clearbanned');

  this.pool.hosts.clearBanned();

  return null;
});

/* Block chain and UTXO */
RPC.prototype.getBlockchainInfo = co(function* getBlockchainInfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getblockchaininfo');

  return {
    chain: this.network.type !== 'testnet'
      ? this.network.type
      : 'test',
    blocks: this.chain.height,
    headers: this.chain.height,
    bestblockhash: this.chain.tip.rhash(),
    difficulty: toDifficulty(this.chain.tip.bits),
    mediantime: yield this.chain.tip.getMedianTime(),
    verificationprogress: this.chain.getProgress(),
    chainwork: this.chain.tip.chainwork.toString('hex', 64),
    pruned: this.chain.options.prune,
    softforks: this.getSoftforks(),
    bip9_softforks: yield this.getBIP9Softforks(),
    pruneheight: this.chain.options.prune
      ? Math.max(0, this.chain.height - this.network.block.keepBlocks)
      : null
  };
});

RPC.prototype.getBestBlockHash = co(function* getBestBlockHash(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getbestblockhash');

  return this.chain.tip.rhash();
});

RPC.prototype.getBlockCount = co(function* getBlockCount(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getblockcount');

  return this.chain.tip.height;
});

RPC.prototype.getBlock = co(function* getBlock(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var verbose = valid.bool(1, true);
  var entry, block;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'getblock "hash" ( verbose )');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid block hash.');

  entry = yield this.chain.db.getEntry(hash);

  if (!entry)
    throw new RPCError(errs.MISC_ERROR, 'Block not found');

  block = yield this.chain.db.getBlock(entry.hash);

  if (!block) {
    if (this.chain.options.spv)
      throw new RPCError(errs.MISC_ERROR, 'Block not available (spv mode)');

    if (this.chain.options.prune)
      throw new RPCError(errs.MISC_ERROR, 'Block not available (pruned data)');

    throw new RPCError(errs.DATABASE_ERROR, 'Can\'t read block from disk');
  }

  if (!verbose)
    return block.toRaw().toString('hex');

  return yield this.blockToJSON(entry, block, false);
});

RPC.prototype.getBlockHash = co(function* getBlockHash(args, help) {
  var valid = new Validator([args]);
  var height = valid.u32(0);
  var hash;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'getblockhash index');

  if (height == null || height > this.chain.height)
    throw new RPCError(errs.INVALID_PARAMETER, 'Block height out of range.');

  hash = yield this.chain.db.getHash(height);

  if (!hash)
    throw new RPCError(errs.MISC_ERROR, 'Not found.');

  return util.revHex(hash);
});

RPC.prototype.getBlockHeader = co(function* getBlockHeader(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var verbose = valid.bool(1, true);
  var entry;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'getblockheader "hash" ( verbose )');

  if (!hash)
    throw new RPCError(errs.MISC_ERROR, 'Invalid block hash.');

  entry = yield this.chain.db.getEntry(hash);

  if (!entry)
    throw new RPCError(errs.MISC_ERROR, 'Block not found');

  if (!verbose)
    return entry.toRaw().toString('hex', 0, 80);

  return yield this.headerToJSON(entry);
});

RPC.prototype.getChainTips = co(function* getChainTips(args, help) {
  var i, hash, tips, result, entry, fork, main;

  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getchaintips');

  tips = yield this.chain.db.getTips();
  result = [];

  for (i = 0; i < tips.length; i++) {
    hash = tips[i];
    entry = yield this.chain.db.getEntry(hash);
    assert(entry);

    fork = yield this.findFork(entry);
    main = yield entry.isMainChain();

    result.push({
      height: entry.height,
      hash: entry.rhash(),
      branchlen: entry.height - fork.height,
      status: main ? 'active' : 'valid-headers'
    });
  }

  return result;
});

RPC.prototype.getDifficulty = co(function* getDifficulty(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getdifficulty');

  return toDifficulty(this.chain.tip.bits);
});

RPC.prototype.getMempoolInfo = co(function* getMempoolInfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getmempoolinfo');

  if (!this.mempool)
    throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

  return {
    size: this.mempool.totalTX,
    bytes: this.mempool.getSize(),
    usage: this.mempool.getSize(),
    maxmempool: this.mempool.options.maxSize,
    mempoolminfee: Amount.btc(this.mempool.options.minRelay, true)
  };
});

RPC.prototype.getMempoolAncestors = co(function* getMempoolAncestors(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var verbose = valid.bool(1, false);
  var out = [];
  var i, entry, entries;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'getmempoolancestors txid (verbose)');

  if (!this.mempool)
    throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID.');

  entry = this.mempool.getEntry(hash);

  if (!entry)
    throw new RPCError(errs.MISC_ERROR, 'Transaction not in mempool.');

  entries = this.mempool.getAncestors(entry);

  if (verbose) {
    for (i = 0; i < entries.length; i++) {
      entry = entries[i];
      out.push(this.entryToJSON(entry));
    }
  } else {
    for (i = 0; i < entries.length; i++) {
      entry = entries[i];
      out.push(entry.txid());
    }
  }

  return out;
});

RPC.prototype.getMempoolDescendants = co(function* getMempoolDescendants(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var verbose = valid.bool(1, false);
  var out = [];
  var i, entry, entries;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'getmempooldescendants txid (verbose)');

  if (!this.mempool)
    throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID.');

  entry = this.mempool.getEntry(hash);

  if (!entry)
    throw new RPCError(errs.MISC_ERROR, 'Transaction not in mempool.');

  entries = this.mempool.getDescendants(entry);

  if (verbose) {
    for (i = 0; i < entries.length; i++) {
      entry = entries[i];
      out.push(this.entryToJSON(entry));
    }
  } else {
    for (i = 0; i < entries.length; i++) {
      entry = entries[i];
      out.push(entry.txid());
    }
  }

  return out;
});

RPC.prototype.getMempoolEntry = co(function* getMempoolEntry(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var entry;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'getmempoolentry txid');

  if (!this.mempool)
    throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID.');

  entry = this.mempool.getEntry(hash);

  if (!entry)
    throw new RPCError(errs.MISC_ERROR, 'Transaction not in mempool.');

  return this.entryToJSON(entry);
});

RPC.prototype.getRawMempool = co(function* getRawMempool(args, help) {
  var valid = new Validator([args]);
  var verbose = valid.bool(0, false);
  var out = {};
  var i, hashes, hash, entry;

  if (help || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'getrawmempool ( verbose )');

  if (!this.mempool)
    throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

  if (verbose) {
    hashes = this.mempool.getSnapshot();

    for (i = 0; i < hashes.length; i++) {
      hash = hashes[i];
      entry = this.mempool.getEntry(hash);

      if (!entry)
        continue;

      out[entry.txid()] = this.entryToJSON(entry);
    }

    return out;
  }

  hashes = this.mempool.getSnapshot();

  return hashes.map(util.revHex);
});

RPC.prototype.getTXOut = co(function* getTXOut(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var index = valid.u32(1);
  var mempool = valid.bool(2, true);
  var coin;

  if (help || args.length < 2 || args.length > 3)
    throw new RPCError(errs.MISC_ERROR, 'gettxout "txid" n ( includemempool )');

  if (this.chain.options.spv)
    throw new RPCError(errs.MISC_ERROR, 'Cannot get coins in SPV mode.');

  if (this.chain.options.prune)
    throw new RPCError(errs.MISC_ERROR, 'Cannot get coins when pruned.');

  if (!hash || index == null)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid outpoint.');

  if (mempool) {
    if (!this.mempool)
      throw new RPCError(errs.MISC_ERROR, 'No mempool available.');
    coin = this.mempool.getCoin(hash, index);
  }

  if (!coin)
    coin = yield this.chain.db.getCoin(hash, index);

  if (!coin)
    return null;

  return {
    bestblock: this.chain.tip.rhash(),
    confirmations: coin.getDepth(this.chain.height),
    value: Amount.btc(coin.value, true),
    scriptPubKey: this.scriptToJSON(coin.script, true),
    version: coin.version,
    coinbase: coin.coinbase
  };
});

RPC.prototype.getTXOutProof = co(function* getTXOutProof(args, help) {
  var valid = new Validator([args]);
  var txids = valid.array(0);
  var hash = valid.hash(1);
  var uniq = {};
  var i, block, txid, tx, coins;

  if (help || (args.length !== 1 && args.length !== 2)) {
    throw new RPCError(errs.MISC_ERROR,
      'gettxoutproof ["txid",...] ( blockhash )');
  }

  if (this.chain.options.spv)
    throw new RPCError(errs.MISC_ERROR, 'Cannot get coins in SPV mode.');

  if (this.chain.options.prune)
    throw new RPCError(errs.MISC_ERROR, 'Cannot get coins when pruned.');

  if (!txids || txids.length === 0)
    throw new RPCError(errs.INVALID_PARAMETER, 'Invalid TXIDs.');

  valid = new Validator([txids]);

  for (i = 0; i < txids.length; i++) {
    txid = valid.hash(i);

    if (!txid)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID.');

    if (uniq[txid])
      throw new RPCError(errs.INVALID_PARAMETER, 'Duplicate txid.');

    uniq[txid] = true;
    txids[i] = txid;
  }

  if (hash) {
    block = yield this.chain.db.getBlock(hash);
  } else if (this.chain.options.indexTX) {
    tx = yield this.chain.db.getMeta(txid);
    if (!tx)
      return;
    block = yield this.chain.db.getBlock(tx.block);
  } else {
    coins = yield this.chain.db.getCoins(txid);
    if (!coins)
      return;
    block = yield this.chain.db.getBlock(coins.height);
  }

  if (!block)
    throw new RPCError(errs.MISC_ERROR, 'Block not found.');

  for (i = 0; i < txids.length; i++) {
    txid = txids[i];
    if (!block.hasTX(txid)) {
      throw new RPCError(errs.VERIFY_ERROR,
        'Block does not contain all txids.');
    }
  }

  block = MerkleBlock.fromHashes(block, txids);

  return block.toRaw().toString('hex');
});

RPC.prototype.verifyTXOutProof = co(function* verifyTXOutProof(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var out = [];
  var i, block, hash, entry;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'verifytxoutproof "proof"');

  if (!data)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid hex string.');

  block = MerkleBlock.fromRaw(data);

  if (!block.verify())
    return out;

  entry = yield this.chain.db.getEntry(block.hash('hex'));

  if (!entry)
    throw new RPCError(errs.MISC_ERROR, 'Block not found in chain.');

  for (i = 0; i < block.matches.length; i++) {
    hash = block.matches[i];
    out.push(util.revHex(hash));
  }

  return out;
});

RPC.prototype.getTXOutSetInfo = co(function* getTXOutSetInfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'gettxoutsetinfo');

  if (this.chain.options.spv)
    throw new RPCError(errs.MISC_ERROR, 'Chainstate not available (SPV mode).');

  return {
    height: this.chain.height,
    bestblock: this.chain.tip.rhash(),
    transactions: this.chain.db.state.tx,
    txouts: this.chain.db.state.coin,
    bytes_serialized: 0,
    hash_serialized: 0,
    total_amount: Amount.btc(this.chain.db.state.value, true)
  };
});

RPC.prototype.verifyChain = co(function* verifyChain(args, help) {
  var valid = new Validator([args]);
  var level = valid.u32(0);
  var blocks = valid.u32(1);

  if (help || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'verifychain ( checklevel numblocks )');

  if (level == null || blocks == null)
    throw new RPCError(errs.TYPE_ERROR, 'Missing parameters.');

  if (this.chain.options.spv)
    throw new RPCError(errs.MISC_ERROR, 'Cannot verify chain in SPV mode.');

  if (this.chain.options.prune)
    throw new RPCError(errs.MISC_ERROR, 'Cannot verify chain when pruned.');

  return null;
});

/*
 * Mining
 */

RPC.prototype.submitWork = co(function* submitWork(data) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._submitWork(data);
  } finally {
    unlock();
  }
});

RPC.prototype._submitWork = co(function* _submitWork(data) {
  var attempt = this.attempt;
  var header, nonce, ts, nonces;
  var n1, n2, proof, block, entry;

  if (!attempt)
    return false;

  if (data.length !== 128)
    throw new RPCError(errs.INVALID_PARAMETER, 'Invalid work size.');

  header = Headers.fromAbbr(data);

  data = data.slice(0, 80);
  data = swap32(data);

  if (header.prevBlock !== attempt.prevBlock
      || header.bits !== attempt.bits) {
    return false;
  }

  if (!header.verify())
    return false;

  nonces = this.merkleMap[header.merkleRoot];

  if (!nonces)
    return false;

  n1 = nonces.nonce1;
  n2 = nonces.nonce2;
  nonce = header.nonce;
  ts = header.ts;

  proof = attempt.getProof(n1, n2, ts, nonce);

  if (!proof.verify(attempt.target))
    return false;

  block = attempt.commit(proof);

  try {
    entry = yield this.chain.add(block);
  } catch (err) {
    if (err.type === 'VerifyError') {
      this.logger.warning('RPC block rejected: %s (%s).',
        block.rhash(), err.reason);
      return false;
    }
    throw err;
  }

  if (!entry) {
    this.logger.warning('RPC block rejected: %s (bad-prevblk).',
      block.rhash());
    return false;
  }

  return true;
});

RPC.prototype.createWork = co(function* createWork(data) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._createWork(data);
  } finally {
    unlock();
  }
});

RPC.prototype._createWork = co(function* _createWork() {
  var attempt = yield this.updateWork();
  var n1 = this.nonce1;
  var n2 = this.nonce2;
  var ts = attempt.ts;
  var data, root, head;

  data = new Buffer(128);
  data.fill(0);

  root = attempt.getRoot(n1, n2);
  head = attempt.getHeader(root, ts, 0);

  head.copy(data, 0);

  data[80] = 0x80;
  data.writeUInt32BE(80 * 8, data.length - 4, true);

  data = swap32(data);

  return {
    data: data.toString('hex'),
    target: attempt.target.toString('hex'),
    height: attempt.height
  };
});

RPC.prototype.getWorkLongpoll = co(function* getWorkLongpoll(args, help) {
  yield this.longpoll();
  return yield this.createWork();
});

RPC.prototype.getWork = co(function* getWork(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);

  if (args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'getwork ( "data" )');

  if (args.length === 1) {
    if (!data)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid work data.');

    return yield this.submitWork(data);
  }

  return yield this.createWork();
});

RPC.prototype.submitBlock = co(function* submitBlock(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var block;

  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'submitblock "hexdata" ( "jsonparametersobject" )');
  }

  block = Block.fromRaw(data);

  return yield this.addBlock(block);
});

RPC.prototype.getBlockTemplate = co(function* getBlockTemplate(args, help) {
  var validator = new Validator([args]);
  var options = validator.obj(0, {});
  var valid = new Validator([options]);
  var mode = valid.str('mode', 'template');
  var lpid = valid.str('longpollid');
  var data = valid.buf('data');
  var rules = valid.array('rules');
  var capabilities = valid.array('capabilities');
  var maxVersion = valid.u32('maxversion', -1);
  var coinbase = false;
  var txnCap = false;
  var valueCap = false;
  var i, capability, block;

  if (help || args.length > 1) {
    throw new RPCError(errs.MISC_ERROR,
      'getblocktemplate ( "jsonrequestobject" )');
  }

  if (mode !== 'template' && mode !== 'proposal')
    throw new RPCError(errs.INVALID_PARAMETER, 'Invalid mode.');

  if (mode === 'proposal') {
    if (!data)
      throw new RPCError(errs.TYPE_ERROR, 'Missing data parameter.');

    block = Block.fromRaw(data);

    if (block.prevBlock !== this.chain.tip.hash)
      return 'inconclusive-not-best-prevblk';

    try {
      yield this.chain.verifyBlock(block);
    } catch (e) {
      if (e.type === 'VerifyError')
        return e.reason;
      throw e;
    }

    return null;
  }

  if (rules)
    maxVersion = -1;

  if (capabilities) {
    for (i = 0; i < capabilities.length; i++) {
      capability = capabilities[i];

      if (typeof capability !== 'string')
        throw new RPCError(errs.TYPE_ERROR, 'Invalid capability.');

      switch (capability) {
        case 'coinbasetxn':
          txnCap = true;
          break;
        case 'coinbasevalue':
          // Prefer value if they support it.
          valueCap = true;
          break;
      }
    }

    // BIP22 states that we can't have coinbasetxn
    // _and_ coinbasevalue in the same template.
    // The problem is, many clients _say_ they
    // support coinbasetxn when they don't (ckpool).
    // To make matters worse, some clients will
    // parse an undefined `coinbasevalue` as zero.
    // Because of all of this, coinbasetxn is
    // disabled for now.
    valueCap = true;

    if (txnCap && !valueCap) {
      if (this.miner.addresses.length === 0) {
        throw new RPCError(errs.MISC_ERROR,
          'No addresses available for coinbase.');
      }
      coinbase = true;
    }
  }

  if (!this.network.selfConnect) {
    if (this.pool.peers.size() === 0) {
      throw new RPCError(errs.CLIENT_NOT_CONNECTED,
        'Bitcoin is not connected!');
    }

    if (!this.chain.synced) {
      throw new RPCError(errs.CLIENT_IN_INITIAL_DOWNLOAD,
        'Bitcoin is downloading blocks...');
    }
  }

  if (lpid)
    yield this.handleLongpoll(lpid);

  return yield this.createTemplate(maxVersion, coinbase, rules);
});

RPC.prototype.createTemplate = co(function* createTemplate(maxVersion, coinbase, rules) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._createTemplate(maxVersion, coinbase, rules);
  } finally {
    unlock();
  }
});

RPC.prototype._createTemplate = co(function* _createTemplate(maxVersion, coinbase, rules) {
  var attempt = yield this.getTemplate();
  var version = attempt.version;
  var scale = attempt.witness ? 1 : consensus.WITNESS_SCALE_FACTOR;
  var mutable = ['time', 'transactions', 'prevblock'];
  var txs = [];
  var index = {};
  var vbavailable = {};
  var vbrules = [];
  var i, j, entry, tx, input, output;
  var dep, deps, json, name, deploy;
  var state;

  // The miner doesn't support
  // versionbits. Force them to
  // encode our version.
  if (maxVersion >= 2)
    mutable.push('version/force');

  // Allow the miner to change
  // our provided coinbase.
  // Note that these are implied
  // without `coinbasetxn`.
  if (coinbase) {
    mutable.push('coinbase');
    mutable.push('coinbase/append');
    mutable.push('generation');
  }

  // Build an index of every transaction.
  for (i = 0; i < attempt.items.length; i++) {
    entry = attempt.items[i];
    index[entry.hash] = i + 1;
  }

  // Calculate dependencies for each transaction.
  for (i = 0; i < attempt.items.length; i++) {
    entry = attempt.items[i];
    tx = entry.tx;
    deps = [];

    for (j = 0; j < tx.inputs.length; j++) {
      input = tx.inputs[j];
      dep = index[input.prevout.hash];

      if (dep == null)
        continue;

      if (deps.indexOf(dep) === -1) {
        assert(dep < i + 1);
        deps.push(dep);
      }
    }

    txs.push({
      data: tx.toRaw().toString('hex'),
      txid: tx.txid(),
      hash: tx.wtxid(),
      depends: deps,
      fee: entry.fee,
      sigops: entry.sigops / scale | 0,
      weight: tx.getWeight()
    });
  }

  // Calculate version based on given rules.
  for (i = 0; i < this.network.deploys.length; i++) {
    deploy = this.network.deploys[i];
    state = yield this.chain.getState(this.chain.tip, deploy);
    name = deploy.name;

    switch (state) {
      case common.thresholdStates.DEFINED:
      case common.thresholdStates.FAILED:
        break;
      case common.thresholdStates.LOCKED_IN:
        version |= 1 << deploy.bit;
      case common.thresholdStates.STARTED:
        if (!deploy.force) {
          if (!rules || rules.indexOf(name) === -1)
            version &= ~(1 << deploy.bit);
          name = '!' + name;
        }
        vbavailable[name] = deploy.bit;
        break;
      case common.thresholdStates.ACTIVE:
        if (!deploy.force) {
          if (!rules || rules.indexOf(name) === -1) {
            throw new RPCError(errs.INVALID_PARAMETER,
              'Client must support ' + name + '.');
          }
          name = '!' + name;
        }
        vbrules.push(name);
        break;
      default:
        assert(false, 'Bad state.');
        break;
    }
  }

  version >>>= 0;

  json = {
    capabilities: ['proposal'],
    mutable: mutable,
    version: version,
    rules: vbrules,
    vbavailable: vbavailable,
    vbrequired: 0,
    height: attempt.height,
    previousblockhash: util.revHex(attempt.prevBlock),
    target: util.revHex(attempt.target.toString('hex')),
    bits: util.hex32(attempt.bits),
    noncerange: '00000000ffffffff',
    curtime: attempt.ts,
    mintime: attempt.mtp + 1,
    maxtime: attempt.ts + 7200,
    expires: attempt.ts + 7200,
    sigoplimit: consensus.MAX_BLOCK_SIGOPS_COST / scale | 0,
    sizelimit: consensus.MAX_BLOCK_SIZE,
    weightlimit: undefined,
    longpollid: this.chain.tip.rhash() + util.pad32(this.totalTX()),
    submitold: false,
    coinbaseaux: {
      flags: attempt.coinbaseFlags.toString('hex')
    },
    coinbasevalue: undefined,
    coinbasetxn: undefined,
    default_witness_commitment: undefined,
    transactions: txs
  };

  // See:
  // bitcoin/bitcoin#9fc7f0bce94f1cea0239b1543227f22a3f3b9274
  if (attempt.witness) {
    json.sizelimit = consensus.MAX_RAW_BLOCK_SIZE;
    json.weightlimit = consensus.MAX_BLOCK_WEIGHT;
  }

  // The client wants a coinbasetxn
  // instead of a coinbasevalue.
  if (coinbase) {
    tx = attempt.toCoinbase();

    // Pop off the nonces.
    tx.inputs[0].script.code.pop();
    tx.inputs[0].script.compile();

    if (attempt.witness) {
      // We don't include the commitment
      // output (see bip145).
      output = tx.outputs.pop();
      assert(output.script.isCommitment());

      // Also not including the witness nonce.
      tx.inputs[0].witness.length = 0;
      tx.inputs[0].witness.compile();

      tx.refresh();
    }

    json.coinbasetxn = {
      data: tx.toRaw().toString('hex'),
      txid: tx.txid(),
      hash: tx.wtxid(),
      depends: [],
      fee: 0,
      sigops: tx.getSigopsCost() / scale | 0,
      weight: tx.getWeight()
    };
  } else {
    json.coinbasevalue = attempt.getReward();
  }

  if (rules && rules.indexOf('segwit') !== -1)
    json.default_witness_commitment = attempt.getWitnessScript().toJSON();

  return json;
});

RPC.prototype.getMiningInfo = co(function* getMiningInfo(args, help) {
  var attempt = this.attempt;
  var size = 0;
  var weight = 0;
  var txs = 0;
  var diff = 0;
  var i, item;

  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getmininginfo');

  if (attempt) {
    weight = attempt.weight;
    txs = attempt.items.length + 1;
    diff = attempt.getDifficulty();
    size = 1000;
    for (i = 0; i < attempt.items.length; i++) {
      item = attempt.items[i];
      size += item.tx.getBaseSize();
    }
  }

  return {
    blocks: this.chain.height,
    currentblocksize: size,
    currentblockweight: weight,
    currentblocktx: txs,
    difficulty: diff,
    errors: '',
    genproclimit: this.procLimit,
    networkhashps: yield this.getHashRate(120),
    pooledtx: this.totalTX(),
    testnet: this.network !== Network.main,
    chain: this.network.type !== 'testnet'
      ? this.network.type
      : 'test',
    generate: this.mining
  };
});

RPC.prototype.getNetworkHashPS = co(function* getNetworkHashPS(args, help) {
  var valid = new Validator([args]);
  var lookup = valid.u32(0, 120);
  var height = valid.u32(1);

  if (help || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'getnetworkhashps ( blocks height )');

  return yield this.getHashRate(lookup, height);
});

RPC.prototype.prioritiseTransaction = co(function* prioritiseTransaction(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var pri = valid.num(1);
  var fee = valid.i64(2);
  var entry;

  if (help || args.length !== 3) {
    throw new RPCError(errs.MISC_ERROR,
      'prioritisetransaction <txid> <priority delta> <fee delta>');
  }

  if (!this.mempool)
    throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID');

  if (pri == null || fee == null)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid fee or priority.');

  entry = this.mempool.getEntry(hash);

  if (!entry)
    throw new RPCError(errs.MISC_ERROR, 'Transaction not in mempool.');

  this.mempool.prioritise(entry, pri, fee);

  return true;
});

RPC.prototype.verifyBlock = co(function* verifyBlock(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var block;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'verifyblock "block-hex"');

  if (!data)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid block hex.');

  if (this.chain.options.spv)
    throw new RPCError(errs.MISC_ERROR, 'Cannot verify block in SPV mode.');

  block = Block.fromRaw(data);

  try {
    yield this.chain.verifyBlock(block);
  } catch (e) {
    if (e.type === 'VerifyError')
      return e.reason;
    throw e;
  }

  return null;
});

/*
 * Coin generation
 */

RPC.prototype.getGenerate = co(function* getGenerate(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getgenerate');
  return this.mining;
});

RPC.prototype.setGenerate = co(function* setGenerate(args, help) {
  var valid = new Validator([args]);
  var mine = valid.bool(0, false);
  var limit = valid.u32(1, 0);

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'setgenerate mine ( proclimit )');

  this.mining = mine;
  this.procLimit = limit;

  if (mine) {
    this.miner.cpu.start();
    return true;
  }

  yield this.miner.cpu.stop();

  return false;
});

RPC.prototype.generate = co(function* generate(args, help) {
  var valid = new Validator([args]);
  var blocks = valid.u32(0, 1);
  var tries = valid.u32(1);

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'generate numblocks ( maxtries )');

  return yield this.mineBlocks(blocks, null, tries);
});

RPC.prototype.generateToAddress = co(function* _generateToAddress(args, help) {
  var valid = new Validator([args]);
  var blocks = valid.u32(0, 1);
  var addr = valid.str(1, '');
  var tries = valid.u32(2);

  if (help || args.length < 2 || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'generatetoaddress numblocks address ( maxtries )');
  }

  addr = parseAddress(addr, this.network);

  return yield this.mineBlocks(blocks, addr, tries);
});

/*
 * Raw transactions
 */

RPC.prototype.createRawTransaction = co(function* createRawTransaction(args, help) {
  var valid = new Validator([args]);
  var inputs = valid.array(0);
  var sendTo = valid.obj(1);
  var locktime = valid.u32(2);
  var i, tx, input, output, hash, index, sequence;
  var keys, addrs, key, value, address, b58;

  if (help || args.length < 2 || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'createrawtransaction'
      + ' [{"txid":"id","vout":n},...]'
      + ' {"address":amount,"data":"hex",...}'
      + ' ( locktime )');
  }

  if (!inputs || !sendTo) {
    throw new RPCError(errs.TYPE_ERROR,
      'Invalid parameters (inputs and sendTo).');
  }

  tx = new MTX();

  if (locktime != null)
    tx.locktime = locktime;

  for (i = 0; i < inputs.length; i++) {
    input = inputs[i];
    valid = new Validator([input]);

    hash = valid.hash('txid');
    index = valid.u32('vout');
    sequence = valid.u32('sequence', 0xffffffff);

    if (tx.locktime)
      sequence--;

    if (!hash || index == null)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid outpoint.');

    input = new Input();
    input.prevout.hash = hash;
    input.prevout.index = index;
    input.sequence = sequence;

    tx.inputs.push(input);
  }

  keys = Object.keys(sendTo);
  valid = new Validator([sendTo]);
  addrs = {};

  for (i = 0; i < keys.length; i++) {
    key = keys[i];

    if (key === 'data') {
      value = valid.buf(key);

      if (!value)
        throw new RPCError(errs.TYPE_ERROR, 'Invalid nulldata..');

      output = new Output();
      output.value = 0;
      output.script.fromNulldata(value);
      tx.outputs.push(output);

      continue;
    }

    address = parseAddress(key, this.network);
    b58 = address.toBase58(this.network);

    if (addrs[b58])
      throw new RPCError(errs.INVALID_PARAMETER, 'Duplicate address');

    addrs[b58] = true;

    value = valid.btc(key);

    if (value == null)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid output value.');

    output = new Output();
    output.value = value;
    output.script.fromAddress(address);

    tx.outputs.push(output);
  }

  return tx.toRaw().toString('hex');
});

RPC.prototype.decodeRawTransaction = co(function* decodeRawTransaction(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var tx;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'decoderawtransaction "hexstring"');

  if (!data)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid hex string.');

  tx = TX.fromRaw(data);

  return this.txToJSON(tx);
});

RPC.prototype.decodeScript = co(function* decodeScript(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var script, address;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'decodescript "hex"');

  script = new Script();

  if (data)
    script = Script.fromRaw(data);

  address = Address.fromScripthash(script.hash160());

  script = this.scriptToJSON(script);
  script.p2sh = address.toBase58(this.network);

  return script;
});

RPC.prototype.getRawTransaction = co(function* getRawTransaction(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var verbose = valid.bool(1, false);
  var json, meta, tx, entry;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'getrawtransaction "txid" ( verbose )');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID.');

  meta = yield this.node.getMeta(hash);

  if (!meta)
    throw new RPCError(errs.MISC_ERROR, 'Transaction not found.');

  tx = meta.tx;

  if (!verbose)
    return tx.toRaw().toString('hex');

  if (meta.block)
    entry = yield this.chain.db.getEntry(meta.block);

  json = this.txToJSON(tx, entry);
  json.time = meta.ps;
  json.hex = tx.toRaw().toString('hex');

  return json;
});

RPC.prototype.sendRawTransaction = co(function* sendRawTransaction(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var tx;

  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'sendrawtransaction "hexstring" ( allowhighfees )');
  }

  if (!data)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid hex string.');

  tx = TX.fromRaw(data);

  this.node.relay(tx);

  return tx.txid();
});

RPC.prototype.signRawTransaction = co(function* signRawTransaction(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var prevout = valid.array(1);
  var secrets = valid.array(2);
  var sighash = valid.str(3);
  var type = Script.hashType.ALL;
  var keys = [];
  var map = {};
  var i, j, tx, secret, key, coin;
  var hash, index, script, value;
  var prev, redeem, op, parts;

  if (help || args.length < 1 || args.length > 4) {
    throw new RPCError(errs.MISC_ERROR,
      'signrawtransaction'
      + ' "hexstring" ('
      + ' [{"txid":"id","vout":n,"scriptPubKey":"hex",'
      + 'redeemScript":"hex"},...] ["privatekey1",...]'
      + ' sighashtype )');
  }

  if (!data)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid hex string.');

  if (!this.mempool)
    throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

  tx = MTX.fromRaw(data);
  tx.view = yield this.mempool.getSpentView(tx);

  if (secrets) {
    valid = new Validator([secrets]);
    for (i = 0; i < secrets.length; i++) {
      secret = valid.str(i, '');
      key = parseSecret(secret, this.network);
      map[key.getPublicKey('hex')] = key;
      keys.push(key);
    }
  }

  if (prevout) {
    for (i = 0; i < prevout.length; i++) {
      prev = prevout[i];
      valid = new Validator([prev]);
      hash = valid.hash('txid');
      index = valid.u32('index');
      script = valid.buf('scriptPubKey');
      value = valid.btc('amount');
      redeem = valid.buf('redeemScript');

      if (!hash || index == null || !script || value == null)
        throw new RPCError(errs.INVALID_PARAMETER, 'Invalid UTXO.');

      script = Script.fromRaw(script);

      coin = new Output();
      coin.script = script;
      coin.value = value;

      tx.view.addOutput(hash, index, coin);

      if (keys.length === 0 || !redeem)
        continue;

      if (!script.isScripthash() && !script.isWitnessScripthash())
        continue;

      if (!redeem) {
        throw new RPCError(errs.INVALID_PARAMETER,
          'P2SH requires redeem script.');
      }

      redeem = Script.fromRaw(redeem);

      for (j = 0; j < redeem.code.length; j++) {
        op = redeem.code[j];

        if (!op.data)
          continue;

        key = map[op.data.toString('hex')];

        if (key) {
          key.script = redeem;
          key.witness = script.isWitnessScripthash();
          key.refresh();
          break;
        }
      }
    }
  }

  if (sighash) {
    parts = sighash.split('|');
    type = Script.hashType[parts[0]];

    if (type == null)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid sighash type.');

    if (parts.length > 2)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid sighash type.');

    if (parts.length === 2) {
      if (parts[1] !== 'ANYONECANPAY')
        throw new RPCError(errs.INVALID_PARAMETER, 'Invalid sighash type.');
      type |= Script.hashType.ANYONECANPAY;
    }
  }

  yield tx.signAsync(keys, type);

  return {
    hex: tx.toRaw().toString('hex'),
    complete: tx.isSigned()
  };
});

/*
 * Utility Functions
 */

RPC.prototype.createMultisig = co(function* createMultisig(args, help) {
  var valid = new Validator([args]);
  var keys = valid.array(1, []);
  var m = valid.u32(0, 0);
  var n = keys.length;
  var i, script, key, address;

  if (help || args.length < 2 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'createmultisig nrequired ["key",...]');

  if (m < 1 || n < m || n > 16)
    throw new RPCError(errs.INVALID_PARAMETER, 'Invalid m and n values.');

  valid = new Validator([keys]);

  for (i = 0; i < keys.length; i++) {
    key = valid.buf(i);

    if (!key)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid key.');

    if (!ec.publicKeyVerify(key))
      throw new RPCError(errs.INVALID_ADDRESS_OR_KEY, 'Invalid key.');

    keys[i] = key;
  }

  script = Script.fromMultisig(m, n, keys);

  if (script.getSize() > consensus.MAX_SCRIPT_PUSH)
    throw new RPCError(errs.VERIFY_ERROR, 'Redeem script exceeds size limit.');

  address = script.getAddress();

  return {
    address: address.toBase58(this.network),
    redeemScript: script.toJSON()
  };
});

RPC.prototype.createWitnessAddress = co(function* createWitnessAddress(args, help) {
  var valid = new Validator([args]);
  var raw = valid.buf(0);
  var script, program, address;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'createwitnessaddress "script"');

  if (!raw)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid script hex.');

  script = Script.fromRaw(raw);
  program = script.forWitness();
  address = program.getAddress();

  return {
    address: address.toBase58(this.network),
    witnessScript: program.toJSON()
  };
});

RPC.prototype.validateAddress = co(function* validateAddress(args, help) {
  var valid = new Validator([args]);
  var b58 = valid.str(0, '');
  var address, script;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'validateaddress "bitcoinaddress"');

  try {
    address = Address.fromBase58(b58, this.network);
  } catch (e) {
    return {
      isvalid: false
    };
  }

  script = Script.fromAddress(address);

  return {
    isvalid: true,
    address: address.toBase58(this.network),
    scriptPubKey: script.toJSON(),
    ismine: false,
    iswatchonly: false
  };
});

RPC.prototype.verifyMessage = co(function* verifyMessage(args, help) {
  var valid = new Validator([args]);
  var b58 = valid.str(0, '');
  var sig = valid.buf(1, null, 'base64');
  var msg = valid.str(2);
  var hash = Address.getHash(b58);
  var key;

  if (help || args.length !== 3) {
    throw new RPCError(errs.MISC_ERROR,
      'verifymessage "bitcoinaddress" "signature" "message"');
  }

  if (!hash || !sig || !msg)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameters.');

  msg = new Buffer(MAGIC_STRING + msg, 'utf8');
  msg = crypto.hash256(msg);

  key = ec.recover(msg, sig, 0, true);

  if (!key)
    return false;

  key = crypto.hash160(key);

  return crypto.ccmp(key, hash);
});

RPC.prototype.signMessageWithPrivkey = co(function* signMessageWithPrivkey(args, help) {
  var valid = new Validator([args]);
  var key = valid.str(0, '');
  var msg = valid.str(1, '');
  var sig;

  if (help || args.length !== 2) {
    throw new RPCError(errs.MISC_ERROR,
      'signmessagewithprivkey "privkey" "message"');
  }

  key = parseSecret(key, this.network);
  msg = new Buffer(MAGIC_STRING + msg, 'utf8');
  msg = crypto.hash256(msg);

  sig = key.sign(msg);

  return sig.toString('base64');
});

RPC.prototype.estimateFee = co(function* estimateFee(args, help) {
  var valid = new Validator([args]);
  var blocks = valid.u32(0, 1);
  var fee;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'estimatefee nblocks');

  if (!this.fees)
    throw new RPCError(errs.MISC_ERROR, 'Fee estimation not available.');

  if (blocks < 1)
    blocks = 1;

  fee = this.fees.estimateFee(blocks, false);

  if (fee === 0)
    return -1;

  return Amount.btc(fee, true);
});

RPC.prototype.estimatePriority = co(function* estimatePriority(args, help) {
  var valid = new Validator([args]);
  var blocks = valid.u32(0, 1);

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'estimatepriority nblocks');

  if (!this.fees)
    throw new RPCError(errs.MISC_ERROR, 'Priority estimation not available.');

  if (blocks < 1)
    blocks = 1;

  return this.fees.estimatePriority(blocks, false);
});

RPC.prototype.estimateSmartFee = co(function* estimateSmartFee(args, help) {
  var valid = new Validator([args]);
  var blocks = valid.u32(0, 1);
  var fee;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'estimatesmartfee nblocks');

  if (!this.fees)
    throw new RPCError(errs.MISC_ERROR, 'Fee estimation not available.');

  if (blocks < 1)
    blocks = 1;

  fee = this.fees.estimateFee(blocks, true);

  if (fee === 0)
    fee = -1;
  else
    fee = Amount.btc(fee, true);

  return {
    fee: fee,
    blocks: blocks
  };
});

RPC.prototype.estimateSmartPriority = co(function* estimateSmartPriority(args, help) {
  var valid = new Validator([args]);
  var blocks = valid.u32(0, 1);
  var pri;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'estimatesmartpriority nblocks');

  if (!this.fees)
    throw new RPCError(errs.MISC_ERROR, 'Priority estimation not available.');

  if (blocks < 1)
    blocks = 1;

  pri = this.fees.estimatePriority(blocks, true);

  return {
    priority: pri,
    blocks: blocks
  };
});

RPC.prototype.invalidateBlock = co(function* invalidateBlock(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'invalidateblock "hash"');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid block hash.');

  yield this.chain.invalidate(hash);

  return null;
});

RPC.prototype.reconsiderBlock = co(function* reconsiderBlock(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'reconsiderblock "hash"');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid block hash.');

  this.chain.removeInvalid(hash);

  return null;
});

RPC.prototype.setMockTime = co(function* setMockTime(args, help) {
  var valid = new Validator([args]);
  var ts = valid.u32(0);
  var delta;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'setmocktime timestamp');

  if (ts == null)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid timestamp.');

  this.network.time.offset = 0;

  delta = this.network.now() - ts;

  this.network.time.offset = -delta;

  return null;
});

RPC.prototype.getMemoryInfo = co(function* getMemoryInfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getmemoryinfo');

  return util.memoryUsage();
});

RPC.prototype.setLogLevel = co(function* setLogLevel(args, help) {
  var valid = new Validator([args]);
  var level = valid.str(0, '');

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'setloglevel "level"');

  this.logger.setLevel(level);

  return null;
});

/*
 * Helpers
 */

RPC.prototype.handleLongpoll = co(function* handleLongpoll(lpid) {
  var watched, lastTX;

  if (lpid.length !== 74)
    throw new RPCError(errs.INVALID_PARAMETER, 'Invalid longpoll ID.');

  watched = lpid.slice(0, 64);
  lastTX = +lpid.slice(64, 74);

  if (!util.isHex(watched) || !util.isNumber(lastTX) || lastTX < 0)
    throw new RPCError(errs.INVALID_PARAMETER, 'Invalid longpoll ID.');

  watched = util.revHex(watched);

  if (this.chain.tip.hash !== watched)
    return;

  yield this.longpoll();
});

RPC.prototype.longpoll = function longpoll() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.pollers.push(co.job(resolve, reject));
  });
};

RPC.prototype.refreshBlock = function refreshBlock() {
  var pollers = this.pollers;
  var i, job;

  this.attempt = null;
  this.lastActivity = 0;
  this.merkleMap = {};
  this.nonce1 = 0;
  this.nonce2 = 0;
  this.pollers = [];

  for (i = 0; i < pollers.length; i++) {
    job = pollers[i];
    job.resolve();
  }
};

RPC.prototype.bindChain = function bindChain() {
  var self = this;

  if (this.boundChain)
    return;

  this.boundChain = true;

  this.node.on('connect', function() {
    if (!self.attempt)
      return;

    self.refreshBlock();
  });

  if (!this.mempool)
    return;

  this.node.on('tx', function() {
    if (!self.attempt)
      return;

    if (util.now() - self.lastActivity > 10)
      self.refreshBlock();
  });
};

RPC.prototype.getTemplate = co(function* getTemplate() {
  var attempt = this.attempt;

  this.bindChain();

  if (attempt) {
    this.miner.updateTime(attempt);
  } else {
    attempt = yield this.miner.createBlock();
    this.attempt = attempt;
    this.lastActivity = util.now();
  }

  return attempt;
});

RPC.prototype.updateWork = co(function* updateWork() {
  var attempt = this.attempt;
  var root, n1, n2;

  this.bindChain();

  if (attempt) {
    if (attempt.address.isNull()) {
      throw new RPCError(errs.MISC_ERROR,
        'No addresses available for coinbase.');
    }

    this.miner.updateTime(attempt);

    if (++this.nonce2 === 0x100000000) {
      this.nonce2 = 0;
      this.nonce1++;
    }

    n1 = this.nonce1;
    n2 = this.nonce2;

    root = attempt.getRoot(n1, n2);
    root = root.toString('hex');

    this.merkleMap[root] = new Nonces(n1, n2);

    return attempt;
  }

  if (this.miner.addresses.length === 0) {
    throw new RPCError(errs.MISC_ERROR,
      'No addresses available for coinbase.');
  }

  attempt = yield this.miner.createBlock();

  n1 = this.nonce1;
  n2 = this.nonce2;

  root = attempt.getRoot(n1, n2);
  root = root.toString('hex');

  this.attempt = attempt;
  this.lastActivity = util.now();
  this.merkleMap[root] = new Nonces(n1, n2);

  return attempt;
});

RPC.prototype.addBlock = co(function* addBlock(block) {
  var unlock1 = yield this.locker.lock();
  var unlock2 = yield this.chain.locker.lock();
  try {
    return yield this._addBlock(block);
  } finally {
    unlock2();
    unlock1();
  }
});

RPC.prototype._addBlock = co(function* _addBlock(block) {
  var entry, prev, state, tx;

  this.logger.info('Handling submitted block: %s.', block.rhash());

  prev = yield this.chain.db.getEntry(block.prevBlock);

  if (prev) {
    state = yield this.chain.getDeployments(block.ts, prev);

    // Fix eloipool bug (witness nonce is not present).
    if (state.hasWitness() && block.getCommitmentHash()) {
      tx = block.txs[0];
      if (!tx.hasWitness()) {
        this.logger.warning('Submitted block had no witness nonce.');
        this.logger.debug(tx);

        // Recreate witness nonce (all zeroes).
        tx.inputs[0].witness.set(0, encoding.ZERO_HASH);
        tx.inputs[0].witness.compile();

        tx.refresh();
        block.refresh();
      }
    }
  }

  try {
    entry = yield this.chain._add(block);
  } catch (err) {
    if (err.type === 'VerifyError') {
      this.logger.warning('RPC block rejected: %s (%s).',
        block.rhash(), err.reason);
      return 'rejected: ' + err.reason;
    }
    throw err;
  }

  if (!entry) {
    this.logger.warning('RPC block rejected: %s (bad-prevblk).',
      block.rhash());
    return 'rejected: bad-prevblk';
  }

  return null;
});

RPC.prototype.totalTX = function totalTX() {
  return this.mempool ? this.mempool.totalTX : 0;
};

RPC.prototype.getSoftforks = function getSoftforks() {
  return [
    toDeployment('bip34', 2, this.chain.state.hasBIP34()),
    toDeployment('bip66', 3, this.chain.state.hasBIP66()),
    toDeployment('bip65', 4, this.chain.state.hasCLTV())
  ];
};

RPC.prototype.getBIP9Softforks = co(function* getBIP9Softforks() {
  var tip = this.chain.tip;
  var forks = {};
  var i, deployment, state, status;

  for (i = 0; i < this.network.deploys.length; i++) {
    deployment = this.network.deploys[i];
    state = yield this.chain.getState(tip, deployment);

    switch (state) {
      case common.thresholdStates.DEFINED:
        status = 'defined';
        break;
      case common.thresholdStates.STARTED:
        status = 'started';
        break;
      case common.thresholdStates.LOCKED_IN:
        status = 'locked_in';
        break;
      case common.thresholdStates.ACTIVE:
        status = 'active';
        break;
      case common.thresholdStates.FAILED:
        status = 'failed';
        break;
      default:
        assert(false, 'Bad state.');
        break;
    }

    forks[deployment.name] = {
      status: status,
      bit: deployment.bit,
      startTime: deployment.startTime,
      timeout: deployment.timeout
    };
  }

  return forks;
});

RPC.prototype.getHashRate = co(function* getHashRate(lookup, height) {
  var tip = this.chain.tip;
  var i, minTime, maxTime, workDiff, timeDiff, ps, entry;

  if (height != null)
    tip = yield this.chain.db.getEntry(height);

  if (!tip)
    return 0;

  if (lookup <= 0)
    lookup = tip.height % this.network.pow.retargetInterval + 1;

  if (lookup > tip.height)
    lookup = tip.height;

  minTime = tip.ts;
  maxTime = minTime;
  entry = tip;

  for (i = 0; i < lookup; i++) {
    entry = yield entry.getPrevious();

    if (!entry)
      throw new RPCError(errs.DATABASE_ERROR, 'Not found.');

    minTime = Math.min(entry.ts, minTime);
    maxTime = Math.max(entry.ts, maxTime);
  }

  if (minTime === maxTime)
    return 0;

  workDiff = tip.chainwork.sub(entry.chainwork);
  timeDiff = maxTime - minTime;
  ps = +workDiff.toString(10) / timeDiff;

  return ps;
});

RPC.prototype.mineBlocks = co(function* mineBlocks(blocks, address, tries) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._mineBlocks(blocks, address, tries);
  } finally {
    unlock();
  }
});

RPC.prototype._mineBlocks = co(function* _mineBlocks(blocks, address, tries) {
  var hashes = [];
  var i, block;

  for (i = 0; i < blocks; i++) {
    block = yield this.miner.mineBlock(null, address);
    hashes.push(block.rhash());
    assert(yield this.chain.add(block));
  }

  return hashes;
});

RPC.prototype.findFork = co(function* findFork(entry) {
  while (entry) {
    if (yield entry.isMainChain())
      return entry;
    entry = yield entry.getPrevious();
  }
  throw new Error('Fork not found.');
});

RPC.prototype.txToJSON = function txToJSON(tx, entry) {
  var height = -1;
  var conf = 0;
  var time = 0;
  var hash = null;
  var vin = [];
  var vout = [];
  var i, input, output, json;

  if (entry) {
    height = entry.height;
    time = entry.ts;
    hash = entry.rhash();
    conf = this.chain.height - height + 1;
  }

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    json = {
      coinbase: undefined,
      txid: undefined,
      scriptSig: undefined,
      txinwitness: undefined,
      sequence: input.sequence
    };

    if (tx.isCoinbase()) {
      json.coinbase = input.script.toJSON();
    } else {
      json.txid = input.prevout.txid();
      json.vout = input.prevout.index;
      json.scriptSig = {
        asm: input.script.toASM(),
        hex: input.script.toJSON()
      };
    }

    if (input.witness.items.length > 0) {
      json.txinwitness = input.witness.items.map(function(item) {
        return item.toString('hex');
      });
    }

    vin.push(json);
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    vout.push({
      value: Amount.btc(output.value, true),
      n: i,
      scriptPubKey: this.scriptToJSON(output.script, true)
    });
  }

  return {
    txid: tx.txid(),
    hash: tx.wtxid(),
    size: tx.getSize(),
    vsize: tx.getVirtualSize(),
    version: tx.version,
    locktime: tx.locktime,
    vin: vin,
    vout: vout,
    blockhash: hash,
    confirmations: conf,
    time: time,
    blocktime: time,
    hex: undefined
  };
};

RPC.prototype.scriptToJSON = function scriptToJSON(script, hex) {
  var type = script.getType();
  var address = script.getAddress();
  var out;

  out = {
    asm: script.toASM(),
    hex: undefined,
    type: Script.typesByVal[type],
    reqSigs: 1,
    addresses: [],
    p2sh: undefined
  };

  if (hex)
    out.hex = script.toJSON();

  if (script.isMultisig())
    out.reqSigs = script.getSmall(0);

  if (address) {
    address = address.toBase58(this.network);
    out.addresses.push(address);
  }

  return out;
};

RPC.prototype.headerToJSON = co(function* headerToJSON(entry) {
  var medianTime = yield entry.getMedianTime();
  var nextHash = yield this.chain.db.getNextHash(entry.hash);

  return {
    hash: entry.rhash(),
    confirmations: this.chain.height - entry.height + 1,
    height: entry.height,
    version: entry.version,
    versionHex: util.hex32(entry.version),
    merkleroot: util.revHex(entry.merkleRoot),
    time: entry.ts,
    mediantime: medianTime,
    bits: entry.bits,
    difficulty: toDifficulty(entry.bits),
    chainwork: entry.chainwork.toString('hex', 64),
    previousblockhash: entry.prevBlock !== encoding.NULL_HASH
      ? util.revHex(entry.prevBlock)
      : null,
    nextblockhash: nextHash ? util.revHex(nextHash) : null
  };
});

RPC.prototype.blockToJSON = co(function* blockToJSON(entry, block, details) {
  var mtp = yield entry.getMedianTime();
  var nextHash = yield this.chain.db.getNextHash(entry.hash);
  var txs = [];
  var i, tx, json;

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];

    if (details) {
      json = this.txToJSON(tx, entry);
      txs.push(json);
      continue;
    }

    txs.push(tx.txid());
  }

  return {
    hash: entry.rhash(),
    confirmations: this.chain.height - entry.height + 1,
    strippedsize: block.getBaseSize(),
    size: block.getSize(),
    weight: block.getWeight(),
    height: entry.height,
    version: entry.version,
    versionHex: util.hex32(entry.version),
    merkleroot: util.revHex(entry.merkleRoot),
    tx: txs,
    time: entry.ts,
    mediantime: mtp,
    bits: entry.bits,
    difficulty: toDifficulty(entry.bits),
    chainwork: entry.chainwork.toString('hex', 64),
    previousblockhash: entry.prevBlock !== encoding.NULL_HASH
      ? util.revHex(entry.prevBlock)
      : null,
    nextblockhash: nextHash ? util.revHex(nextHash) : null
  };
});

RPC.prototype.entryToJSON = function entryToJSON(entry) {
  return {
    size: entry.size,
    fee: Amount.btc(entry.deltaFee, true),
    modifiedfee: 0,
    time: entry.ts,
    height: entry.height,
    startingpriority: entry.priority,
    currentpriority: entry.getPriority(this.chain.height),
    descendantcount: this.mempool.countDescendants(entry),
    descendantsize: entry.descSize,
    descendantfees: entry.descFee,
    ancestorcount: this.mempool.countAncestors(entry),
    ancestorsize: 0,
    ancestorfees: 0,
    depends: this.mempool.getDepends(entry.tx).map(util.revHex)
  };
};

/*
 * Helpers
 */

function swap32(data) {
  var i, field;
  for (i = 0; i < data.length; i += 4) {
    field = data.readUInt32LE(i, true);
    data.writeUInt32BE(field, i, true);
  }
  return data;
}

function toAddedNode(peer) {
  return {
    addednode: peer.hostname(),
    connected: peer.connected,
    addresses: [
      {
        address: peer.hostname(),
        connected: peer.outbound
          ? 'outbound'
          : 'inbound'
      }
    ]
  };
}

function toDeployment(id, version, status) {
  return {
    id: id,
    version: version,
    reject: {
      status: status
    }
  };
}

function Nonces(n1, n2) {
  this.nonce1 = n1;
  this.nonce2 = n2;
}

function parseAddress(raw, network) {
  try {
    return Address.fromBase58(raw, network);
  } catch (e) {
    throw new RPCError(errs.INVALID_ADDRESS_OR_KEY, 'Invalid address.');
  }
}

function parseSecret(raw, network) {
  try {
    return KeyRing.fromSecret(raw, network);
  } catch (e) {
    throw new RPCError(errs.INVALID_ADDRESS_OR_KEY, 'Invalid key.');
  }
}

function toDifficulty(bits) {
  var shift = (bits >>> 24) & 0xff;
  var diff = 0x0000ffff / (bits & 0x00ffffff);

  while (shift < 29) {
    diff *= 256.0;
    shift++;
  }

  while (shift > 29) {
    diff /= 256.0;
    shift--;
  }

  return diff;
}

/*
 * Expose
 */

module.exports = RPC;
