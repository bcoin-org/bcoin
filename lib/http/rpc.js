/*!
 * rpc.js - bitcoind-compatible json rpc for bcoin.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const co = require('../utils/co');
const digest = require('../crypto/digest');
const ccmp = require('../crypto/ccmp');
const common = require('../blockchain/common');
const secp256k1 = require('../crypto/secp256k1');
const Amount = require('../btc/amount');
const NetAddress = require('../primitives/netaddress');
const Script = require('../script/script');
const Address = require('../primitives/address');
const Block = require('../primitives/block');
const Headers = require('../primitives/headers');
const Input = require('../primitives/input');
const KeyRing = require('../primitives/keyring');
const MerkleBlock = require('../primitives/merkleblock');
const MTX = require('../primitives/mtx');
const Network = require('../protocol/network');
const Output = require('../primitives/output');
const TX = require('../primitives/tx');
const IP = require('../utils/ip');
const encoding = require('../utils/encoding');
const consensus = require('../protocol/consensus');
const Validator = require('../utils/validator');
const RPCBase = require('./rpcbase');
const pkg = require('../pkg');
const RPCError = RPCBase.RPCError;
const errs = RPCBase.errors;
const MAGIC_STRING = RPCBase.MAGIC_STRING;

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
  this.workers = node.workers;
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
  this.merkleMap = new Map();
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
  this.add('getblockbyheight', this.getBlockByHeight);
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
  this.add('pruneblockchain', this.pruneBlockchain);
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

RPC.prototype.getInfo = async function getInfo(args, help) {
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
};

RPC.prototype.help = async function _help(args, help) {
  let json;

  if (args.length === 0)
    return 'Select a command.';

  json = {
    method: args[0],
    params: []
  };

  return await this.execute(json, true);
};

RPC.prototype.stop = async function stop(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'stop');

  this.node.close().catch(() => {});

  return 'Stopping.';
};

/*
 * P2P networking
 */

RPC.prototype.getNetworkInfo = async function getNetworkInfo(args, help) {
  let hosts = this.pool.hosts;
  let locals = [];

  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getnetworkinfo');

  for (let local of hosts.local.values()) {
    locals.push({
      address: local.addr.host,
      port: local.addr.port,
      score: local.score
    });
  }

  return {
    version: pkg.version,
    subversion: this.pool.options.agent,
    protocolversion: this.pool.options.version,
    localservices: util.hex32(this.pool.options.services),
    localrelay: !this.pool.options.noRelay,
    timeoffset: this.network.time.offset,
    networkactive: this.pool.connected,
    connections: this.pool.peers.size(),
    networks: [],
    relayfee: Amount.btc(this.network.minRelay, true),
    incrementalfee: 0,
    localaddresses: locals,
    warnings: ''
  };
};

RPC.prototype.addNode = async function addNode(args, help) {
  let valid = new Validator([args]);
  let node = valid.str(0, '');
  let cmd = valid.str(1, '');

  if (help || args.length !== 2)
    throw new RPCError(errs.MISC_ERROR, 'addnode "node" "add|remove|onetry"');

  switch (cmd) {
    case 'add': {
      this.pool.hosts.addNode(node);
      ; // fall through
    }
    case 'onetry': {
      let addr = parseNetAddress(node, this.network);

      if (!this.pool.peers.get(addr.hostname)) {
        let peer = this.pool.createOutbound(addr);
        this.pool.peers.add(peer);
      }

      break;
    }
    case 'remove': {
      this.pool.hosts.removeNode(node);
      break;
    }
  }

  return null;
};

RPC.prototype.disconnectNode = async function disconnectNode(args, help) {
  let valid = new Validator([args]);
  let addr = valid.str(0, '');
  let peer;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'disconnectnode "node"');

  addr = parseIP(addr, this.network);
  peer = this.pool.peers.get(addr.hostname);

  if (peer)
    peer.destroy();

  return null;
};

RPC.prototype.getAddedNodeInfo = async function getAddedNodeInfo(args, help) {
  let hosts = this.pool.hosts;
  let valid = new Validator([args]);
  let addr = valid.str(0, '');
  let result = [];
  let target;

  if (help || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'getaddednodeinfo ( "node" )');

  if (args.length === 1)
    target = parseIP(addr, this.network);

  for (let node of hosts.nodes) {
    let peer;

    if (target) {
      if (node.host !== target.host)
        continue;

      if (node.port !== target.port)
        continue;
    }

    peer = this.pool.peers.get(node.hostname);

    if (!peer || !peer.connected) {
      result.push({
        addednode: node.hostname,
        connected: false,
        addresses: []
      });
      continue;
    }

    result.push({
      addednode: node.hostname,
      connected: peer.connected,
      addresses: [
        {
          address: peer.hostname(),
          connected: peer.outbound
            ? 'outbound'
            : 'inbound'
        }
      ]
    });
  }

  if (target && result.length === 0) {
    throw new RPCError(errs.CLIENT_NODE_NOT_ADDED,
      'Node has not been added.');
  }

  return result;
};

RPC.prototype.getConnectionCount = async function getConnectionCount(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getconnectioncount');

  return this.pool.peers.size();
};

RPC.prototype.getNetTotals = async function getNetTotals(args, help) {
  let sent = 0;
  let recv = 0;

  if (help || args.length > 0)
    throw new RPCError(errs.MISC_ERROR, 'getnettotals');

  for (let peer = this.pool.peers.head(); peer; peer = peer.next) {
    sent += peer.socket.bytesWritten;
    recv += peer.socket.bytesRead;
  }

  return {
    totalbytesrecv: recv,
    totalbytessent: sent,
    timemillis: util.ms()
  };
};

RPC.prototype.getPeerInfo = async function getPeerInfo(args, help) {
  let peers = [];

  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getpeerinfo');

  for (let peer = this.pool.peers.head(); peer; peer = peer.next) {
    let offset = this.network.time.known.get(peer.hostname());
    let hashes = [];

    if (offset == null)
      offset = 0;

    for (let hash in peer.blockMap.keys()) {
      hash = util.revHex(hash);
      hashes.push(hash);
    }

    peers.push({
      id: peer.id,
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
      inflight: hashes,
      whitelisted: false
    });
  }

  return peers;
};

RPC.prototype.ping = async function ping(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'ping');

  for (let peer = this.pool.peers.head(); peer; peer = peer.next)
    peer.sendPing();

  return null;
};

RPC.prototype.setBan = async function setBan(args, help) {
  let valid = new Validator([args]);
  let addr = valid.str(0, '');
  let action = valid.str(1, '');

  if (help
      || args.length < 2
      || (action !== 'add' && action !== 'remove')) {
    throw new RPCError(errs.MISC_ERROR,
      'setban "ip(/netmask)" "add|remove" (bantime) (absolute)');
  }

  addr = parseNetAddress(addr, this.network);

  switch (action) {
    case 'add':
      this.pool.ban(addr);
      break;
    case 'remove':
      this.pool.unban(addr);
      break;
  }

  return null;
};

RPC.prototype.listBanned = async function listBanned(args, help) {
  let banned = [];

  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'listbanned');

  for (let [host, time] of this.pool.hosts.banned) {
    banned.push({
      address: host,
      banned_until: time + this.pool.options.banTime,
      ban_created: time,
      ban_reason: ''
    });
  }

  return banned;
};

RPC.prototype.clearBanned = async function clearBanned(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'clearbanned');

  this.pool.hosts.clearBanned();

  return null;
};

/* Block chain and UTXO */
RPC.prototype.getBlockchainInfo = async function getBlockchainInfo(args, help) {
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
    mediantime: await this.chain.tip.getMedianTime(),
    verificationprogress: this.chain.getProgress(),
    chainwork: this.chain.tip.chainwork.toString('hex', 64),
    pruned: this.chain.options.prune,
    softforks: this.getSoftforks(),
    bip9_softforks: await this.getBIP9Softforks(),
    pruneheight: this.chain.options.prune
      ? Math.max(0, this.chain.height - this.network.block.keepBlocks)
      : null
  };
};

RPC.prototype.getBestBlockHash = async function getBestBlockHash(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getbestblockhash');

  return this.chain.tip.rhash();
};

RPC.prototype.getBlockCount = async function getBlockCount(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getblockcount');

  return this.chain.tip.height;
};

RPC.prototype.getBlock = async function getBlock(args, help) {
  let valid = new Validator([args]);
  let hash = valid.hash(0);
  let verbose = valid.bool(1, true);
  let details = valid.bool(2, false);
  let entry, block;

  if (help || args.length < 1 || args.length > 3)
    throw new RPCError(errs.MISC_ERROR, 'getblock "hash" ( verbose )');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid block hash.');

  entry = await this.chain.db.getEntry(hash);

  if (!entry)
    throw new RPCError(errs.MISC_ERROR, 'Block not found');

  block = await this.chain.db.getBlock(entry.hash);

  if (!block) {
    if (this.chain.options.spv)
      throw new RPCError(errs.MISC_ERROR, 'Block not available (spv mode)');

    if (this.chain.options.prune)
      throw new RPCError(errs.MISC_ERROR, 'Block not available (pruned data)');

    throw new RPCError(errs.MISC_ERROR, 'Can\'t read block from disk');
  }

  if (!verbose)
    return block.toRaw().toString('hex');

  return await this.blockToJSON(entry, block, details);
};

RPC.prototype.getBlockByHeight = async function getBlockByHeight(args, help) {
  let valid = new Validator([args]);
  let height = valid.u32(0, -1);
  let verbose = valid.bool(1, true);
  let details = valid.bool(2, false);
  let entry, block;

  if (help || args.length < 1 || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'getblockbyheight "height" ( verbose )');
  }

  if (height === -1)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid block height.');

  entry = await this.chain.db.getEntry(height);

  if (!entry)
    throw new RPCError(errs.MISC_ERROR, 'Block not found');

  block = await this.chain.db.getBlock(entry.hash);

  if (!block) {
    if (this.chain.options.spv)
      throw new RPCError(errs.MISC_ERROR, 'Block not available (spv mode)');

    if (this.chain.options.prune)
      throw new RPCError(errs.MISC_ERROR, 'Block not available (pruned data)');

    throw new RPCError(errs.DATABASE_ERROR, 'Can\'t read block from disk');
  }

  if (!verbose)
    return block.toRaw().toString('hex');

  return await this.blockToJSON(entry, block, details);
};

RPC.prototype.getBlockHash = async function getBlockHash(args, help) {
  let valid = new Validator([args]);
  let height = valid.u32(0);
  let hash;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'getblockhash index');

  if (height == null || height > this.chain.height)
    throw new RPCError(errs.INVALID_PARAMETER, 'Block height out of range.');

  hash = await this.chain.db.getHash(height);

  if (!hash)
    throw new RPCError(errs.MISC_ERROR, 'Not found.');

  return util.revHex(hash);
};

RPC.prototype.getBlockHeader = async function getBlockHeader(args, help) {
  let valid = new Validator([args]);
  let hash = valid.hash(0);
  let verbose = valid.bool(1, true);
  let entry;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'getblockheader "hash" ( verbose )');

  if (!hash)
    throw new RPCError(errs.MISC_ERROR, 'Invalid block hash.');

  entry = await this.chain.db.getEntry(hash);

  if (!entry)
    throw new RPCError(errs.MISC_ERROR, 'Block not found');

  if (!verbose)
    return entry.toRaw().toString('hex', 0, 80);

  return await this.headerToJSON(entry);
};

RPC.prototype.getChainTips = async function getChainTips(args, help) {
  let tips, result;

  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getchaintips');

  tips = await this.chain.db.getTips();
  result = [];

  for (let hash of tips) {
    let entry = await this.chain.db.getEntry(hash);
    let fork, main;

    assert(entry);

    fork = await this.findFork(entry);
    main = await entry.isMainChain();

    result.push({
      height: entry.height,
      hash: entry.rhash(),
      branchlen: entry.height - fork.height,
      status: main ? 'active' : 'valid-headers'
    });
  }

  return result;
};

RPC.prototype.getDifficulty = async function getDifficulty(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getdifficulty');

  return toDifficulty(this.chain.tip.bits);
};

RPC.prototype.getMempoolInfo = async function getMempoolInfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getmempoolinfo');

  if (!this.mempool)
    throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

  return {
    size: this.mempool.map.size,
    bytes: this.mempool.getSize(),
    usage: this.mempool.getSize(),
    maxmempool: this.mempool.options.maxSize,
    mempoolminfee: Amount.btc(this.mempool.options.minRelay, true)
  };
};

RPC.prototype.getMempoolAncestors = async function getMempoolAncestors(args, help) {
  let valid = new Validator([args]);
  let hash = valid.hash(0);
  let verbose = valid.bool(1, false);
  let out = [];
  let entries, entry;

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
    for (let entry of entries)
      out.push(this.entryToJSON(entry));
  } else {
    for (let entry of entries)
      out.push(entry.txid());
  }

  return out;
};

RPC.prototype.getMempoolDescendants = async function getMempoolDescendants(args, help) {
  let valid = new Validator([args]);
  let hash = valid.hash(0);
  let verbose = valid.bool(1, false);
  let out = [];
  let entries, entry;

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
    for (let entry of entries)
      out.push(this.entryToJSON(entry));
  } else {
    for (let entry of entries)
      out.push(entry.txid());
  }

  return out;
};

RPC.prototype.getMempoolEntry = async function getMempoolEntry(args, help) {
  let valid = new Validator([args]);
  let hash = valid.hash(0);
  let entry;

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
};

RPC.prototype.getRawMempool = async function getRawMempool(args, help) {
  let valid = new Validator([args]);
  let verbose = valid.bool(0, false);
  let out = {};
  let hashes;

  if (help || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'getrawmempool ( verbose )');

  if (!this.mempool)
    throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

  if (verbose) {
    for (let entry of this.mempool.map.values())
      out[entry.txid()] = this.entryToJSON(entry);

    return out;
  }

  hashes = this.mempool.getSnapshot();

  return hashes.map(util.revHex);
};

RPC.prototype.getTXOut = async function getTXOut(args, help) {
  let valid = new Validator([args]);
  let hash = valid.hash(0);
  let index = valid.u32(1);
  let mempool = valid.bool(2, true);
  let coin;

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
    coin = await this.chain.db.getCoin(hash, index);

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
};

RPC.prototype.getTXOutProof = async function getTXOutProof(args, help) {
  let valid = new Validator([args]);
  let txids = valid.array(0);
  let hash = valid.hash(1);
  let uniq = {};
  let block, last;

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

  for (let i = 0; i < txids.length; i++) {
    let txid = valid.hash(i);

    if (!txid)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID.');

    if (uniq[txid])
      throw new RPCError(errs.INVALID_PARAMETER, 'Duplicate txid.');

    uniq[txid] = true;
    txids[i] = txid;
    last = txid;
  }

  if (hash) {
    block = await this.chain.db.getBlock(hash);
  } else if (this.chain.options.indexTX) {
    let tx = await this.chain.db.getMeta(last);
    if (!tx)
      return;
    block = await this.chain.db.getBlock(tx.block);
  } else {
    let coins = await this.chain.db.getCoins(last);
    if (!coins)
      return;
    block = await this.chain.db.getBlock(coins.height);
  }

  if (!block)
    throw new RPCError(errs.MISC_ERROR, 'Block not found.');

  for (let txid of txids) {
    if (!block.hasTX(txid)) {
      throw new RPCError(errs.VERIFY_ERROR,
        'Block does not contain all txids.');
    }
  }

  block = MerkleBlock.fromHashes(block, txids);

  return block.toRaw().toString('hex');
};

RPC.prototype.verifyTXOutProof = async function verifyTXOutProof(args, help) {
  let valid = new Validator([args]);
  let data = valid.buf(0);
  let out = [];
  let block, entry;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'verifytxoutproof "proof"');

  if (!data)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid hex string.');

  block = MerkleBlock.fromRaw(data);

  if (!block.verify())
    return out;

  entry = await this.chain.db.getEntry(block.hash('hex'));

  if (!entry)
    throw new RPCError(errs.MISC_ERROR, 'Block not found in chain.');

  for (let hash of block.tree.matches)
    out.push(util.revHex(hash));

  return out;
};

RPC.prototype.getTXOutSetInfo = async function getTXOutSetInfo(args, help) {
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
};

RPC.prototype.pruneBlockchain = async function pruneBlockchain(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'pruneblockchain');

  if (this.chain.options.spv)
    throw new RPCError(errs.MISC_ERROR, 'Cannot prune chain in SPV mode.');

  if (this.chain.options.prune)
    throw new RPCError(errs.MISC_ERROR, 'Chain is already pruned.');

  if (this.chain.height < this.network.block.pruneAfterHeight)
    throw new RPCError(errs.MISC_ERROR, 'Chain is too short for pruning.');

  try {
    await this.chain.prune();
  } catch (e) {
    throw new RPCError(errs.DATABASE_ERROR, e.message);
  }
};

RPC.prototype.verifyChain = async function verifyChain(args, help) {
  let valid = new Validator([args]);
  let level = valid.u32(0);
  let blocks = valid.u32(1);

  if (help || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'verifychain ( checklevel numblocks )');

  if (level == null || blocks == null)
    throw new RPCError(errs.TYPE_ERROR, 'Missing parameters.');

  if (this.chain.options.spv)
    throw new RPCError(errs.MISC_ERROR, 'Cannot verify chain in SPV mode.');

  if (this.chain.options.prune)
    throw new RPCError(errs.MISC_ERROR, 'Cannot verify chain when pruned.');

  return null;
};

/*
 * Mining
 */

RPC.prototype.submitWork = async function submitWork(data) {
  let unlock = await this.locker.lock();
  try {
    return await this._submitWork(data);
  } finally {
    unlock();
  }
};

RPC.prototype._submitWork = async function _submitWork(data) {
  let attempt = this.attempt;
  let header, nonce, ts, nonces;
  let n1, n2, proof, block, entry;

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

  nonces = this.merkleMap.get(header.merkleRoot);

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
    entry = await this.chain.add(block);
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
};

RPC.prototype.createWork = async function createWork(data) {
  let unlock = await this.locker.lock();
  try {
    return await this._createWork(data);
  } finally {
    unlock();
  }
};

RPC.prototype._createWork = async function _createWork() {
  let attempt = await this.updateWork();
  let n1 = this.nonce1;
  let n2 = this.nonce2;
  let ts = attempt.ts;
  let data, root, head;

  data = Buffer.allocUnsafe(128);
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
};

RPC.prototype.getWorkLongpoll = async function getWorkLongpoll(args, help) {
  await this.longpoll();
  return await this.createWork();
};

RPC.prototype.getWork = async function getWork(args, help) {
  let valid = new Validator([args]);
  let data = valid.buf(0);

  if (args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'getwork ( "data" )');

  if (args.length === 1) {
    if (!data)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid work data.');

    return await this.submitWork(data);
  }

  return await this.createWork();
};

RPC.prototype.submitBlock = async function submitBlock(args, help) {
  let valid = new Validator([args]);
  let data = valid.buf(0);
  let block;

  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'submitblock "hexdata" ( "jsonparametersobject" )');
  }

  block = Block.fromRaw(data);

  return await this.addBlock(block);
};

RPC.prototype.getBlockTemplate = async function getBlockTemplate(args, help) {
  let validator = new Validator([args]);
  let options = validator.obj(0, {});
  let valid = new Validator([options]);
  let mode = valid.str('mode', 'template');
  let lpid = valid.str('longpollid');
  let data = valid.buf('data');
  let rules = valid.array('rules');
  let capabilities = valid.array('capabilities');
  let maxVersion = valid.u32('maxversion', -1);
  let coinbase = false;
  let txnCap = false;
  let valueCap = false;

  if (help || args.length > 1) {
    throw new RPCError(errs.MISC_ERROR,
      'getblocktemplate ( "jsonrequestobject" )');
  }

  if (mode !== 'template' && mode !== 'proposal')
    throw new RPCError(errs.INVALID_PARAMETER, 'Invalid mode.');

  if (mode === 'proposal') {
    let block;

    if (!data)
      throw new RPCError(errs.TYPE_ERROR, 'Missing data parameter.');

    block = Block.fromRaw(data);

    if (block.prevBlock !== this.chain.tip.hash)
      return 'inconclusive-not-best-prevblk';

    try {
      await this.chain.verifyBlock(block);
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
    for (let capability of capabilities) {
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
    await this.handleLongpoll(lpid);

  if (!rules)
    rules = [];

  return await this.createTemplate(maxVersion, coinbase, rules);
};

RPC.prototype.createTemplate = async function createTemplate(maxVersion, coinbase, rules) {
  let unlock = await this.locker.lock();
  try {
    return await this._createTemplate(maxVersion, coinbase, rules);
  } finally {
    unlock();
  }
};

RPC.prototype._createTemplate = async function _createTemplate(maxVersion, coinbase, rules) {
  let attempt = await this.getTemplate();
  let version = attempt.version;
  let scale = attempt.witness ? 1 : consensus.WITNESS_SCALE_FACTOR;
  let mutable = ['time', 'transactions', 'prevblock'];
  let txs = [];
  let index = {};
  let vbavailable = {};
  let vbrules = [];
  let json;

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
  for (let i = 0; i < attempt.items.length; i++) {
    let entry = attempt.items[i];
    index[entry.hash] = i + 1;
  }

  // Calculate dependencies for each transaction.
  for (let i = 0; i < attempt.items.length; i++) {
    let entry = attempt.items[i];
    let tx = entry.tx;
    let deps = [];

    for (let j = 0; j < tx.inputs.length; j++) {
      let input = tx.inputs[j];
      let dep = index[input.prevout.hash];

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

  if (this.chain.options.bip91) {
    rules.push('segwit');
    rules.push('segsignal');
  }

  if (this.chain.options.bip148)
    rules.push('segwit');

  // Calculate version based on given rules.
  for (let deploy of this.network.deploys) {
    let state = await this.chain.getState(this.chain.tip, deploy);
    let name = deploy.name;

    switch (state) {
      case common.thresholdStates.DEFINED:
      case common.thresholdStates.FAILED:
        break;
      case common.thresholdStates.LOCKED_IN:
        version |= 1 << deploy.bit;
      case common.thresholdStates.STARTED:
        if (!deploy.force) {
          if (rules.indexOf(name) === -1)
            version &= ~(1 << deploy.bit);
          if (deploy.required)
            name = '!' + name;
        }
        vbavailable[name] = deploy.bit;
        break;
      case common.thresholdStates.ACTIVE:
        if (!deploy.force && deploy.required) {
          if (rules.indexOf(name) === -1) {
            throw new RPCError(errs.INVALID_PARAMETER,
              `Client must support ${name}.`);
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
    let tx = attempt.toCoinbase();

    // Pop off the nonces.
    tx.inputs[0].script.code.pop();
    tx.inputs[0].script.compile();

    if (attempt.witness) {
      // We don't include the commitment
      // output (see bip145).
      let output = tx.outputs.pop();
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

  if (rules.indexOf('segwit') !== -1)
    json.default_witness_commitment = attempt.getWitnessScript().toJSON();

  return json;
};

RPC.prototype.getMiningInfo = async function getMiningInfo(args, help) {
  let attempt = this.attempt;
  let size = 0;
  let weight = 0;
  let txs = 0;
  let diff = 0;
  let item;

  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getmininginfo');

  if (attempt) {
    weight = attempt.weight;
    txs = attempt.items.length + 1;
    diff = attempt.getDifficulty();
    size = 1000;
    for (item of attempt.items)
      size += item.tx.getBaseSize();
  }

  return {
    blocks: this.chain.height,
    currentblocksize: size,
    currentblockweight: weight,
    currentblocktx: txs,
    difficulty: diff,
    errors: '',
    genproclimit: this.procLimit,
    networkhashps: await this.getHashRate(120),
    pooledtx: this.totalTX(),
    testnet: this.network !== Network.main,
    chain: this.network.type !== 'testnet'
      ? this.network.type
      : 'test',
    generate: this.mining
  };
};

RPC.prototype.getNetworkHashPS = async function getNetworkHashPS(args, help) {
  let valid = new Validator([args]);
  let lookup = valid.u32(0, 120);
  let height = valid.u32(1);

  if (help || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'getnetworkhashps ( blocks height )');

  return await this.getHashRate(lookup, height);
};

RPC.prototype.prioritiseTransaction = async function prioritiseTransaction(args, help) {
  let valid = new Validator([args]);
  let hash = valid.hash(0);
  let pri = valid.num(1);
  let fee = valid.i64(2);
  let entry;

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
};

RPC.prototype.verifyBlock = async function verifyBlock(args, help) {
  let valid = new Validator([args]);
  let data = valid.buf(0);
  let block;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'verifyblock "block-hex"');

  if (!data)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid block hex.');

  if (this.chain.options.spv)
    throw new RPCError(errs.MISC_ERROR, 'Cannot verify block in SPV mode.');

  block = Block.fromRaw(data);

  try {
    await this.chain.verifyBlock(block);
  } catch (e) {
    if (e.type === 'VerifyError')
      return e.reason;
    throw e;
  }

  return null;
};

/*
 * Coin generation
 */

RPC.prototype.getGenerate = async function getGenerate(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getgenerate');
  return this.mining;
};

RPC.prototype.setGenerate = async function setGenerate(args, help) {
  let valid = new Validator([args]);
  let mine = valid.bool(0, false);
  let limit = valid.u32(1, 0);

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'setgenerate mine ( proclimit )');

  if (mine && this.miner.addresses.length === 0) {
    throw new RPCError(errs.MISC_ERROR,
      'No addresses available for coinbase.');
  }

  this.mining = mine;
  this.procLimit = limit;

  if (mine) {
    this.miner.cpu.start();
    return true;
  }

  await this.miner.cpu.stop();

  return false;
};

RPC.prototype.generate = async function generate(args, help) {
  let valid = new Validator([args]);
  let blocks = valid.u32(0, 1);
  let tries = valid.u32(1);

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'generate numblocks ( maxtries )');

  if (this.miner.addresses.length === 0) {
    throw new RPCError(errs.MISC_ERROR,
      'No addresses available for coinbase.');
  }

  return await this.mineBlocks(blocks, null, tries);
};

RPC.prototype.generateToAddress = async function _generateToAddress(args, help) {
  let valid = new Validator([args]);
  let blocks = valid.u32(0, 1);
  let addr = valid.str(1, '');
  let tries = valid.u32(2);

  if (help || args.length < 2 || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'generatetoaddress numblocks address ( maxtries )');
  }

  addr = parseAddress(addr, this.network);

  return await this.mineBlocks(blocks, addr, tries);
};

/*
 * Raw transactions
 */

RPC.prototype.createRawTransaction = async function createRawTransaction(args, help) {
  let valid = new Validator([args]);
  let inputs = valid.array(0);
  let sendTo = valid.obj(1);
  let locktime = valid.u32(2);
  let tx, keys, addrs;

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

  for (let input of tx.inputs) {
    let valid = new Validator([input]);
    let hash = valid.hash('txid');
    let index = valid.u32('vout');
    let sequence = valid.u32('sequence', 0xffffffff);

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

  for (let key of keys) {
    let addr, b58, value, output;

    if (key === 'data') {
      let value = valid.buf(key);
      let output;

      if (!value)
        throw new RPCError(errs.TYPE_ERROR, 'Invalid nulldata..');

      output = new Output();
      output.value = 0;
      output.script.fromNulldata(value);
      tx.outputs.push(output);

      continue;
    }

    addr = parseAddress(key, this.network);
    b58 = addr.toString(this.network);

    if (addrs[b58])
      throw new RPCError(errs.INVALID_PARAMETER, 'Duplicate address');

    addrs[b58] = true;

    value = valid.btc(key);

    if (value == null)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid output value.');

    output = new Output();
    output.value = value;
    output.script.fromAddress(addr);

    tx.outputs.push(output);
  }

  return tx.toRaw().toString('hex');
};

RPC.prototype.decodeRawTransaction = async function decodeRawTransaction(args, help) {
  let valid = new Validator([args]);
  let data = valid.buf(0);
  let tx;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'decoderawtransaction "hexstring"');

  if (!data)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid hex string.');

  tx = TX.fromRaw(data);

  return this.txToJSON(tx);
};

RPC.prototype.decodeScript = async function decodeScript(args, help) {
  let valid = new Validator([args]);
  let data = valid.buf(0);
  let script, addr;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'decodescript "hex"');

  script = new Script();

  if (data)
    script = Script.fromRaw(data);

  addr = Address.fromScripthash(script.hash160());

  script = this.scriptToJSON(script);
  script.p2sh = addr.toString(this.network);

  return script;
};

RPC.prototype.getRawTransaction = async function getRawTransaction(args, help) {
  let valid = new Validator([args]);
  let hash = valid.hash(0);
  let verbose = valid.bool(1, false);
  let json, meta, tx, entry;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'getrawtransaction "txid" ( verbose )');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID.');

  meta = await this.node.getMeta(hash);

  if (!meta)
    throw new RPCError(errs.MISC_ERROR, 'Transaction not found.');

  tx = meta.tx;

  if (!verbose)
    return tx.toRaw().toString('hex');

  if (meta.block)
    entry = await this.chain.db.getEntry(meta.block);

  json = this.txToJSON(tx, entry);
  json.time = meta.ps;
  json.hex = tx.toRaw().toString('hex');

  return json;
};

RPC.prototype.sendRawTransaction = async function sendRawTransaction(args, help) {
  let valid = new Validator([args]);
  let data = valid.buf(0);
  let tx;

  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'sendrawtransaction "hexstring" ( allowhighfees )');
  }

  if (!data)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid hex string.');

  tx = TX.fromRaw(data);

  this.node.relay(tx);

  return tx.txid();
};

RPC.prototype.signRawTransaction = async function signRawTransaction(args, help) {
  let valid = new Validator([args]);
  let data = valid.buf(0);
  let prevout = valid.array(1);
  let secrets = valid.array(2);
  let sighash = valid.str(3);
  let type = Script.hashType.ALL;
  let keys = [];
  let map = {};
  let tx;

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
  tx.view = await this.mempool.getSpentView(tx);

  if (secrets) {
    let valid = new Validator([secrets]);
    for (let i = 0; i < secrets.length; i++) {
      let secret = valid.str(i, '');
      let key = parseSecret(secret, this.network);
      map[key.getPublicKey('hex')] = key;
      keys.push(key);
    }
  }

  if (prevout) {
    for (let prev of prevout) {
      let valid = new Validator([prev]);
      let hash = valid.hash('txid');
      let index = valid.u32('index');
      let script = valid.buf('scriptPubKey');
      let value = valid.btc('amount');
      let redeem = valid.buf('redeemScript');
      let coin;

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

      for (let op of redeem.code) {
        let key;

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
    let parts = sighash.split('|');
    let type = Script.hashType[parts[0]];

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

  await tx.signAsync(keys, type, this.workers);

  return {
    hex: tx.toRaw().toString('hex'),
    complete: tx.isSigned()
  };
};

/*
 * Utility Functions
 */

RPC.prototype.createMultisig = async function createMultisig(args, help) {
  let valid = new Validator([args]);
  let keys = valid.array(1, []);
  let m = valid.u32(0, 0);
  let n = keys.length;
  let script, addr;

  if (help || args.length < 2 || args.length > 2)
    throw new RPCError(errs.MISC_ERROR, 'createmultisig nrequired ["key",...]');

  if (m < 1 || n < m || n > 16)
    throw new RPCError(errs.INVALID_PARAMETER, 'Invalid m and n values.');

  valid = new Validator([keys]);

  for (let i = 0; i < keys.length; i++) {
    let key = valid.buf(i);

    if (!key)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid key.');

    if (!secp256k1.publicKeyVerify(key))
      throw new RPCError(errs.INVALID_ADDRESS_OR_KEY, 'Invalid key.');

    keys[i] = key;
  }

  script = Script.fromMultisig(m, n, keys);

  if (script.getSize() > consensus.MAX_SCRIPT_PUSH)
    throw new RPCError(errs.VERIFY_ERROR, 'Redeem script exceeds size limit.');

  addr = script.getAddress();

  return {
    address: addr.toString(this.network),
    redeemScript: script.toJSON()
  };
};

RPC.prototype.createWitnessAddress = async function createWitnessAddress(args, help) {
  let valid = new Validator([args]);
  let raw = valid.buf(0);
  let script, program, addr;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'createwitnessaddress "script"');

  if (!raw)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid script hex.');

  script = Script.fromRaw(raw);
  program = script.forWitness();
  addr = program.getAddress();

  return {
    address: addr.toString(this.network),
    witnessScript: program.toJSON()
  };
};

RPC.prototype.validateAddress = async function validateAddress(args, help) {
  let valid = new Validator([args]);
  let b58 = valid.str(0, '');
  let addr, script;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'validateaddress "bitcoinaddress"');

  try {
    addr = Address.fromString(b58, this.network);
  } catch (e) {
    return {
      isvalid: false
    };
  }

  script = Script.fromAddress(addr);

  return {
    isvalid: true,
    address: addr.toString(this.network),
    scriptPubKey: script.toJSON(),
    ismine: false,
    iswatchonly: false
  };
};

RPC.prototype.verifyMessage = async function verifyMessage(args, help) {
  let valid = new Validator([args]);
  let b58 = valid.str(0, '');
  let sig = valid.buf(1, null, 'base64');
  let msg = valid.str(2);
  let addr, key;

  if (help || args.length !== 3) {
    throw new RPCError(errs.MISC_ERROR,
      'verifymessage "bitcoinaddress" "signature" "message"');
  }

  if (!sig || !msg)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameters.');

  addr = parseAddress(b58, this.network);

  msg = Buffer.from(MAGIC_STRING + msg, 'utf8');
  msg = digest.hash256(msg);

  key = secp256k1.recover(msg, sig, 0, true);

  if (!key)
    return false;

  key = digest.hash160(key);

  return ccmp(key, addr.hash);
};

RPC.prototype.signMessageWithPrivkey = async function signMessageWithPrivkey(args, help) {
  let valid = new Validator([args]);
  let key = valid.str(0, '');
  let msg = valid.str(1, '');
  let sig;

  if (help || args.length !== 2) {
    throw new RPCError(errs.MISC_ERROR,
      'signmessagewithprivkey "privkey" "message"');
  }

  key = parseSecret(key, this.network);
  msg = Buffer.from(MAGIC_STRING + msg, 'utf8');
  msg = digest.hash256(msg);

  sig = key.sign(msg);

  return sig.toString('base64');
};

RPC.prototype.estimateFee = async function estimateFee(args, help) {
  let valid = new Validator([args]);
  let blocks = valid.u32(0, 1);
  let fee;

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
};

RPC.prototype.estimatePriority = async function estimatePriority(args, help) {
  let valid = new Validator([args]);
  let blocks = valid.u32(0, 1);

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'estimatepriority nblocks');

  if (!this.fees)
    throw new RPCError(errs.MISC_ERROR, 'Priority estimation not available.');

  if (blocks < 1)
    blocks = 1;

  return this.fees.estimatePriority(blocks, false);
};

RPC.prototype.estimateSmartFee = async function estimateSmartFee(args, help) {
  let valid = new Validator([args]);
  let blocks = valid.u32(0, 1);
  let fee;

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
};

RPC.prototype.estimateSmartPriority = async function estimateSmartPriority(args, help) {
  let valid = new Validator([args]);
  let blocks = valid.u32(0, 1);
  let pri;

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
};

RPC.prototype.invalidateBlock = async function invalidateBlock(args, help) {
  let valid = new Validator([args]);
  let hash = valid.hash(0);

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'invalidateblock "hash"');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid block hash.');

  await this.chain.invalidate(hash);

  return null;
};

RPC.prototype.reconsiderBlock = async function reconsiderBlock(args, help) {
  let valid = new Validator([args]);
  let hash = valid.hash(0);

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'reconsiderblock "hash"');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid block hash.');

  this.chain.removeInvalid(hash);

  return null;
};

RPC.prototype.setMockTime = async function setMockTime(args, help) {
  let valid = new Validator([args]);
  let ts = valid.u32(0);
  let delta;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'setmocktime timestamp');

  if (ts == null)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid timestamp.');

  this.network.time.offset = 0;

  delta = this.network.now() - ts;

  this.network.time.offset = -delta;

  return null;
};

RPC.prototype.getMemoryInfo = async function getMemoryInfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getmemoryinfo');

  return util.memoryUsage();
};

RPC.prototype.setLogLevel = async function setLogLevel(args, help) {
  let valid = new Validator([args]);
  let level = valid.str(0, '');

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'setloglevel "level"');

  this.logger.setLevel(level);

  return null;
};

/*
 * Helpers
 */

RPC.prototype.handleLongpoll = async function handleLongpoll(lpid) {
  let watched, lastTX;

  if (lpid.length !== 74)
    throw new RPCError(errs.INVALID_PARAMETER, 'Invalid longpoll ID.');

  watched = lpid.slice(0, 64);
  lastTX = +lpid.slice(64, 74);

  if (!util.isHex(watched) || !util.isNumber(lastTX) || lastTX < 0)
    throw new RPCError(errs.INVALID_PARAMETER, 'Invalid longpoll ID.');

  watched = util.revHex(watched);

  if (this.chain.tip.hash !== watched)
    return;

  await this.longpoll();
};

RPC.prototype.longpoll = function longpoll() {
  return new Promise((resolve, reject) => {
    this.pollers.push(co.job(resolve, reject));
  });
};

RPC.prototype.refreshBlock = function refreshBlock() {
  let pollers = this.pollers;

  this.attempt = null;
  this.lastActivity = 0;
  this.merkleMap.clear();
  this.nonce1 = 0;
  this.nonce2 = 0;
  this.pollers = [];

  for (let job of pollers)
    job.resolve();
};

RPC.prototype.bindChain = function bindChain() {
  if (this.boundChain)
    return;

  this.boundChain = true;

  this.node.on('connect', () => {
    if (!this.attempt)
      return;

    this.refreshBlock();
  });

  if (!this.mempool)
    return;

  this.node.on('tx', () => {
    if (!this.attempt)
      return;

    if (util.now() - this.lastActivity > 10)
      this.refreshBlock();
  });
};

RPC.prototype.getTemplate = async function getTemplate() {
  let attempt = this.attempt;

  this.bindChain();

  if (attempt) {
    this.miner.updateTime(attempt);
  } else {
    attempt = await this.miner.createBlock();
    this.attempt = attempt;
    this.lastActivity = util.now();
  }

  return attempt;
};

RPC.prototype.updateWork = async function updateWork() {
  let attempt = this.attempt;
  let root, n1, n2;

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

    this.merkleMap.set(root, new Nonces(n1, n2));

    return attempt;
  }

  if (this.miner.addresses.length === 0) {
    throw new RPCError(errs.MISC_ERROR,
      'No addresses available for coinbase.');
  }

  attempt = await this.miner.createBlock();

  n1 = this.nonce1;
  n2 = this.nonce2;

  root = attempt.getRoot(n1, n2);
  root = root.toString('hex');

  this.attempt = attempt;
  this.lastActivity = util.now();
  this.merkleMap.set(root, new Nonces(n1, n2));

  return attempt;
};

RPC.prototype.addBlock = async function addBlock(block) {
  let unlock1 = await this.locker.lock();
  let unlock2 = await this.chain.locker.lock();
  try {
    return await this._addBlock(block);
  } finally {
    unlock2();
    unlock1();
  }
};

RPC.prototype._addBlock = async function _addBlock(block) {
  let entry, prev;

  this.logger.info('Handling submitted block: %s.', block.rhash());

  prev = await this.chain.db.getEntry(block.prevBlock);

  if (prev) {
    let state = await this.chain.getDeployments(block.ts, prev);

    // Fix eloipool bug (witness nonce is not present).
    if (state.hasWitness() && block.getCommitmentHash()) {
      let tx = block.txs[0];
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
    entry = await this.chain._add(block);
  } catch (err) {
    if (err.type === 'VerifyError') {
      this.logger.warning('RPC block rejected: %s (%s).',
        block.rhash(), err.reason);
      return `rejected: ${err.reason}`;
    }
    throw err;
  }

  if (!entry) {
    this.logger.warning('RPC block rejected: %s (bad-prevblk).',
      block.rhash());
    return 'rejected: bad-prevblk';
  }

  return null;
};

RPC.prototype.totalTX = function totalTX() {
  return this.mempool ? this.mempool.map.size : 0;
};

RPC.prototype.getSoftforks = function getSoftforks() {
  return [
    toDeployment('bip34', 2, this.chain.state.hasBIP34()),
    toDeployment('bip66', 3, this.chain.state.hasBIP66()),
    toDeployment('bip65', 4, this.chain.state.hasCLTV())
  ];
};

RPC.prototype.getBIP9Softforks = async function getBIP9Softforks() {
  let tip = this.chain.tip;
  let forks = {};

  for (let deployment of this.network.deploys) {
    let state = await this.chain.getState(tip, deployment);
    let status;

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
};

RPC.prototype.getHashRate = async function getHashRate(lookup, height) {
  let tip = this.chain.tip;
  let minTime, maxTime, workDiff, timeDiff, ps, entry;

  if (height != null)
    tip = await this.chain.db.getEntry(height);

  if (!tip)
    return 0;

  if (lookup <= 0)
    lookup = tip.height % this.network.pow.retargetInterval + 1;

  if (lookup > tip.height)
    lookup = tip.height;

  minTime = tip.ts;
  maxTime = minTime;
  entry = tip;

  for (let i = 0; i < lookup; i++) {
    let entry = await entry.getPrevious();

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
};

RPC.prototype.mineBlocks = async function mineBlocks(blocks, addr, tries) {
  let unlock = await this.locker.lock();
  try {
    return await this._mineBlocks(blocks, addr, tries);
  } finally {
    unlock();
  }
};

RPC.prototype._mineBlocks = async function _mineBlocks(blocks, addr, tries) {
  let hashes = [];

  for (let i = 0; i < blocks; i++) {
    let block = await this.miner.mineBlock(null, addr);
    hashes.push(block.rhash());
    assert(await this.chain.add(block));
  }

  return hashes;
};

RPC.prototype.findFork = async function findFork(entry) {
  while (entry) {
    if (await entry.isMainChain())
      return entry;
    entry = await entry.getPrevious();
  }
  throw new Error('Fork not found.');
};

RPC.prototype.txToJSON = function txToJSON(tx, entry) {
  let height = -1;
  let conf = 0;
  let time = 0;
  let hash = null;
  let vin = [];
  let vout = [];

  if (entry) {
    height = entry.height;
    time = entry.ts;
    hash = entry.rhash();
    conf = this.chain.height - height + 1;
  }

  for (let input of tx.inputs) {
    let json = {
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
      json.txinwitness = input.witness.items.map((item) => {
        return item.toString('hex');
      });
    }

    vin.push(json);
  }

  for (let i = 0; i < tx.outputs.length; i++) {
    let output = tx.outputs[i];
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
  let type = script.getType();
  let addr = script.getAddress();
  let out;

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

  if (addr) {
    addr = addr.toString(this.network);
    out.addresses.push(addr);
  }

  return out;
};

RPC.prototype.headerToJSON = async function headerToJSON(entry) {
  let mtp = await entry.getMedianTime();
  let next = await this.chain.db.getNextHash(entry.hash);

  return {
    hash: entry.rhash(),
    confirmations: this.chain.height - entry.height + 1,
    height: entry.height,
    version: entry.version,
    versionHex: util.hex32(entry.version),
    merkleroot: util.revHex(entry.merkleRoot),
    time: entry.ts,
    mediantime: mtp,
    bits: entry.bits,
    difficulty: toDifficulty(entry.bits),
    chainwork: entry.chainwork.toString('hex', 64),
    previousblockhash: entry.prevBlock !== encoding.NULL_HASH
      ? util.revHex(entry.prevBlock)
      : null,
    nextblockhash: next ? util.revHex(next) : null
  };
};

RPC.prototype.blockToJSON = async function blockToJSON(entry, block, details) {
  let mtp = await entry.getMedianTime();
  let next = await this.chain.db.getNextHash(entry.hash);
  let txs = [];

  for (let tx of block.txs) {
    if (details) {
      let json = this.txToJSON(tx, entry);
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
    coinbase: block.txs[0].inputs[0].script.toJSON(),
    tx: txs,
    time: entry.ts,
    mediantime: mtp,
    bits: entry.bits,
    difficulty: toDifficulty(entry.bits),
    chainwork: entry.chainwork.toString('hex', 64),
    previousblockhash: entry.prevBlock !== encoding.NULL_HASH
      ? util.revHex(entry.prevBlock)
      : null,
    nextblockhash: next ? util.revHex(next) : null
  };
};

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
  for (let i = 0; i < data.length; i += 4) {
    let field = data.readUInt32LE(i, true);
    data.writeUInt32BE(field, i, true);
  }
  return data;
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
    return Address.fromString(raw, network);
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

function parseIP(addr, network) {
  try {
    return IP.fromHostname(addr, network.port);
  } catch (e) {
    throw new RPCError(errs.CLIENT_INVALID_IP_OR_SUBNET,
      'Invalid IP address or subnet.');
  }
}

function parseNetAddress(addr, network) {
  try {
    return NetAddress.fromHostname(addr, network);
  } catch (e) {
    throw new RPCError(errs.CLIENT_INVALID_IP_OR_SUBNET,
      'Invalid IP address or subnet.');
  }
}

function toDifficulty(bits) {
  let shift = (bits >>> 24) & 0xff;
  let diff = 0x0000ffff / (bits & 0x00ffffff);

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
