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
var Lock = require('../utils/lock');
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
  this.logger = node.logger;
  this.calls = {};

  this.locker = new Lock();

  this.feeRate = null;
  this.mining = false;
  this.proclimit = 0;

  this.attempt = null;
  this.start = 0;
  this._boundChain = false;
  this.coinbase = {};

  this.init();
}

util.inherits(RPC, RPCBase);

RPC.prototype.init = function init() {
  this.add('stop', this.stop);
  this.add('help', this.help);

  this.add('getblockchaininfo', this.getblockchaininfo);
  this.add('getbestblockhash', this.getbestblockhash);
  this.add('getblockcount', this.getblockcount);
  this.add('getblock', this.getblock);
  this.add('getblockhash', this.getblockhash);
  this.add('getblockheader', this.getblockheader);
  this.add('getchaintips', this.getchaintips);
  this.add('getdifficulty', this.getdifficulty);
  this.add('getmempoolancestors', this.getmempoolancestors);
  this.add('getmempooldescendants', this.getmempooldescendants);
  this.add('getmempoolentry', this.getmempoolentry);
  this.add('getmempoolinfo', this.getmempoolinfo);
  this.add('getrawmempool', this.getrawmempool);
  this.add('gettxout', this.gettxout);
  this.add('gettxoutsetinfo', this.gettxoutsetinfo);
  this.add('verifychain', this.verifychain);

  this.add('invalidateblock', this.invalidateblock);
  this.add('reconsiderblock', this.reconsiderblock);

  this.add('getnetworkhashps', this.getnetworkhashps);
  this.add('getmininginfo', this.getmininginfo);
  this.add('prioritisetransaction', this.prioritisetransaction);
  this.add('getwork', this.getwork);
  this.add('getworklp', this.getworklp);
  this.add('getblocktemplate', this.getblocktemplate);
  this.add('submitblock', this.submitblock);
  this.add('verifyblock', this.verifyblock);

  this.add('setgenerate', this.setgenerate);
  this.add('getgenerate', this.getgenerate);
  this.add('generate', this.generate);
  this.add('generatetoaddress', this.generatetoaddress);

  this.add('estimatefee', this.estimatefee);
  this.add('estimatepriority', this.estimatepriority);
  this.add('estimatesmartfee', this.estimatesmartfee);
  this.add('estimatesmartpriority', this.estimatesmartpriority);

  this.add('getinfo', this.getinfo);
  this.add('validateaddress', this.validateaddress);
  this.add('createmultisig', this.createmultisig);
  this.add('createwitnessaddress', this.createwitnessaddress);
  this.add('verifymessage', this.verifymessage);
  this.add('signmessagewithprivkey', this.signmessagewithprivkey);

  this.add('setmocktime', this.setmocktime);

  this.add('getconnectioncount', this.getconnectioncount);
  this.add('ping', this.ping);
  this.add('getpeerinfo', this.getpeerinfo);
  this.add('addnode', this.addnode);
  this.add('disconnectnode', this.disconnectnode);
  this.add('getaddednodeinfo', this.getaddednodeinfo);
  this.add('getnettotals', this.getnettotals);
  this.add('getnetworkinfo', this.getnetworkinfo);
  this.add('setban', this.setban);
  this.add('listbanned', this.listbanned);
  this.add('clearbanned', this.clearbanned);

  this.add('getrawtransaction', this.getrawtransaction);
  this.add('createrawtransaction', this.createrawtransaction);
  this.add('decoderawtransaction', this.decoderawtransaction);
  this.add('decodescript', this.decodescript);
  this.add('sendrawtransaction', this.sendrawtransaction);
  this.add('signrawtransaction', this.signrawtransaction);

  this.add('gettxoutproof', this.gettxoutproof);
  this.add('verifytxoutproof', this.verifytxoutproof);

  this.add('getmemory', this.getmemory);
  this.add('setloglevel', this.setloglevel);
};

/*
 * Overall control/query calls
 */

RPC.prototype.getinfo = co(function* getinfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError('getinfo');

  return {
    version: pkg.version,
    protocolversion: this.pool.options.version,
    walletversion: 0,
    balance: 0,
    blocks: this.chain.height,
    timeoffset: this.network.time.offset,
    connections: this.pool.peers.size(),
    proxy: '',
    difficulty: this._getDifficulty(),
    testnet: this.network.type !== Network.main,
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
    throw new RPCError('stop');

  this.node.close();

  return 'Stopping.';
});

/*
 * P2P networking
 */

RPC.prototype.getnetworkinfo = co(function* getnetworkinfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError('getnetworkinfo');

  return {
    version: pkg.version,
    subversion: this.pool.options.agent,
    protocolversion: this.pool.options.version,
    localservices: this.pool.options.services,
    timeoffset: this.network.time.offset,
    connections: this.pool.peers.size(),
    networks: [],
    relayfee: Amount.btc(this.network.minRelay, true),
    localaddresses: [],
    warnings: ''
  };
});

RPC.prototype.addnode = co(function* addnode(args, help) {
  var valid = new Validator([args]);
  var node = valid.str(0, '');
  var cmd = valid.str(1, '');
  var addr, peer;

  if (help || args.length !== 2)
    throw new RPCError('addnode "node" "add|remove|onetry"');

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
        peer = this.pool.createPeer(addr);
        this.pool.peers.add(peer);
      }
      break;
  }

  return null;
});

RPC.prototype.disconnectnode = co(function* disconnectnode(args, help) {
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var peer;

  if (help || args.length !== 1)
    throw new RPCError('disconnectnode "node"');

  addr = IP.fromHostname(addr, this.network.port);
  peer = this.pool.peers.get(addr.hostname);

  if (peer)
    peer.destroy();

  return null;
});

RPC.prototype.getaddednodeinfo = co(function* getaddednodeinfo(args, help) {
  var valid = new Validator([args]);
  var addr = valid.str(1, '');
  var out = [];
  var peer;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getaddednodeinfo dummy ( "node" )');

  if (args.length === 2) {
    addr = IP.fromHostname(addr, this.network.port);
    peer = this.pool.peers.get(addr.hostname);
    if (!peer)
      throw new RPCError('Node has not been added.');
    return [this._toAddedNode(peer)];
  }

  for (peer = this.pool.peers.head(); peer; peer = peer.next)
    out.push(this._toAddedNode(peer));

  return out;
});

RPC.prototype._toAddedNode = function _toAddedNode(peer) {
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
};

RPC.prototype.getconnectioncount = co(function* getconnectioncount(args, help) {
  if (help || args.length !== 0)
    throw new RPCError('getconnectioncount');

  return this.pool.peers.size();
});

RPC.prototype.getnettotals = co(function* getnettotals(args, help) {
  var sent = 0;
  var recv = 0;
  var peer;

  if (help || args.length > 0)
    throw new RPCError('getnettotals');

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

RPC.prototype.getpeerinfo = co(function* getpeerinfo(args, help) {
  var peers = [];
  var id = 0;
  var peer, offset;

  if (help || args.length !== 0)
    throw new RPCError('getpeerinfo');

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
    throw new RPCError('ping');

  for (peer = this.pool.peers.head(); peer; peer = peer.next)
    peer.sendPing();

  return null;
});

RPC.prototype.setban = co(function* setban(args, help) {
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var action = valid.str(1, '');

  if (help
      || args.length < 2
      || (action !== 'add' && action !== 'remove')) {
    throw new RPCError('setban "ip(/netmask)"'
      + ' "add|remove" (bantime) (absolute)');
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

RPC.prototype.listbanned = co(function* listbanned(args, help) {
  var i, banned, keys, host, time;

  if (help || args.length !== 0)
    throw new RPCError('listbanned');

  banned = [];
  keys = Object.keys(this.pool.hosts.banned);

  for (i = 0; i < keys.length; i++) {
    host = keys[i];
    time = this.pool.hosts.banned[host];
    banned.push({
      address: host,
      banned_until: time + this.pool.hosts.banTime,
      ban_created: time,
      ban_reason: ''
    });
  }

  return banned;
});

RPC.prototype.clearbanned = co(function* clearbanned(args, help) {
  if (help || args.length !== 0)
    throw new RPCError('clearbanned');

  this.pool.hosts.clearBanned();

  return null;
});

RPC.prototype._deployment = function _deployment(id, version, status) {
  return {
    id: id,
    version: version,
    reject: {
      status: status
    }
  };
};

RPC.prototype._getSoftforks = function _getSoftforks() {
  return [
    this._deployment('bip34', 2, this.chain.state.hasBIP34()),
    this._deployment('bip66', 3, this.chain.state.hasBIP66()),
    this._deployment('bip65', 4, this.chain.state.hasCLTV())
  ];
};

RPC.prototype._getBIP9Softforks = co(function* _getBIP9Softforks() {
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

/* Block chain and UTXO */
RPC.prototype.getblockchaininfo = co(function* getblockchaininfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError('getblockchaininfo');

  return {
    chain: 'main',
    blocks: this.chain.height,
    headers: this.chain.height,
    bestblockhash: this.chain.tip.rhash(),
    difficulty: this._getDifficulty(),
    mediantime: yield this.chain.tip.getMedianTime(),
    verificationprogress: this.chain.getProgress(),
    chainwork: this.chain.tip.chainwork.toString('hex', 64),
    pruned: this.chain.options.prune,
    softforks: this._getSoftforks(),
    bip9_softforks: yield this._getBIP9Softforks(),
    pruneheight: this.chain.options.prune
      ? Math.max(0, this.chain.height - this.network.block.keepBlocks)
      : null
  };
});

RPC.prototype._getDifficulty = function getDifficulty(entry) {
  var shift, diff;

  if (!entry) {
    if (!this.chain.tip)
      return 1.0;
    entry = this.chain.tip;
  }

  shift = (entry.bits >>> 24) & 0xff;
  diff = 0x0000ffff / (entry.bits & 0x00ffffff);

  while (shift < 29) {
    diff *= 256.0;
    shift++;
  }

  while (shift > 29) {
    diff /= 256.0;
    shift--;
  }

  return diff;
};

RPC.prototype.getbestblockhash = co(function* getbestblockhash(args, help) {
  if (help || args.length !== 0)
    throw new RPCError('getbestblockhash');

  return this.chain.tip.rhash();
});

RPC.prototype.getblockcount = co(function* getblockcount(args, help) {
  if (help || args.length !== 0)
    throw new RPCError('getblockcount');

  return this.chain.tip.height;
});

RPC.prototype.getblock = co(function* getblock(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var verbose = valid.bool(1, true);
  var entry, block;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getblock "hash" ( verbose )');

  if (!hash)
    throw new RPCError('Invalid parameter.');

  entry = yield this.chain.db.getEntry(hash);

  if (!entry)
    throw new RPCError('Block not found');

  block = yield this.chain.db.getBlock(entry.hash);

  if (!block) {
    if (this.chain.options.spv)
      throw new RPCError('Block not available (spv mode)');

    if (this.chain.options.prune)
      throw new RPCError('Block not available (pruned data)');

    throw new RPCError('Can\'t read block from disk');
  }

  if (!verbose)
    return block.toRaw().toString('hex');

  return yield this._blockToJSON(entry, block, false);
});

RPC.prototype._txToJSON = function _txToJSON(tx, entry) {
  var self = this;
  var height = entry ? entry.height : -1;
  var conf = 0;

  if (height >= this.chain.height)
    conf = height + 1 - this.chain.height;

  return {
    txid: tx.txid(),
    hash: tx.wtxid(),
    size: tx.getSize(),
    vsize: tx.getVirtualSize(),
    version: tx.version,
    locktime: tx.locktime,
    vin: tx.inputs.map(function(input) {
      var out = {};
      if (tx.isCoinbase()) {
        out.coinbase = input.script.toJSON();
      } else {
        out.txid = input.prevout.txid();
        out.vout = input.prevout.index;
        out.scriptSig = {
          asm: input.script.toASM(),
          hex: input.script.toJSON()
        };
      }
      if (input.witness.items.length > 0) {
        out.txinwitness = input.witness.items.map(function(item) {
          return item.toString('hex');
        });
      }
      out.sequence = input.sequence;
      return out;
    }),
    vout: tx.outputs.map(function(output, i) {
      return {
        value: Amount.btc(output.value, true),
        n: i,
        scriptPubKey: self._scriptToJSON(output.script, true)
      };
    }),
    blockhash: entry ? entry.rhash() : null,
    confirmations: conf,
    time: entry ? entry.ts : 0,
    blocktime: entry ? entry.ts : 0,
    hex: undefined
  };
};

RPC.prototype._scriptToJSON = function scriptToJSON(script, hex) {
  var type = script.getType();
  var address = script.getAddress();
  var out;

  out = {
    asm: script.toASM(),
    hex: undefined,
    type: Script.typesByVal[type],
    reqSigs: 1,
    addresses: []
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

RPC.prototype.getblockhash = co(function* getblockhash(args, help) {
  var valid = new Validator([args]);
  var height = valid.num(0, -1);
  var hash;

  if (help || args.length !== 1)
    throw new RPCError('getblockhash index');

  if (height < 0 || height > this.chain.height)
    throw new RPCError('Block height out of range.');

  hash = yield this.chain.db.getHash(height);

  if (!hash)
    throw new RPCError('Not found.');

  return util.revHex(hash);
});

RPC.prototype.getblockheader = co(function* getblockheader(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var verbose = valid.bool(1, true);
  var entry;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getblockheader "hash" ( verbose )');

  if (!hash)
    throw new RPCError('Invalid parameter.');

  entry = yield this.chain.db.getEntry(hash);

  if (!entry)
    throw new RPCError('Block not found');

  if (!verbose)
    return entry.toRaw().toString('hex', 0, 80);

  return yield this._headerToJSON(entry);
});

RPC.prototype._headerToJSON = co(function* _headerToJSON(entry) {
  var medianTime = yield entry.getMedianTime();
  var nextHash = yield this.chain.db.getNextHash(entry.hash);

  return {
    hash: entry.rhash(),
    confirmations: this.chain.height - entry.height + 1,
    height: entry.height,
    version: entry.version,
    merkleroot: util.revHex(entry.merkleRoot),
    time: entry.ts,
    mediantime: medianTime,
    bits: entry.bits,
    difficulty: this._getDifficulty(entry),
    chainwork: entry.chainwork.toString('hex', 64),
    previousblockhash: entry.prevBlock !== encoding.NULL_HASH
      ? util.revHex(entry.prevBlock)
      : null,
    nextblockhash: nextHash ? util.revHex(nextHash) : null
  };
});

RPC.prototype._blockToJSON = co(function* _blockToJSON(entry, block, txDetails) {
  var self = this;
  var mtp = yield entry.getMedianTime();
  var nextHash = yield this.chain.db.getNextHash(entry.hash);

  return {
    hash: entry.rhash(),
    confirmations: this.chain.height - entry.height + 1,
    strippedsize: block.getBaseSize(),
    size: block.getSize(),
    weight: block.getWeight(),
    height: entry.height,
    version: entry.version,
    merkleroot: util.revHex(entry.merkleRoot),
    tx: block.txs.map(function(tx) {
      if (txDetails)
        return self._txToJSON(tx, entry);
      return tx.txid();
    }),
    time: entry.ts,
    mediantime: mtp,
    bits: entry.bits,
    difficulty: this._getDifficulty(entry),
    chainwork: entry.chainwork.toString('hex', 64),
    previousblockhash: entry.prevBlock !== encoding.NULL_HASH
      ? util.revHex(entry.prevBlock)
      : null,
    nextblockhash: nextHash ? util.revHex(nextHash) : null
  };
});

RPC.prototype.getchaintips = co(function* getchaintips(args, help) {
  var i, hash, tips, result, entry, fork, main;

  if (help || args.length !== 0)
    throw new RPCError('getchaintips');

  tips = yield this.chain.db.getTips();
  result = [];

  for (i = 0; i < tips.length; i++) {
    hash = tips[i];
    entry = yield this.chain.db.getEntry(hash);
    assert(entry);

    fork = yield this._findFork(entry);
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

RPC.prototype._findFork = co(function* _findFork(entry) {
  while (entry) {
    if (yield entry.isMainChain())
      return entry;
    entry = yield entry.getPrevious();
  }
  throw new Error('Fork not found.');
});

RPC.prototype.getdifficulty = co(function* getdifficulty(args, help) {
  if (help || args.length !== 0)
    throw new RPCError('getdifficulty');

  return this._getDifficulty();
});

RPC.prototype.getmempoolinfo = co(function* getmempoolinfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError('getmempoolinfo');

  if (!this.mempool)
    throw new RPCError('No mempool available.');

  return {
    size: this.mempool.totalTX,
    bytes: this.mempool.getSize(),
    usage: this.mempool.getSize(),
    maxmempool: this.mempool.options.maxSize,
    mempoolminfee: Amount.btc(this.mempool.options.minRelay, true)
  };
});

RPC.prototype.getmempoolancestors = co(function* getmempoolancestors(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var verbose = valid.bool(1, false);
  var out = [];
  var i, entry, entries;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getmempoolancestors txid (verbose)');

  if (!this.mempool)
    throw new RPCError('No mempool available.');

  if (!hash)
    throw new RPCError('Invalid parameter.');

  entry = this.mempool.getEntry(hash);

  if (!entry)
    throw new RPCError('Transaction not in mempool.');

  entries = this.mempool.getAncestors(entry);

  if (verbose) {
    for (i = 0; i < entries.length; i++) {
      entry = entries[i];
      out.push(this._entryToJSON(entry));
    }
  } else {
    for (i = 0; i < entries.length; i++) {
      entry = entries[i];
      out.push(entry.txid());
    }
  }

  return out;
});

RPC.prototype.getmempooldescendants = co(function* getmempooldescendants(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var verbose = valid.bool(1, false);
  var out = [];
  var i, entry, entries;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getmempooldescendants txid (verbose)');

  if (!this.mempool)
    throw new RPCError('No mempool available.');

  if (!hash)
    throw new RPCError('Invalid parameter.');

  entry = this.mempool.getEntry(hash);

  if (!entry)
    throw new RPCError('Transaction not in mempool.');

  entries = this.mempool.getDescendants(entry);

  if (verbose) {
    for (i = 0; i < entries.length; i++) {
      entry = entries[i];
      out.push(this._entryToJSON(entry));
    }
  } else {
    for (i = 0; i < entries.length; i++) {
      entry = entries[i];
      out.push(entry.txid());
    }
  }

  return out;
});

RPC.prototype.getmempoolentry = co(function* getmempoolentry(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var entry;

  if (help || args.length !== 1)
    throw new RPCError('getmempoolentry txid');

  if (!this.mempool)
    throw new RPCError('No mempool available.');

  if (!hash)
    throw new RPCError('Invalid parameter.');

  entry = this.mempool.getEntry(hash);

  if (!entry)
    throw new RPCError('Transaction not in mempool.');

  return this._entryToJSON(entry);
});

RPC.prototype.getrawmempool = co(function* getrawmempool(args, help) {
  var valid = new Validator([args]);
  var verbose = valid.bool(0, false);
  var out = {};
  var i, hashes, hash, entry;

  if (help || args.length > 1)
    throw new RPCError('getrawmempool ( verbose )');

  if (verbose) {
    hashes = this.mempool.getSnapshot();

    for (i = 0; i < hashes.length; i++) {
      hash = hashes[i];
      entry = this.mempool.getEntry(hash);

      if (!entry)
        continue;

      out[entry.txid()] = this._entryToJSON(entry);
    }

    return out;
  }

  hashes = this.mempool.getSnapshot();

  return hashes.map(util.revHex);
});

RPC.prototype._entryToJSON = function _entryToJSON(entry) {
  return {
    size: entry.size,
    fee: Amount.btc(entry.fee, true),
    modifiedfee: 0,
    time: entry.ts,
    height: entry.height,
    startingpriority: entry.priority,
    currentpriority: entry.getPriority(this.chain.height),
    descendantcount: this.mempool.countDescendants(entry),
    descendantsize: entry.descSize,
    descendantfees: Amount.btc(entry.descFee, true),
    ancestorcount: this.mempool.countAncestors(entry),
    ancestorsize: 0,
    ancestorfees: 0,
    depends: this.mempool.getDepends(entry.tx).map(util.revHex)
  };
};

RPC.prototype.gettxout = co(function* gettxout(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var index = valid.num(1);
  var mempool = valid.bool(2, true);
  var coin;

  if (help || args.length < 2 || args.length > 3)
    throw new RPCError('gettxout "txid" n ( includemempool )');

  if (this.chain.options.spv)
    throw new RPCError('Cannot get coins in SPV mode.');

  if (this.chain.options.prune)
    throw new RPCError('Cannot get coins when pruned.');

  if (!hash || index < 0)
    throw new RPCError('Invalid parameter.');

  if (mempool)
    coin = this.mempool.getCoin(hash, index);

  if (!coin)
    coin = yield this.chain.db.getCoin(hash, index);

  if (!coin)
    return null;

  return {
    bestblock: this.chain.tip.rhash(),
    confirmations: coin.getDepth(this.chain.height),
    value: Amount.btc(coin.value, true),
    scriptPubKey: this._scriptToJSON(coin.script, true),
    version: coin.version,
    coinbase: coin.coinbase
  };
});

RPC.prototype.gettxoutproof = co(function* gettxoutproof(args, help) {
  var valid = new Validator([args]);
  var txids = valid.array(0);
  var hash = valid.hash(1);
  var uniq = {};
  var i, block, txid, tx, coins;

  if (help || (args.length !== 1 && args.length !== 2))
    throw new RPCError('gettxoutproof ["txid",...] ( blockhash )');

  if (this.chain.options.spv)
    throw new RPCError('Cannot get coins in SPV mode.');

  if (this.chain.options.prune)
    throw new RPCError('Cannot get coins when pruned.');

  if (!txids || txids.length === 0)
    throw new RPCError('Invalid parameter.');

  valid = new Validator([txids]);

  for (i = 0; i < txids.length; i++) {
    txid = valid.hash(i);

    if (!txid)
      throw new RPCError('Invalid parameter.');

    if (uniq[txid])
      throw new RPCError('Duplicate txid.');

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
    throw new RPCError('Block not found.');

  for (i = 0; i < txids.length; i++) {
    txid = txids[i];
    if (!block.hasTX(txid))
      throw new RPCError('Block does not contain all txids.');
  }

  block = MerkleBlock.fromHashes(block, txids);

  return block.toRaw().toString('hex');
});

RPC.prototype.verifytxoutproof = co(function* verifytxoutproof(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var out = [];
  var i, block, hash, entry;

  if (help || args.length !== 1)
    throw new RPCError('verifytxoutproof "proof"');

  if (!data)
    throw new RPCError('Invalid hex string.');

  block = MerkleBlock.fromRaw(data);

  if (!block.verify())
    return out;

  entry = yield this.chain.db.getEntry(block.hash('hex'));

  if (!entry)
    throw new RPCError('Block not found in chain.');

  for (i = 0; i < block.matches.length; i++) {
    hash = block.matches[i];
    out.push(util.revHex(hash));
  }

  return out;
});

RPC.prototype.gettxoutsetinfo = co(function* gettxoutsetinfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError('gettxoutsetinfo');

  if (this.chain.options.spv)
    throw new RPCError('Chainstate not available (SPV mode).');

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

RPC.prototype.verifychain = co(function* verifychain(args, help) {
  var valid = new Validator([args]);
  var level = valid.num(0);
  var blocks = valid.num(1);

  if (help || args.length > 2)
    throw new RPCError('verifychain ( checklevel numblocks )');

  if (level == null || blocks == null)
    throw new RPCError('Invalid parameter.');

  if (this.chain.options.spv)
    throw new RPCError('Cannot verify chain in SPV mode.');

  if (this.chain.options.prune)
    throw new RPCError('Cannot verify chain when pruned.');

  return null;
});

/*
 * Mining
 */

RPC.prototype._submitwork = co(function* _submitwork(data) {
  var unlock = yield this.locker.lock();
  try {
    return yield this.__submitwork(data);
  } finally {
    unlock();
  }
});

RPC.prototype.__submitwork = co(function* _submitwork(data) {
  var attempt = this.attempt;
  var block, entry, header, cb, cur;

  if (data.length !== 128)
    throw new RPCError('Invalid parameter.');

  if (!attempt)
    return false;

  data = data.slice(0, 80);
  data = swap32(data);

  header = Headers.fromAbbr(data);
  block = attempt.block;

  if (header.prevBlock !== block.prevBlock
      || header.bits !== block.bits) {
    return false;
  }

  if (!header.verify())
    return false;

  cb = this.coinbase[header.merkleRoot];

  if (!cb)
    return false;

  cur = block.txs[0];
  block.txs[0] = cb;
  attempt.updateMerkle();

  if (header.merkleRoot !== block.merkleRoot) {
    block.txs[0] = cur;
    attempt.updateMerkle();
    this.logger.warning('Bad calculated merkle root for submitted work.');
    return false;
  }

  block.ts = header.ts;
  attempt.commit(header.nonce);

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

RPC.prototype._creatework = co(function* _creatework(data) {
  var unlock = yield this.locker.lock();
  try {
    return yield this.__creatework(data);
  } finally {
    unlock();
  }
});

RPC.prototype.__creatework = co(function* _creatework() {
  var attempt = yield this._getAttempt(true);
  var data, abbr;

  data = new Buffer(128);
  data.fill(0);

  abbr = attempt.block.abbr();
  abbr.copy(data, 0);

  data[80] = 0x80;
  data.writeUInt32BE(80 * 8, data.length - 4, true);

  data = swap32(data);

  return {
    data: data.toString('hex'),
    target: attempt.target.toString('hex'),
    height: attempt.height
  };
});

RPC.prototype.getworklp = co(function* getworklp(args, help) {
  yield this._onBlock();
  return yield this._creatework();
});

RPC.prototype.getwork = co(function* getwork(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);

  if (args.length > 1)
    throw new RPCError('getwork ( "data" )');

  if (args.length === 1) {
    if (!data)
      throw new RPCError('Invalid parameter.');

    return yield this._submitwork(data);
  }

  return yield this._creatework();
});

RPC.prototype.submitblock = co(function* submitblock(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var block, tx;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('submitblock "hexdata" ( "jsonparametersobject" )');

  block = Block.fromRaw(data);

  // Fix eloipool bug (witness nonce is not present).
  if (this.chain.state.hasWitness() && block.getCommitmentHash()) {
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

  return yield this._submitblock(block);
});

RPC.prototype._submitblock = co(function* submitblock(block) {
  var unlock = yield this.locker.lock();
  try {
    return yield this.__submitblock(block);
  } finally {
    unlock();
  }
});

RPC.prototype.__submitblock = co(function* submitblock(block) {
  var entry;

  this.logger.info('Handling submitted block: %s.', block.rhash());

  try {
    entry = yield this.chain.add(block);
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

RPC.prototype.getblocktemplate = co(function* getblocktemplate(args, help) {
  var validator = new Validator([args]);
  var options = validator.obj(0, {});
  var valid = new Validator([options]);
  var mode = valid.str('mode', 'template');
  var lpid = valid.str('longpollid');
  var data = valid.buf('data');
  var rules = valid.array('rules');
  var capabilities = valid.array('capabilities');
  var version = valid.num('maxversion', -1);
  var coinbase = false;
  var i, cap, block, value, txn;

  if (help || args.length > 1)
    throw new RPCError('getblocktemplate ( "jsonrequestobject" )');

  if (mode !== 'template' && mode !== 'proposal')
    throw new RPCError('Invalid mode.');

  if (mode === 'proposal') {
    if (!data)
      throw new RPCError('Invalid parameter.');

    block = Block.fromRaw(data);

    return yield this._submitblock(block);
  }

  if (rules)
    version = -1;

  if (capabilities) {
    for (i = 0; i < capabilities.length; i++) {
      cap = capabilities[i];
      switch (cap) {
        case 'coinbasetxn':
          txn = true;
          break;
        case 'coinbasevalue':
          value = true;
          break;
        case 'coinbase/append':
          break;
      }
    }

    if (txn)
      coinbase = true;
  }

  if (!this.network.selfConnect) {
    if (this.pool.peers.size() === 0)
      throw new RPCError('Bitcoin is not connected!');

    if (!this.chain.synced)
      throw new RPCError('Bitcoin is downloading blocks...');
  }

  if (lpid)
    yield this._poll(lpid);

  return yield this._template(version, coinbase, rules);
});

RPC.prototype._template = co(function* _template(version, coinbase, rules) {
  var unlock = yield this.locker.lock();
  try {
    return yield this.__template(version, coinbase, rules);
  } finally {
    unlock();
  }
});

RPC.prototype.__template = co(function* _template(version, coinbase, rules) {
  var attempt = yield this._getAttempt(false);
  var scale = attempt.witness ? 1 : consensus.WITNESS_SCALE_FACTOR;
  var block = attempt.block;
  var mutable = ['time', 'transactions', 'prevblock'];
  var txs = [];
  var index = {};
  var vbavailable = {};
  var vbrules = [];
  var i, j, entry, tx, input, output;
  var dep, deps, json, name, deploy;
  var state;

  for (i = 0; i < attempt.items.length; i++) {
    entry = attempt.items[i];
    index[entry.hash] = i;
  }

  for (i = 0; i < attempt.items.length; i++) {
    entry = attempt.items[i];
    tx = entry.tx;
    deps = [];

    for (j = 0; j < tx.inputs.length; j++) {
      input = tx.inputs[j];
      dep = index[input.prevout.hash];
      if (dep != null && deps.indexOf(dep) === -1) {
        assert(dep < i);
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

  if (version >= 2)
    mutable.push('version/force');

  for (i = 0; i < this.network.deploys.length; i++) {
    deploy = this.network.deploys[i];
    state = yield this.chain.getState(this.chain.tip, deploy);
    name = deploy.name;

    switch (state) {
      case common.thresholdStates.DEFINED:
      case common.thresholdStates.FAILED:
        break;
      case common.thresholdStates.LOCKED_IN:
        block.version |= 1 << deploy.bit;
      case common.thresholdStates.STARTED:
        if (!deploy.force) {
          if (rules.indexOf(name) === -1)
            block.version &= ~(1 << deploy.bit);
          name = '!' + name;
        }
        vbavailable[name] = deploy.bit;
        break;
      case common.thresholdStates.ACTIVE:
        if (!deploy.force) {
          if (rules.indexOf(name) === -1)
            throw new RPCError('Client must support ' + name + '.');
          name = '!' + name;
        }
        vbrules.push(name);
        break;
      default:
        assert(false, 'Bad state.');
        break;
    }
  }

  block.version >>>= 0;

  json = {
    capabilities: ['proposal'],
    mutable: mutable,
    version: block.version,
    rules: vbrules,
    vbavailable: vbavailable,
    vbrequired: 0,
    height: attempt.height,
    previousblockhash: util.revHex(block.prevBlock),
    target: util.revHex(attempt.target.toString('hex')),
    bits: util.hex32(block.bits),
    noncerange: '00000000ffffffff',
    curtime: block.ts,
    mintime: block.ts,
    maxtime: block.ts + 7200,
    expires: block.ts + 7200,
    sigoplimit: consensus.MAX_BLOCK_SIGOPS_COST / scale | 0,
    sizelimit: consensus.MAX_BLOCK_SIZE,
    weightlimit: undefined,
    longpollid: this.chain.tip.rhash() + util.pad32(this._totalTX()),
    submitold: false,
    coinbaseaux: {
      flags: attempt.coinbaseFlags.toString('hex')
    },
    coinbasevalue: attempt.coinbase.getOutputValue(),
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

  if (coinbase) {
    tx = attempt.coinbase;

    // We don't include the commitment
    // output (see bip145).
    if (attempt.witness) {
      output = tx.outputs.pop();
      assert(output.script.isCommitment());
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

    if (attempt.witness)
      tx.outputs.push(output);
  }

  if (attempt.witness) {
    tx = attempt.coinbase;
    output = tx.outputs[tx.outputs.length - 1];
    assert(output.script.isCommitment());
    json.default_witness_commitment = output.script.toJSON();
  }

  return json;
});

RPC.prototype._poll = co(function* _poll(lpid) {
  var watched, lastTX;

  if (lpid.length !== 74)
    throw new RPCError('Invalid parameter.');

  watched = lpid.slice(0, 64);
  lastTX = +lpid.slice(64, 74);

  if (!util.isHex(watched) || !util.isNumber(lastTX))
    throw new RPCError('Invalid parameter.');

  watched = util.revHex(watched);

  if (this.chain.tip.hash !== watched)
    return;

  yield this._onBlock();
});

RPC.prototype._onBlock = function _onBlock() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.once('clear block', resolve);
  });
};

RPC.prototype._clearBlock = function _clearBlock() {
  this.attempt = null;
  this.start = 0;
  this.coinbase = {};
  this.emit('clear block');
};

RPC.prototype._bindChain = function _bindChain() {
  var self = this;

  if (this._boundChain)
    return;

  this._boundChain = true;

  this.node.on('connect', function() {
    if (!self.attempt)
      return;

    self._clearBlock();
  });

  if (!this.mempool)
    return;

  this.node.on('tx', function() {
    if (!self.attempt)
      return;

    if (util.now() - self.start > 10)
      self._clearBlock();
  });
};

RPC.prototype._getAttempt = co(function* _getAttempt(update) {
  var attempt = this.attempt;
  var block;

  this._bindChain();

  if (attempt) {
    block = attempt.block;
    if (update) {
      attempt.updateNonce();
      this.coinbase[block.merkleRoot] = attempt.coinbase.clone();
    }
    return attempt;
  }

  attempt = yield this.miner.createBlock();
  block = attempt.block;

  this.attempt = attempt;
  this.start = util.now();
  this.coinbase[block.merkleRoot] = attempt.coinbase.clone();

  return attempt;
});

RPC.prototype._totalTX = function _totalTX() {
  return this.mempool ? this.mempool.totalTX : 0;
};

RPC.prototype.getmininginfo = co(function* getmininginfo(args, help) {
  var attempt = this.attempt;
  var hashps;

  if (help || args.length !== 0)
    throw new RPCError('getmininginfo');

  hashps = yield this._hashps(120, -1);

  return {
    blocks: this.chain.height,
    currentblocksize: attempt ? attempt.block.getBaseSize() : 0,
    currentblocktx: attempt ? attempt.block.txs.length : 0,
    difficulty: this._getDifficulty(),
    errors: '',
    genproclimit: this.proclimit,
    networkhashps: hashps,
    pooledtx: this._totalTX(),
    testnet: this.network !== Network.main,
    chain: 'main',
    generate: this.mining
  };
});

RPC.prototype.getnetworkhashps = co(function* getnetworkhashps(args, help) {
  var valid = new Validator([args]);
  var lookup = valid.num(0, 120);
  var height = valid.num(1, -1);

  if (help || args.length > 2)
    throw new RPCError('getnetworkhashps ( blocks height )');

  return yield this._hashps(lookup, height);
});

RPC.prototype.prioritisetransaction = co(function* prioritisetransaction(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var pri = valid.num(1);
  var fee = valid.btc(2);
  var entry;

  if (help || args.length !== 3) {
    throw new RPCError('prioritisetransaction'
      + ' <txid> <priority delta> <fee delta>');
  }

  if (!this.mempool)
    throw new RPCError('No mempool available.');

  if (!hash)
    throw new RPCError('Invalid parameter');

  if (pri == null || fee == null)
    throw new RPCError('Invalid parameter');

  entry = this.mempool.getEntry(hash);

  if (!entry)
    throw new RPCError('Transaction not in mempool.');

  entry.priority += pri;
  entry.fee += fee;

  if (entry.priority < 0)
    entry.priority = 0;

  if (entry.fee < 0)
    entry.fee = 0;

  return true;
});

RPC.prototype._hashps = co(function* _hashps(lookup, height) {
  var tip = this.chain.tip;
  var i, minTime, maxTime, workDiff, timeDiff, ps, entry;

  if (height !== -1)
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
      throw new RPCError('Not found.');

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

RPC.prototype.verifyblock = co(function* verifyblock(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var block;

  if (help || args.length !== 1)
    throw new RPCError('verifyblock "block-hex"');

  if (!data)
    throw new RPCError('Invalid parameters.');

  if (this.chain.options.spv)
    throw new RPCError('Cannot verify block in SPV mode.');

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

RPC.prototype.getgenerate = co(function* getgenerate(args, help) {
  if (help || args.length !== 0)
    throw new RPCError('getgenerate');
  return this.mining;
});

RPC.prototype.setgenerate = co(function* setgenerate(args, help) {
  var valid = new Validator([args]);
  var mine = valid.bool(0, false);
  var limit = valid.num(0, 0);

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('setgenerate mine ( proclimit )');

  this.mining = mine;
  this.proclimit = limit;

  if (mine) {
    this.miner.start().catch(util.nop);
    return true;
  }

  yield this.miner.stop();

  return false;
});

RPC.prototype.generate = co(function* generate(args, help) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._generate(args);
  } finally {
    unlock();
  }
});

RPC.prototype._generate = co(function* generate(args, help) {
  var valid = new Validator([args]);
  var blocks = valid.num(0, 1);
  var tries = valid.num(1);

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('generate numblocks ( maxtries )');

  return yield this._generateBlocks(blocks, null, tries);
});

RPC.prototype._generateBlocks = co(function* _generateBlocks(blocks, address, tries) {
  var hashes = [];
  var i, block;

  for (i = 0; i < blocks; i++) {
    block = yield this.miner.mineBlock(null, address);
    hashes.push(block.rhash());
    assert(yield this.chain.add(block));
  }

  return hashes;
});

RPC.prototype.generatetoaddress = co(function* generatetoaddress(args, help) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._generatetoaddress(args);
  } finally {
    unlock();
  }
});

RPC.prototype._generatetoaddress = co(function* generatetoaddress(args, help) {
  var valid = new Validator([args]);
  var blocks = valid.num(0, 1);
  var addr = valid.str(1, '');
  var tries = valid.num(2, 1000000);

  if (help || args.length < 2 || args.length > 3)
    throw new RPCError('generatetoaddress numblocks address ( maxtries )');

  if (tries < 0)
    throw new RPCError('Invalid parameter.');

  addr = Address.fromBase58(addr, this.network);

  return yield this._generateBlocks(blocks, addr);
});

/*
 * Raw transactions
 */

RPC.prototype.createrawtransaction = co(function* createrawtransaction(args, help) {
  var valid = new Validator([args]);
  var inputs = valid.array(0);
  var sendTo = valid.obj(1);
  var locktime = valid.num(2, -1);
  var i, tx, input, output, hash, index, sequence;
  var keys, addrs, key, value, address, b58;

  if (help || args.length < 2 || args.length > 3) {
    throw new RPCError('createrawtransaction'
      + ' [{"txid":"id","vout":n},...]'
      + ' {"address":amount,"data":"hex",...}'
      + ' ( locktime )');
  }

  if (!inputs || !sendTo)
    throw new RPCError('Invalid parameter');

  tx = new TX();

  if (locktime !== -1)
    tx.setLocktime(locktime);

  for (i = 0; i < inputs.length; i++) {
    input = inputs[i];
    valid = new Validator([input]);

    hash = valid.hash('txid');
    index = valid.num('vout');
    sequence = valid.num('sequence');

    if (tx.locktime)
      sequence--;

    if (!hash || !util.isUInt32(index) || !util.isUInt32(sequence))
      throw new RPCError('Invalid parameter');

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
        throw new RPCError('Invalid parameter.');

      output = new Output();
      output.value = 0;
      output.script.fromNulldata(value);
      tx.outputs.push(output);

      continue;
    }

    address = Address.fromBase58(key, this.network);
    b58 = address.toBase58(this.network);

    if (addrs[b58])
      throw new RPCError('Duplicate address');

    addrs[b58] = true;

    value = valid.btc(key);

    if (value == null)
      throw new RPCError('Invalid parameter.');

    output = new Output();
    output.value = value;
    output.script.fromAddress(address);

    tx.outputs.push(output);
  }

  return tx.toRaw().toString('hex');
});

RPC.prototype.decoderawtransaction = co(function* decoderawtransaction(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var tx;

  if (help || args.length !== 1)
    throw new RPCError('decoderawtransaction "hexstring"');

  if (!data)
    throw new RPCError('Invalid parameter.');

  tx = TX.fromRaw(data);

  return this._txToJSON(tx);
});

RPC.prototype.decodescript = co(function* decodescript(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var script, address;

  if (help || args.length !== 1)
    throw new RPCError('decodescript "hex"');

  script = new Script();

  if (data)
    script.fromRaw(data);

  address = Address.fromScripthash(script.hash160());

  script = this._scriptToJSON(script);
  script.p2sh = address.toBase58(this.network);

  return script;
});

RPC.prototype.getrawtransaction = co(function* getrawtransaction(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var verbose = valid.bool(1, false);
  var json, meta, tx, entry;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getrawtransaction "txid" ( verbose )');

  if (!hash)
    throw new RPCError('Invalid parameter');

  meta = yield this.node.getMeta(hash);

  if (!meta)
    throw new RPCError('Transaction not found.');

  tx = meta.tx;

  if (!verbose)
    return tx.toRaw().toString('hex');

  if (meta.block)
    entry = yield this.chain.db.getEntry(meta.block);

  json = this._txToJSON(tx, entry);
  json.time = meta.ps;
  json.hex = tx.toRaw().toString('hex');

  return json;
});

RPC.prototype.sendrawtransaction = co(function* sendrawtransaction(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var tx;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('sendrawtransaction "hexstring" ( allowhighfees )');

  if (!data)
    throw new RPCError('Invalid parameter');

  tx = TX.fromRaw(data);

  this.node.relay(tx);

  return tx.txid();
});

RPC.prototype.signrawtransaction = co(function* signrawtransaction(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var tx;

  if (help || args.length < 1 || args.length > 4) {
    throw new RPCError('signrawtransaction'
      + ' "hexstring" ('
      + ' [{"txid":"id","vout":n,"scriptPubKey":"hex",'
      + 'redeemScript":"hex"},...] ["privatekey1",...]'
      + ' sighashtype )');
  }

  if (!data)
    throw new RPCError('Invalid parameter');

  tx = MTX.fromRaw(data);
  tx.view = yield this.mempool.getSpentView(tx);

  return yield this._signrawtransaction(tx, args);
});

RPC.prototype._signrawtransaction = co(function* signrawtransaction(tx, args) {
  var valid = new Validator([args]);
  var prevout = valid.array(1);
  var secrets = valid.array(2);
  var sighash = valid.str(3);
  var type = Script.hashType.ALL;
  var keys = [];
  var map = {};
  var i, j, secret, key;
  var coin, prev;
  var hash, index, script, value;
  var redeem, op, parts;

  if (secrets) {
    valid = new Validator([secrets]);
    for (i = 0; i < secrets.length; i++) {
      secret = valid.str(i, '');
      key = KeyRing.fromSecret(secret, this.network);
      map[key.getPublicKey('hex')] = key;
      keys.push(key);
    }
  }

  if (prevout) {
    for (i = 0; i < prevout.length; i++) {
      prev = prevout[i];
      valid = new Validator([prev]);
      hash = valid.hash('txid');
      index = valid.num('index');
      script = valid.buf('scriptPubKey');
      value = valid.btc('amount');
      redeem = valid.buf('redeemScript');

      if (!hash || index == null || !script || value == null)
        throw new RPCError('Invalid parameter');

      script = Script.fromRaw(script);

      coin = new Output();
      coin.script = script;
      coin.value = value;

      tx.view.addOutput(hash, index, coin);

      if (keys.length === 0 || !redeem)
        continue;

      if (!script.isScripthash() && !script.isWitnessScripthash())
        continue;

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
      throw new RPCError('Invalid parameter');

    if (parts.length > 2)
      throw new RPCError('Invalid parameter');

    if (parts.length === 2) {
      if (parts[1] !== 'ANYONECANPAY')
        throw new RPCError('Invalid parameter');
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

RPC.prototype.createmultisig = co(function* createmultisig(args, help) {
  var valid = new Validator([args]);
  var keys = valid.array(1, []);
  var m = valid.num(0, 0);
  var n = keys.length;
  var i, script, key, address;

  if (help || args.length < 2 || args.length > 2)
    throw new RPCError('createmultisig nrequired ["key",...]');

  if (m < 1 || n < m || n > 16)
    throw new RPCError('Invalid parameter.');

  valid = new Validator([keys]);

  for (i = 0; i < keys.length; i++) {
    key = valid.buf(i);

    if (!key)
      throw new RPCError('Invalid key.');

    if (!ec.publicKeyVerify(key))
      throw new RPCError('Invalid key.');

    keys[i] = key;
  }

  script = Script.fromMultisig(m, n, keys);

  if (script.getSize() > consensus.MAX_SCRIPT_PUSH)
    throw new RPCError('Redeem script exceeds size limit.');

  address = script.getAddress();

  return {
    address: address.toBase58(this.network),
    redeemScript: script.toJSON()
  };
});

RPC.prototype.createwitnessaddress = co(function* createwitnessaddress(args, help) {
  var valid = new Validator([args]);
  var raw = valid.buf(0);
  var script, program, address;

  if (help || args.length !== 1)
    throw new RPCError('createwitnessaddress "script"');

  if (!raw)
    throw new RPCError('Invalid parameter.');

  script = Script.fromRaw(raw);
  program = script.forWitness();
  address = program.getAddress();

  return {
    address: address.toBase58(this.network),
    witnessScript: program.toJSON()
  };
});

RPC.prototype.validateaddress = co(function* validateaddress(args, help) {
  var valid = new Validator([args]);
  var b58 = valid.str(0, '');
  var address, script;

  if (help || args.length !== 1)
    throw new RPCError('validateaddress "bitcoinaddress"');

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

RPC.prototype.verifymessage = co(function* verifymessage(args, help) {
  var valid = new Validator([args]);
  var b58 = valid.str(0, '');
  var sig = valid.buf(1, null, 'base64');
  var msg = valid.str(2);
  var hash = Address.getHash(b58);
  var key;

  if (help || args.length !== 3)
    throw new RPCError('verifymessage "bitcoinaddress" "signature" "message"');

  if (!hash || !sig || !msg)
    throw new RPCError('Invalid parameter.');

  msg = new Buffer(MAGIC_STRING + msg, 'utf8');
  msg = crypto.hash256(msg);

  key = ec.recover(msg, sig, 0, true);

  if (!key)
    return false;

  key = crypto.hash160(key);

  return crypto.ccmp(key, hash);
});

RPC.prototype.signmessagewithprivkey = co(function* signmessagewithprivkey(args, help) {
  var valid = new Validator([args]);
  var key = valid.str(0, '');
  var msg = valid.str(1, '');
  var sig;

  if (help || args.length !== 2)
    throw new RPCError('signmessagewithprivkey "privkey" "message"');

  key = KeyRing.fromSecret(key, this.network);
  msg = new Buffer(MAGIC_STRING + msg, 'utf8');
  msg = crypto.hash256(msg);

  sig = key.sign(msg);

  return sig.toString('base64');
});

RPC.prototype.estimatefee = co(function* estimatefee(args, help) {
  var valid = new Validator([args]);
  var blocks = valid.num(0, 1);
  var fee;

  if (help || args.length !== 1)
    throw new RPCError('estimatefee nblocks');

  if (!this.fees)
    throw new RPCError('Fee estimation not available.');

  if (blocks < 1)
    blocks = 1;

  fee = this.fees.estimateFee(blocks, false);

  if (fee === 0)
    return -1;

  return Amount.btc(fee, true);
});

RPC.prototype.estimatepriority = co(function* estimatepriority(args, help) {
  var valid = new Validator([args]);
  var blocks = valid.num(0, 1);

  if (help || args.length !== 1)
    throw new RPCError('estimatepriority nblocks');

  if (!this.fees)
    throw new RPCError('Priority estimation not available.');

  if (blocks < 1)
    blocks = 1;

  return this.fees.estimatePriority(blocks, false);
});

RPC.prototype.estimatesmartfee = co(function* estimatesmartfee(args, help) {
  var valid = new Validator([args]);
  var blocks = valid.num(0, 1);
  var fee;

  if (help || args.length !== 1)
    throw new RPCError('estimatesmartfee nblocks');

  if (!this.fees)
    throw new RPCError('Fee estimation not available.');

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

RPC.prototype.estimatesmartpriority = co(function* estimatesmartpriority(args, help) {
  var valid = new Validator([args]);
  var blocks = valid.num(0, 1);
  var pri;

  if (help || args.length !== 1)
    throw new RPCError('estimatesmartpriority nblocks');

  if (!this.fees)
    throw new RPCError('Priority estimation not available.');

  if (blocks < 1)
    blocks = 1;

  pri = this.fees.estimatePriority(blocks, true);

  return {
    priority: pri,
    blocks: blocks
  };
});

RPC.prototype.invalidateblock = co(function* invalidateblock(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);

  if (help || args.length !== 1)
    throw new RPCError('invalidateblock "hash"');

  if (!hash)
    throw new RPCError('Block not found.');

  this.chain.setInvalid(hash);

  return null;
});

RPC.prototype.reconsiderblock = co(function* reconsiderblock(args, help) {
  var valid = new Validator([args]);
  var hash = valid.hash(0);

  if (help || args.length !== 1)
    throw new RPCError('reconsiderblock "hash"');

  if (!hash)
    throw new RPCError('Block not found.');

  this.chain.removeInvalid(hash);

  return null;
});

RPC.prototype.setmocktime = co(function* setmocktime(args, help) {
  var valid = new Validator([args]);
  var ts = valid.num(0);
  var delta;

  if (help || args.length !== 1)
    throw new RPCError('setmocktime timestamp');

  if (ts == null)
    throw new RPCError('Invalid parameter.');

  this.network.time.offset = 0;

  delta = this.network.now() - ts;

  this.network.time.offset = -delta;

  return null;
});

RPC.prototype.getmemory = co(function* getmemory(args, help) {
  if (help || args.length !== 0)
    throw new RPCError('getmemory');

  return util.memoryUsage();
});

RPC.prototype.setloglevel = co(function* setloglevel(args, help) {
  var valid = new Validator([args]);
  var level = valid.str(0, '');

  if (help || args.length !== 1)
    throw new RPCError('setloglevel "level"');

  this.logger.setLevel(level);

  return null;
});

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

/*
 * Expose
 */

module.exports = RPC;
