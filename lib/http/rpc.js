/*!
 * rpc.js - bitcoind-compatible json rpc for bcoin.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
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
var Logger = require('../node/logger');
var IP = require('../utils/ip');
var encoding = require('../utils/encoding');
var consensus = require('../protocol/consensus');
var pkg = require('../pkg');

/**
 * Bitcoin Core RPC
 * @alias module:http.RPC
 * @constructor
 * @param {Node} node
 */

function RPC(node) {
  if (!(this instanceof RPC))
    return new RPC(node);

  EventEmitter.call(this);

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
}

util.inherits(RPC, EventEmitter);

RPC.magic = 'Bitcoin Signed Message:\n';

RPC.prototype.call = co(function* call(body, query) {
  var cmds = body;
  var out = [];
  var array = true;
  var i, cmd, result;

  if (!Array.isArray(cmds)) {
    cmds = [cmds];
    array = false;
  }

  for (i = 0; i < cmds.length; i++) {
    cmd = cmds[i];

    assert(cmd && typeof cmd === 'object', 'Command must be an object.');
    assert(typeof cmd.method === 'string', 'Method must be a string.');

    if (!cmd.params)
      cmd.params = [];

    assert(Array.isArray(cmd.params), 'Params must be an array.');

    if (!cmd.id)
      cmd.id = 0;

    assert(typeof cmd.id === 'number', 'ID must be a number.');
  }

  for (i = 0; i < cmds.length; i++) {
    cmd = cmds[i];

    if (cmd.method !== 'getwork'
        && cmd.method !== 'getblocktemplate'
        && cmd.method !== 'getbestblockhash') {
      this.logger.debug('Handling RPC call: %s.', cmd.method);
      if (cmd.method !== 'submitblock'
          && cmd.method !== 'getmemorypool') {
        this.logger.debug(cmd.params);
      }
    }

    if (cmd.method === 'getwork') {
      if (query.longpoll)
        cmd.method = 'getworklp';
    }

    try {
      result = yield this.execute(cmd);
    } catch (err) {
      if (err.type === 'RPCError') {
        out.push({
          result: null,
          error: {
            message: err.message,
            code: -1
          },
          id: cmd.id
        });
        continue;
      }

      this.logger.error(err);

      out.push({
        result: null,
        error: {
          message: err.message,
          code: 1
        },
        id: cmd.id
      });

      continue;
    }

    if (result === undefined)
      result = null;

    out.push({
      result: result,
      error: null,
      id: cmd.id
    });
  }

  if (!array)
    out = out[0];

  return out;
});

RPC.prototype.execute = function execute(json, help) {
  switch (json.method) {
    case 'stop':
      return this.stop(json.params, help);
    case 'help':
      return this.help(json.params, help);

    case 'getblockchaininfo':
      return this.getblockchaininfo(json.params, help);
    case 'getbestblockhash':
      return this.getbestblockhash(json.params, help);
    case 'getblockcount':
      return this.getblockcount(json.params, help);
    case 'getblock':
      return this.getblock(json.params, help);
    case 'getblockhash':
      return this.getblockhash(json.params, help);
    case 'getblockheader':
      return this.getblockheader(json.params, help);
    case 'getchaintips':
      return this.getchaintips(json.params, help);
    case 'getdifficulty':
      return this.getdifficulty(json.params, help);
    case 'getmempoolancestors':
      return this.getmempoolancestors(json.params, help);
    case 'getmempooldescendants':
      return this.getmempooldescendants(json.params, help);
    case 'getmempoolentry':
      return this.getmempoolentry(json.params, help);
    case 'getmempoolinfo':
      return this.getmempoolinfo(json.params, help);
    case 'getrawmempool':
      return this.getrawmempool(json.params, help);
    case 'gettxout':
      return this.gettxout(json.params, help);
    case 'gettxoutsetinfo':
      return this.gettxoutsetinfo(json.params, help);
    case 'verifychain':
      return this.verifychain(json.params, help);

    case 'invalidateblock':
      return this.invalidateblock(json.params, help);
    case 'reconsiderblock':
      return this.reconsiderblock(json.params, help);

    case 'getnetworkhashps':
      return this.getnetworkhashps(json.params, help);
    case 'getmininginfo':
      return this.getmininginfo(json.params, help);
    case 'prioritisetransaction':
      return this.prioritisetransaction(json.params, help);
    case 'getwork':
      return this.getwork(json.params, help);
    case 'getworklp':
      return this.getworklp(json.params, help);
    case 'getblocktemplate':
      return this.getblocktemplate(json.params, help);
    case 'submitblock':
      return this.submitblock(json.params, help);
    case 'verifyblock':
      return this.verifyblock(json.params, help);

    case 'setgenerate':
      return this.setgenerate(json.params, help);
    case 'getgenerate':
      return this.getgenerate(json.params, help);
    case 'generate':
      return this.generate(json.params, help);
    case 'generatetoaddress':
      return this.generatetoaddress(json.params, help);

    case 'estimatefee':
      return this.estimatefee(json.params, help);
    case 'estimatepriority':
      return this.estimatepriority(json.params, help);
    case 'estimatesmartfee':
      return this.estimatesmartfee(json.params, help);
    case 'estimatesmartpriority':
      return this.estimatesmartpriority(json.params, help);

    case 'getinfo':
      return this.getinfo(json.params, help);
    case 'validateaddress':
      return this.validateaddress(json.params, help);
    case 'createmultisig':
      return this.createmultisig(json.params, help);
    case 'createwitnessaddress':
      return this.createwitnessaddress(json.params, help);
    case 'verifymessage':
      return this.verifymessage(json.params, help);
    case 'signmessagewithprivkey':
      return this.signmessagewithprivkey(json.params, help);

    case 'setmocktime':
      return this.setmocktime(json.params, help);

    case 'getconnectioncount':
      return this.getconnectioncount(json.params, help);
    case 'ping':
      return this.ping(json.params, help);
    case 'getpeerinfo':
      return this.getpeerinfo(json.params, help);
    case 'addnode':
      return this.addnode(json.params, help);
    case 'disconnectnode':
      return this.disconnectnode(json.params, help);
    case 'getaddednodeinfo':
      return this.getaddednodeinfo(json.params, help);
    case 'getnettotals':
      return this.getnettotals(json.params, help);
    case 'getnetworkinfo':
      return this.getnetworkinfo(json.params, help);
    case 'setban':
      return this.setban(json.params, help);
    case 'listbanned':
      return this.listbanned(json.params, help);
    case 'clearbanned':
      return this.clearbanned(json.params, help);

    case 'getrawtransaction':
      return this.getrawtransaction(json.params, help);
    case 'createrawtransaction':
      return this.createrawtransaction(json.params, help);
    case 'decoderawtransaction':
      return this.decoderawtransaction(json.params, help);
    case 'decodescript':
      return this.decodescript(json.params, help);
    case 'sendrawtransaction':
      return this.sendrawtransaction(json.params, help);
    case 'signrawtransaction':
      return this.signrawtransaction(json.params, help);

    case 'gettxoutproof':
      return this.gettxoutproof(json.params, help);
    case 'verifytxoutproof':
      return this.verifytxoutproof(json.params, help);

    case 'getmemory':
      return this.getmemory(json.params, help);
    case 'setloglevel':
      return this.setloglevel(json.params, help);

    default:
      return this.custom(json, help);
  }
};

/**
 * Add a custom RPC call.
 * @param {String} name
 * @param {Function} func
 * @param {Object?} ctx
 */

RPC.prototype.add = function add(name, func, ctx) {
  assert(!this.calls[name], 'Duplicate RPC call.');
  this.calls[name] = func.bind(ctx);
};

/**
 * Execute a custom RPC call.
 * @private
 * @param {Object} json
 * @param {Boolean} help
 * @returns {Promise}
 */

RPC.prototype.custom = co(function* custom(json, help) {
  var call = this.calls[json.method];

  if (!call)
    throw new RPCError('Not found: ' + json.method + '.');

  return yield call(json.params, help);
});

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
  var node, cmd, addr, peer;

  if (help || args.length !== 2)
    throw new RPCError('addnode "node" "add|remove|onetry"');

  node = toString(args[0]);
  cmd = toString(args[1]);
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
  var addr, peer;

  if (help || args.length !== 1)
    throw new RPCError('disconnectnode "node"');

  addr = toString(args[0]);
  addr = IP.fromHostname(addr, this.network.port);

  peer = this.pool.peers.get(addr.hostname);

  if (peer)
    peer.destroy();

  return null;
});

RPC.prototype.getaddednodeinfo = co(function* getaddednodeinfo(args, help) {
  var out = [];
  var addr, peer;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getaddednodeinfo dummy ( "node" )');

  if (args.length === 2) {
    addr = toString(args[1]);
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
  var addr;

  if (help
      || args.length < 2
      || (args[1] !== 'add' && args[1] !== 'remove')) {
    throw new RPCError('setban "ip(/netmask)"'
      + ' "add|remove" (bantime) (absolute)');
  }

  addr = toString(args[0]);
  addr = NetAddress.fromHostname(addr, this.network);

  switch (args[1]) {
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
  var hash, verbose, entry, block;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getblock "hash" ( verbose )');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter.');

  verbose = true;

  if (args.length > 1)
    verbose = toBool(args[1]);

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
  var height, hash;

  if (help || args.length !== 1)
    throw new RPCError('getblockhash index');

  height = toNumber(args[0]);

  if (height < 0 || height > this.chain.height)
    throw new RPCError('Block height out of range.');

  hash = yield this.chain.db.getHash(height);

  if (!hash)
    throw new RPCError('Not found.');

  return util.revHex(hash);
});

RPC.prototype.getblockheader = co(function* getblockheader(args, help) {
  var hash, verbose, entry;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getblockheader "hash" ( verbose )');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter.');

  verbose = true;

  if (args.length > 1)
    verbose = toBool(args[1], true);

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
  var out = [];
  var i, hash, verbose, entry, entries;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getmempoolancestors txid (verbose)');

  if (!this.mempool)
    throw new RPCError('No mempool available.');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter.');

  if (args.length > 1)
    verbose = toBool(args[1], false);

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
  var out = [];
  var i, hash, verbose, entry, entries;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getmempooldescendants txid (verbose)');

  if (!this.mempool)
    throw new RPCError('No mempool available.');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter.');

  if (args.length > 1)
    verbose = toBool(args[1], false);

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
  var hash, entry;

  if (help || args.length !== 1)
    throw new RPCError('getmempoolentry txid');

  if (!this.mempool)
    throw new RPCError('No mempool available.');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter.');

  entry = this.mempool.getEntry(hash);

  if (!entry)
    throw new RPCError('Transaction not in mempool.');

  return this._entryToJSON(entry);
});

RPC.prototype.getrawmempool = co(function* getrawmempool(args, help) {
  var verbose;

  if (help || args.length > 1)
    throw new RPCError('getrawmempool ( verbose )');

  verbose = false;

  if (args.length > 0)
    verbose = toBool(args[0], false);

  return this._mempoolToJSON(verbose);
});

RPC.prototype._mempoolToJSON = function _mempoolToJSON(verbose) {
  var out = {};
  var i, hashes, hash, entry;

  if (verbose) {
    hashes = this.mempool.getSnapshot();

    for (i = 0; i < hashes.length; i++) {
      hash = hashes[i];
      entry = this.mempool.getEntry(hash);

      if (!entry)
        continue;

      out[entry.tx.txid()] = this._entryToJSON(entry);
    }

    return out;
  }

  hashes = this.mempool.getSnapshot();

  return hashes.map(util.revHex);
};

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
  var hash, index, mempool, coin;

  if (help || args.length < 2 || args.length > 3)
    throw new RPCError('gettxout "txid" n ( includemempool )');

  if (this.chain.options.spv)
    throw new RPCError('Cannot get coins in SPV mode.');

  if (this.chain.options.prune)
    throw new RPCError('Cannot get coins when pruned.');

  hash = toHash(args[0]);
  index = toNumber(args[1]);
  mempool = true;

  if (args.length > 2)
    mempool = toBool(args[2], true);

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
  var uniq = {};
  var i, txids, block, hash, txid, tx, coins;

  if (help || (args.length !== 1 && args.length !== 2))
    throw new RPCError('gettxoutproof ["txid",...] ( blockhash )');

  if (this.chain.options.spv)
    throw new RPCError('Cannot get coins in SPV mode.');

  if (this.chain.options.prune)
    throw new RPCError('Cannot get coins when pruned.');

  txids = toArray(args[0]);
  hash = args[1];

  if (!txids || txids.length === 0)
    throw new RPCError('Invalid parameter.');

  if (hash) {
    hash = toHash(hash);
    if (!hash)
      throw new RPCError('Invalid parameter.');
  }

  for (i = 0; i < txids.length; i++) {
    txid = toHash(txids[i]);

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
  var out = [];
  var i, block, hash, entry;

  if (help || args.length !== 1)
    throw new RPCError('verifytxoutproof "proof"');

  block = MerkleBlock.fromRaw(toString(args[0]), 'hex');

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
  if (help || args.length > 2)
    throw new RPCError('verifychain ( checklevel numblocks )');

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

  reverseEndian(data);

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

  reverseEndian(data);

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
  var data;

  if (args.length > 1)
    throw new RPCError('getwork ( "data" )');

  if (args.length === 1) {
    if (!util.isHex(args[0]))
      throw new RPCError('Invalid parameter.');

    data = new Buffer(args[0], 'hex');

    return yield this._submitwork(data);
  }

  return yield this._creatework();
});

RPC.prototype.submitblock = co(function* submitblock(args, help) {
  var block, tx;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('submitblock "hexdata" ( "jsonparametersobject" )');

  block = Block.fromRaw(toString(args[0]), 'hex');

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
  var mode = 'template';
  var version = -1;
  var coinbase = false;
  var rules = [];
  var i, opt, lpid, cap, block;
  var coinbasevalue, coinbasetxn;

  if (help || args.length > 1)
    throw new RPCError('getblocktemplate ( "jsonrequestobject" )');

  if (args.length === 1) {
    opt = args[0] || {};

    if (opt.mode != null) {
      mode = opt.mode;
      if (mode !== 'template' && mode !== 'proposal')
        throw new RPCError('Invalid mode.');
    }

    lpid = opt.longpollid;

    if (mode === 'proposal') {
      if (!util.isHex(opt.data))
        throw new RPCError('Invalid parameter.');

      block = Block.fromRaw(opt.data, 'hex');

      return yield this._submitblock(block);
    }

    if (Array.isArray(opt.rules)) {
      for (i = 0; i < opt.rules.length; i++)
        rules.push(toString(opt.rules[i]));
    } else if (util.isNumber(opt.maxversion)) {
      version = opt.maxversion;
    }

    if (Array.isArray(opt.capabilities)) {
      for (i = 0; i < opt.capabilities.length; i++) {
        cap = toString(opt.capabilities[i]);
        switch (cap) {
          case 'coinbasetxn':
            coinbasetxn = true;
            break;
          case 'coinbasevalue':
            coinbasevalue = true;
            break;
          case 'coinbase/append':
            break;
        }
      }

      if (coinbasetxn)
        coinbase = true;
    }
  }

  if (!this.network.selfConnect) {
    if (this.pool.peers.size() === 0)
      throw new RPCError('Bitcoin is not connected!');

    if (!this.chain.synced)
      throw new RPCError('Bitcoin is downloading blocks...');
  }

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

  if (typeof lpid !== 'string')
    return;

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
  var lookup = 120;
  var height = -1;

  if (help || args.length > 2)
    throw new RPCError('getnetworkhashps ( blocks height )');

  if (args.length > 0)
    lookup = toNumber(args[0], 120);

  if (args.length > 1)
    height = toNumber(args[1], -1);

  return yield this._hashps(lookup, height);
});

RPC.prototype.prioritisetransaction = co(function* prioritisetransaction(args, help) {
  var hash, pri, fee, entry;

  if (help || args.length !== 3) {
    throw new RPCError('prioritisetransaction'
      + ' <txid> <priority delta> <fee delta>');
  }

  if (!this.mempool)
    throw new RPCError('No mempool available.');

  hash = toHash(args[0]);
  pri = args[1];
  fee = args[2];

  if (!hash)
    throw new RPCError('Invalid parameter');

  if (!util.isNumber(pri) || !util.isNumber(fee))
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
  var block;

  if (help || args.length !== 1)
    throw new RPCError('verifyblock "block-hex"');

  if (typeof args[0] !== 'string')
    throw new RPCError('Invalid parameters.');

  if (this.chain.options.spv)
    throw new RPCError('Cannot verify block in SPV mode.');

  block = Block.fromRaw(args[0], 'hex');

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
  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('setgenerate mine ( proclimit )');

  this.mining = toBool(args[0]);
  this.proclimit = toNumber(args[1], 0);

  if (this.mining)
    this.miner.start().catch(util.nop);
  else
    yield this.miner.stop();

  return this.mining;
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
  var numblocks;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('generate numblocks ( maxtries )');

  numblocks = toNumber(args[0], 1);

  return yield this._generateBlocks(numblocks);
});

RPC.prototype._generateBlocks = co(function* _generateBlocks(blocks, address) {
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
  var numblocks, address;

  if (help || args.length < 2 || args.length > 3)
    throw new RPCError('generatetoaddress numblocks address ( maxtries )');

  numblocks = toNumber(args[0], 1);
  address = Address.fromBase58(toString(args[1]), this.network);

  return yield this._generateBlocks(numblocks, address);
});

/*
 * Raw transactions
 */

RPC.prototype.createrawtransaction = co(function* createrawtransaction(args, help) {
  var inputs, sendTo, tx, locktime;
  var i, input, output, hash, index, sequence;
  var keys, addrs, key, value, address, b58;

  if (help || args.length < 2 || args.length > 3) {
    throw new RPCError('createrawtransaction'
      + ' [{"txid":"id","vout":n},...]'
      + ' {"address":amount,"data":"hex",...}'
      + ' ( locktime )');
  }

  inputs = toArray(args[0]);
  sendTo = toObject(args[1]);

  if (!inputs || !sendTo)
    throw new RPCError('Invalid parameter');

  tx = new TX();

  if (args.length > 2 && args[2] != null) {
    locktime = toNumber(args[2]);
    if (!util.isUInt32(locktime))
      throw new RPCError('Locktime out of range');
    tx.locktime = locktime;
  }

  for (i = 0; i < inputs.length; i++) {
    input = inputs[i];

    if (!input)
      throw new RPCError('Invalid parameter');

    hash = toHash(input.txid);
    index = input.vout;
    sequence = 0xffffffff;

    if (tx.locktime)
      sequence--;

    if (!hash || !util.isUInt32(index))
      throw new RPCError('Invalid parameter');

    if (util.isNumber(input.sequence)) {
      sequence = toNumber(input.sequence);
      if (!util.isUInt32(sequence))
        throw new RPCError('Invalid parameter');
    }

    input = new Input();
    input.prevout.hash = hash;
    input.prevout.index = index;
    input.sequence = sequence;

    tx.inputs.push(input);
  }

  keys = Object.keys(sendTo);
  addrs = {};

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    value = sendTo[key];

    if (key === 'data') {
      value = new Buffer(value, 'hex');
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

    output = new Output();
    output.value = toSatoshi(value);
    output.script.fromAddress(address);

    tx.outputs.push(output);
  }

  return tx.toRaw().toString('hex');
});

RPC.prototype.decoderawtransaction = co(function* decoderawtransaction(args, help) {
  var tx;

  if (help || args.length !== 1)
    throw new RPCError('decoderawtransaction "hexstring"');

  tx = TX.fromRaw(toString(args[0]), 'hex');

  return this._txToJSON(tx);
});

RPC.prototype.decodescript = co(function* decodescript(args, help) {
  var data, script, address;

  if (help || args.length !== 1)
    throw new RPCError('decodescript "hex"');

  data = toString(args[0]);
  script = new Script();

  if (data.length > 0)
    script.fromRaw(new Buffer(data, 'hex'));

  address = Address.fromScripthash(script.hash160());

  script = this._scriptToJSON(script);
  script.p2sh = address.toBase58(this.network);

  return script;
});

RPC.prototype.getrawtransaction = co(function* getrawtransaction(args, help) {
  var hash, verbose, json, meta, tx, entry;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getrawtransaction "txid" ( verbose )');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter');

  verbose = false;

  if (args.length > 1)
    verbose = toBool(args[1]);

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
  var tx;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('sendrawtransaction "hexstring" ( allowhighfees )');

  if (!util.isHex(args[0]))
    throw new RPCError('Invalid parameter');

  tx = TX.fromRaw(args[0], 'hex');

  this.node.relay(tx);

  return tx.txid();
});

RPC.prototype.signrawtransaction = co(function* signrawtransaction(args, help) {
  var tx;

  if (help || args.length < 1 || args.length > 4) {
    throw new RPCError('signrawtransaction'
      + ' "hexstring" ('
      + ' [{"txid":"id","vout":n,"scriptPubKey":"hex",'
      + 'redeemScript":"hex"},...] ["privatekey1",...]'
      + ' sighashtype )');
  }

  if (!util.isHex(args[0]))
    throw new RPCError('Invalid parameter');

  tx = MTX.fromRaw(args[0], 'hex');
  tx.view = yield this.mempool.getSpentView(tx);

  return yield this._signrawtransaction(tx, args);
});

RPC.prototype._signrawtransaction = co(function* signrawtransaction(tx, args) {
  var type = Script.hashType.ALL;
  var keys = [];
  var keyMap = {};
  var i, j, k, secret, key;
  var coin, prevout, prev;
  var hash, index, script, value;
  var redeem, op, parts;

  if (args.length > 2 && Array.isArray(args[2])) {
    k = args[2];
    for (i = 0; i < k.length; i++) {
      secret = k[i];

      if (typeof secret !== 'string')
        throw new RPCError('Invalid parameter');

      key = KeyRing.fromSecret(secret, this.network);
      keyMap[key.getPublicKey('hex')] = key;
      keys.push(key);
    }
  }

  if (args.length > 1 && Array.isArray(args[1])) {
    prevout = args[1];

    for (i = 0; i < prevout.length; i++) {
      prev = prevout[i];

      if (!prev || typeof prev !== 'object')
        throw new RPCError('Invalid parameter');

      hash = toHash(prev.txid);
      index = prev.vout;
      script = prev.scriptPubKey;
      value = toSatoshi(prev.amount);

      if (!hash
          || !util.isUInt32(index)
          || !util.isHex(script)) {
        throw new RPCError('Invalid parameter');
      }

      script = Script.fromRaw(script, 'hex');

      coin = new Output();
      coin.script = script;
      coin.value = value;

      tx.view.addOutput(hash, index, coin);

      if (keys.length === 0 || !util.isHex(prev.redeemScript))
        continue;

      if (script.isScripthash() || script.isWitnessScripthash()) {
        redeem = Script.fromRaw(prev.redeemScript, 'hex');
        for (j = 0; j < redeem.code.length; j++) {
          op = redeem.code[j];

          if (!op.data)
            continue;

          key = keyMap[op.data.toString('hex')];

          if (key) {
            key.script = redeem;
            key.witness = script.isWitnessScripthash();
            key.refresh();
            break;
          }
        }
      }
    }
  }

  if (args.length > 3) {
    parts = toString(args[3]).split('|');
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

RPC.prototype.createwitnessaddress = co(function* createwitnessaddress(args, help) {
  var raw, script, program, address;

  if (help || args.length !== 1)
    throw new RPCError('createwitnessaddress "script"');

  raw = toString(args[1]);
  script = Script.fromRaw(raw, 'hex');
  program = script.forWitness();
  address = program.getAddress();

  return {
    address: address.toBase58(this.network),
    witnessScript: program.toJSON()
  };
});

RPC.prototype.validateaddress = co(function* validateaddress(args, help) {
  var b58, address, script;

  if (help || args.length !== 1)
    throw new RPCError('validateaddress "bitcoinaddress"');

  b58 = toString(args[0]);

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
  var address, sig, msg, hash, key;

  if (help || args.length !== 3)
    throw new RPCError('verifymessage "bitcoinaddress" "signature" "message"');

  address = toString(args[0]);
  sig = toString(args[1]);
  msg = toString(args[2]);

  hash = Address.getHash(address);

  if (!hash)
    throw new RPCError('Invalid address.');

  sig = new Buffer(sig, 'base64');
  msg = new Buffer(RPC.magic + msg, 'utf8');
  msg = crypto.hash256(msg);

  key = ec.recover(msg, sig, 0, true);

  if (!key)
    return false;

  key = crypto.hash160(key);

  return crypto.ccmp(key, hash);
});

RPC.prototype.signmessagewithprivkey = co(function* signmessagewithprivkey(args, help) {
  var key, msg, sig;

  if (help || args.length !== 2)
    throw new RPCError('signmessagewithprivkey "privkey" "message"');

  key = toString(args[0]);
  msg = toString(args[1]);

  key = KeyRing.fromSecret(key, this.network);
  msg = new Buffer(RPC.magic + msg, 'utf8');
  msg = crypto.hash256(msg);

  sig = key.sign(msg);

  return sig.toString('base64');
});

RPC.prototype.estimatefee = co(function* estimatefee(args, help) {
  var blocks, fee;

  if (help || args.length !== 1)
    throw new RPCError('estimatefee nblocks');

  if (!this.fees)
    throw new RPCError('Fee estimation not available.');

  blocks = toNumber(args[0], 1);

  if (blocks < 1)
    blocks = 1;

  fee = this.fees.estimateFee(blocks, false);

  if (fee === 0)
    fee = -1;
  else
    fee = Amount.btc(fee, true);

  return fee;
});

RPC.prototype.estimatepriority = co(function* estimatepriority(args, help) {
  var blocks, pri;

  if (help || args.length !== 1)
    throw new RPCError('estimatepriority nblocks');

  if (!this.fees)
    throw new RPCError('Priority estimation not available.');

  blocks = toNumber(args[0], 1);

  if (blocks < 1)
    blocks = 1;

  pri = this.fees.estimatePriority(blocks, false);

  return pri;
});

RPC.prototype.estimatesmartfee = co(function* estimatesmartfee(args, help) {
  var blocks, fee;

  if (help || args.length !== 1)
    throw new RPCError('estimatesmartfee nblocks');

  if (!this.fees)
    throw new RPCError('Fee estimation not available.');

  blocks = toNumber(args[0], 1);

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
  var blocks, pri;

  if (help || args.length !== 1)
    throw new RPCError('estimatesmartpriority nblocks');

  if (!this.fees)
    throw new RPCError('Priority estimation not available.');

  blocks = toNumber(args[0], 1);

  if (blocks < 1)
    blocks = 1;

  pri = this.fees.estimatePriority(blocks, true);

  return {
    priority: pri,
    blocks: blocks
  };
});

RPC.prototype.invalidateblock = co(function* invalidateblock(args, help) {
  var hash;

  if (help || args.length !== 1)
    throw new RPCError('invalidateblock "hash"');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Block not found.');

  this.chain.setInvalid(hash);

  return null;
});

RPC.prototype.reconsiderblock = co(function* reconsiderblock(args, help) {
  var hash;

  if (help || args.length !== 1)
    throw new RPCError('reconsiderblock "hash"');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Block not found.');

  this.chain.removeInvalid(hash);

  return null;
});

RPC.prototype.setmocktime = co(function* setmocktime(args, help) {
  var ts, delta;

  if (help || args.length !== 1)
    throw new RPCError('setmocktime timestamp');

  ts = toNumber(args[0]);

  if (ts < 0)
    throw new RPCError('Invalid parameter.');

  this.network.time.offset = 0;

  delta = this.network.now() - ts;

  this.network.time.offset = -delta;

  return null;
});

RPC.prototype.getmemory = co(function* getmemory(args, help) {
  var mem;

  if (help || args.length !== 0)
    throw new RPCError('getmemory');

  if (!process.memoryUsage)
    return {};

  mem = process.memoryUsage();

  return {
    rss: util.mb(mem.rss),
    jsheap: util.mb(mem.heapUsed),
    jsheaptotal: util.mb(mem.heapTotal),
    nativeheap: util.mb(mem.rss - mem.heapTotal)
  };
});

RPC.prototype.setloglevel = co(function* setloglevel(args, help) {
  var name, level;

  if (help || args.length !== 1)
    throw new RPCError('setloglevel "level"');

  name = toString(args[0]);
  level = Logger.levels[name];

  if (level == null)
    throw new RPCError('Bad log level.');

  this.logger.level = level;

  return null;
});

/*
 * Helpers
 */

function RPCError(msg) {
  Error.call(this);

  if (Error.captureStackTrace)
    Error.captureStackTrace(this, RPCError);

  this.type = 'RPCError';
  this.message = msg;
}

util.inherits(RPCError, Error);

function toBool(obj, def) {
  if (typeof obj === 'boolean' || typeof obj === 'number')
    return !!obj;
  return def || false;
}

function toNumber(obj, def) {
  if (util.isNumber(obj))
    return obj;
  return def != null ? def : -1;
}

function toString(obj, def) {
  if (typeof obj === 'string')
    return obj;
  return def != null ? def : '';
}

function toArray(obj, def) {
  if (Array.isArray(obj))
    return obj;
  return def != null ? def : null;
}

function toObject(obj, def) {
  if (obj && typeof obj === 'object')
    return obj;
  return def != null ? def : null;
}

function toHash(obj) {
  if (!isHash(obj))
    return null;
  return util.revHex(obj);
}

function isHash(obj) {
  return util.isHex(obj) && obj.length === 64;
}

function toSatoshi(obj) {
  if (typeof obj !== 'number')
    throw new RPCError('Bad BTC amount.');
  return Amount.value(obj, true);
}

function reverseEndian(data) {
  var i, field;
  for (i = 0; i < data.length; i += 4) {
    field = data.readUInt32LE(i, true);
    data.writeUInt32BE(field, i, true);
  }
}

/*
 * Expose
 */

module.exports = RPC;
