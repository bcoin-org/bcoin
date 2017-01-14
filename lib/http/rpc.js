/*!
 * rpc.js - bitcoind-compatible json rpc for bcoin.
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var fs = require('fs');
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
var Outpoint = require('../primitives/outpoint');
var Output = require('../primitives/output');
var TX = require('../primitives/tx');
var Logger = require('../node/logger');
var IP = require('../utils/ip');
var encoding = require('../utils/encoding');
var consensus = require('../protocol/consensus');
var pkg = require('../../package.json');

/**
 * RPC
 * @constructor
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
  this.wallet = node.wallet;
  this.walletdb = node.walletdb;
  this.logger = node.logger;

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

RPC.prototype.execute = function execute(json) {
  switch (json.method) {
    case 'stop':
      return this.stop(json.params);
    case 'help':
      return this.help(json.params);

    case 'getblockchaininfo':
      return this.getblockchaininfo(json.params);
    case 'getbestblockhash':
      return this.getbestblockhash(json.params);
    case 'getblockcount':
      return this.getblockcount(json.params);
    case 'getblock':
      return this.getblock(json.params);
    case 'getblockhash':
      return this.getblockhash(json.params);
    case 'getblockheader':
      return this.getblockheader(json.params);
    case 'getchaintips':
      return this.getchaintips(json.params);
    case 'getdifficulty':
      return this.getdifficulty(json.params);
    case 'getmempoolancestors':
      return this.getmempoolancestors(json.params);
    case 'getmempooldescendants':
      return this.getmempooldescendants(json.params);
    case 'getmempoolentry':
      return this.getmempoolentry(json.params);
    case 'getmempoolinfo':
      return this.getmempoolinfo(json.params);
    case 'getrawmempool':
      return this.getrawmempool(json.params);
    case 'gettxout':
      return this.gettxout(json.params);
    case 'gettxoutsetinfo':
      return this.gettxoutsetinfo(json.params);
    case 'verifychain':
      return this.verifychain(json.params);

    case 'invalidateblock':
      return this.invalidateblock(json.params);
    case 'reconsiderblock':
      return this.reconsiderblock(json.params);

    case 'getnetworkhashps':
      return this.getnetworkhashps(json.params);
    case 'getmininginfo':
      return this.getmininginfo(json.params);
    case 'prioritisetransaction':
      return this.prioritisetransaction(json.params);
    case 'getwork':
      return this.getwork(json.params);
    case 'getworklp':
      return this.getworklp(json.params);
    case 'getblocktemplate':
      return this.getblocktemplate(json.params);
    case 'submitblock':
      return this.submitblock(json.params);

    case 'setgenerate':
      return this.setgenerate(json.params);
    case 'getgenerate':
      return this.getgenerate(json.params);
    case 'generate':
      return this.generate(json.params);
    case 'generatetoaddress':
      return this.generatetoaddress(json.params);

    case 'estimatefee':
      return this.estimatefee(json.params);
    case 'estimatepriority':
      return this.estimatepriority(json.params);
    case 'estimatesmartfee':
      return this.estimatesmartfee(json.params);
    case 'estimatesmartpriority':
      return this.estimatesmartpriority(json.params);

    case 'getinfo':
      return this.getinfo(json.params);
    case 'validateaddress':
      return this.validateaddress(json.params);
    case 'createmultisig':
      return this.createmultisig(json.params);
    case 'createwitnessaddress':
      return this.createwitnessaddress(json.params);
    case 'verifymessage':
      return this.verifymessage(json.params);
    case 'signmessagewithprivkey':
      return this.signmessagewithprivkey(json.params);

    case 'setmocktime':
      return this.setmocktime(json.params);

    case 'getconnectioncount':
      return this.getconnectioncount(json.params);
    case 'ping':
      return this.ping(json.params);
    case 'getpeerinfo':
      return this.getpeerinfo(json.params);
    case 'addnode':
      return this.addnode(json.params);
    case 'disconnectnode':
      return this.disconnectnode(json.params);
    case 'getaddednodeinfo':
      return this.getaddednodeinfo(json.params);
    case 'getnettotals':
      return this.getnettotals(json.params);
    case 'getnetworkinfo':
      return this.getnetworkinfo(json.params);
    case 'setban':
      return this.setban(json.params);
    case 'listbanned':
      return this.listbanned(json.params);
    case 'clearbanned':
      return this.clearbanned(json.params);

    case 'getrawtransaction':
      return this.getrawtransaction(json.params);
    case 'createrawtransaction':
      return this.createrawtransaction(json.params);
    case 'decoderawtransaction':
      return this.decoderawtransaction(json.params);
    case 'decodescript':
      return this.decodescript(json.params);
    case 'sendrawtransaction':
      return this.sendrawtransaction(json.params);
    case 'signrawtransaction':
      return this.signrawtransaction(json.params);

    case 'gettxoutproof':
      return this.gettxoutproof(json.params);
    case 'verifytxoutproof':
      return this.verifytxoutproof(json.params);

    case 'fundrawtransaction':
      return this.fundrawtransaction(json.params);
    case 'resendwallettransactions':
      return this.resendwallettransactions(json.params);
    case 'abandontransaction':
      return this.abandontransaction(json.params);
    case 'addmultisigaddress':
      return this.addmultisigaddress(json.params);
    case 'addwitnessaddress':
      return this.addwitnessaddress(json.params);
    case 'backupwallet':
      return this.backupwallet(json.params);
    case 'dumpprivkey':
      return this.dumpprivkey(json.params);
    case 'dumpwallet':
      return this.dumpwallet(json.params);
    case 'encryptwallet':
      return this.encryptwallet(json.params);
    case 'getaccountaddress':
      return this.getaccountaddress(json.params);
    case 'getaccount':
      return this.getaccount(json.params);
    case 'getaddressesbyaccount':
      return this.getaddressesbyaccount(json.params);
    case 'getbalance':
      return this.getbalance(json.params);
    case 'getnewaddress':
      return this.getnewaddress(json.params);
    case 'getrawchangeaddress':
      return this.getrawchangeaddress(json.params);
    case 'getreceivedbyaccount':
      return this.getreceivedbyaccount(json.params);
    case 'getreceivedbyaddress':
      return this.getreceivedbyaddress(json.params);
    case 'gettransaction':
      return this.gettransaction(json.params);
    case 'getunconfirmedbalance':
      return this.getunconfirmedbalance(json.params);
    case 'getwalletinfo':
      return this.getwalletinfo(json.params);
    case 'importprivkey':
      return this.importprivkey(json.params);
    case 'importwallet':
      return this.importwallet(json.params);
    case 'importaddress':
      return this.importaddress(json.params);
    case 'importprunedfunds':
      return this.importprunedfunds(json.params);
    case 'importpubkey':
      return this.importpubkey(json.params);
    case 'keypoolrefill':
      return this.keypoolrefill(json.params);
    case 'listaccounts':
      return this.listaccounts(json.params);
    case 'listaddressgroupings':
      return this.listaddressgroupings(json.params);
    case 'listlockunspent':
      return this.listlockunspent(json.params);
    case 'listreceivedbyaccount':
      return this.listreceivedbyaccount(json.params);
    case 'listreceivedbyaddress':
      return this.listreceivedbyaddress(json.params);
    case 'listsinceblock':
      return this.listsinceblock(json.params);
    case 'listtransactions':
      return this.listtransactions(json.params);
    case 'listunspent':
      return this.listunspent(json.params);
    case 'lockunspent':
      return this.lockunspent(json.params);
    case 'move':
      return this.move(json.params);
    case 'sendfrom':
      return this.sendfrom(json.params);
    case 'sendmany':
      return this.sendmany(json.params);
    case 'sendtoaddress':
      return this.sendtoaddress(json.params);
    case 'setaccount':
      return this.setaccount(json.params);
    case 'settxfee':
      return this.settxfee(json.params);
    case 'signmessage':
      return this.signmessage(json.params);
    case 'walletlock':
      return this.walletlock(json.params);
    case 'walletpassphrasechange':
      return this.walletpassphrasechange(json.params);
    case 'walletpassphrase':
      return this.walletpassphrase(json.params);
    case 'removeprunedfunds':
      return this.removeprunedfunds(json.params);

    case 'getmemory':
      return this.getmemory(json.params);
    case 'selectwallet':
      return this.selectwallet(json.params);
    case 'setloglevel':
      return this.setloglevel(json.params);

    default:
      return Promise.reject(new Error('Not found: ' + json.method + '.'));
  }
};

/*
 * Overall control/query calls
 */

RPC.prototype.getinfo = co(function* getinfo(args) {
  var balance;

  if (args.help || args.length !== 0)
    throw new RPCError('getinfo');

  balance = yield this.wallet.getBalance();

  return {
    version: pkg.version,
    protocolversion: this.pool.protoVersion,
    walletversion: 0,
    balance: Amount.btc(balance.unconfirmed, true),
    blocks: this.chain.height,
    timeoffset: this.network.time.offset,
    connections: this.pool.peers.size(),
    proxy: '',
    difficulty: this._getDifficulty(),
    testnet: this.network.type !== Network.main,
    keypoololdest: 0,
    keypoolsize: 0,
    unlocked_until: this.wallet.master.until,
    paytxfee: Amount.btc(this.network.feeRate, true),
    relayfee: Amount.btc(this.network.minRelay, true),
    errors: ''
  };
});

RPC.prototype.help = co(function* help(args) {
  var json;

  if (args.length === 0)
    return 'Select a command.';

  json = {
    method: args[0],
    params: []
  };

  json.params.help = true;

  return yield this.execute(json);
});

RPC.prototype.stop = co(function* stop(args) {
  if (args.help || args.length !== 0)
    throw new RPCError('stop');

  this.node.close();

  return 'Stopping.';
});

/*
 * P2P networking
 */

RPC.prototype.getnetworkinfo = co(function* getnetworkinfo(args) {
  if (args.help || args.length !== 0)
    throw new RPCError('getnetworkinfo');

  return {
    version: pkg.version,
    subversion: this.pool.userAgent,
    protocolversion: this.pool.protoVersion,
    localservices: this.pool.address.services,
    timeoffset: this.network.time.offset,
    connections: this.pool.peers.size(),
    networks: [],
    relayfee: Amount.btc(this.network.minRelay, true),
    localaddresses: [],
    warnings: ''
  };
});

RPC.prototype.addnode = co(function* addnode(args) {
  var node, cmd, addr, peer;

  if (args.help || args.length !== 2)
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

RPC.prototype.disconnectnode = co(function* disconnectnode(args) {
  var addr, peer;

  if (args.help || args.length !== 1)
    throw new RPCError('disconnectnode "node"');

  addr = toString(args[0]);
  addr = IP.parseHost(addr, this.network.port);

  peer = this.pool.peers.get(addr.hostname);

  if (peer)
    peer.destroy();

  return null;
});

RPC.prototype.getaddednodeinfo = co(function* getaddednodeinfo(args) {
  var out = [];
  var addr, peer;

  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('getaddednodeinfo dummy ( "node" )');

  if (args.length === 2) {
    addr = toString(args[1]);
    addr = IP.parseHost(addr, this.network.port);
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
    addednode: peer.hostname,
    connected: peer.connected,
    addresses: [
      {
        address: peer.hostname,
        connected: peer.outbound
          ? 'outbound'
          : 'inbound'
      }
    ]
  };
};

RPC.prototype.getconnectioncount = co(function* getconnectioncount(args) {
  if (args.help || args.length !== 0)
    throw new RPCError('getconnectioncount');

  return this.pool.peers.size();
});

RPC.prototype.getnettotals = co(function* getnettotals(args) {
  var sent = 0;
  var recv = 0;
  var peer;

  if (args.help || args.length > 0)
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

RPC.prototype.getpeerinfo = co(function* getpeerinfo(args) {
  var peers = [];
  var id = 0;
  var peer, offset;

  if (args.help || args.length !== 0)
    throw new RPCError('getpeerinfo');

  for (peer = this.pool.peers.head(); peer; peer = peer.next) {
    offset = this.network.time.known[peer.hostname];

    if (offset == null)
      offset = 0;

    peers.push({
      id: id++,
      addr: peer.hostname,
      addrlocal: peer.hostname,
      relaytxes: peer.outbound,
      lastsend: peer.lastSend / 1000 | 0,
      lastrecv: peer.lastRecv / 1000 | 0,
      bytessent: peer.socket.bytesWritten,
      bytesrecv: peer.socket.bytesRead,
      conntime: peer.ts !== 0 ? util.now() - peer.ts : 0,
      timeoffset: offset,
      pingtime: peer.lastPong !== -1
        ? (peer.lastPong - peer.lastPing) / 1000
        : -1,
      minping: peer.minPing !== -1 ? peer.minPing / 1000 : -1,
      version: peer.version ? peer.version.version : 0,
      subver: peer.version ? peer.version.agent : '',
      inbound: !peer.outbound,
      startingheight: peer.version ? peer.version.height : -1,
      banscore: peer.banScore,
      inflight: peer.requestMap.keys().map(util.revHex),
      whitelisted: false
    });
  }

  return peers;
});

RPC.prototype.ping = co(function* ping(args) {
  var peer;

  if (args.help || args.length !== 0)
    throw new RPCError('ping');

  for (peer = this.pool.peers.head(); peer; peer = peer.next)
    peer.sendPing();

  return null;
});

RPC.prototype.setban = co(function* setban(args) {
  var addr;

  if (args.help
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

RPC.prototype.listbanned = co(function* listbanned(args) {
  var i, banned, keys, host, time;

  if (args.help || args.length !== 0)
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

RPC.prototype.clearbanned = co(function* clearbanned(args) {
  if (args.help || args.length !== 0)
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
  var i, deployment, state;

  for (i = 0; i < this.network.deploys.length; i++) {
    deployment = this.network.deploys[i];
    state = yield this.chain.getState(tip, deployment);

    switch (state) {
      case common.thresholdStates.DEFINED:
        state = 'defined';
        break;
      case common.thresholdStates.STARTED:
        state = 'started';
        break;
      case common.thresholdStates.LOCKED_IN:
        state = 'locked_in';
        break;
      case common.thresholdStates.ACTIVE:
        state = 'active';
        break;
      case common.thresholdStates.FAILED:
        state = 'failed';
        break;
    }

    forks[deployment.name] = {
      status: state,
      bit: deployment.bit,
      startTime: deployment.startTime,
      timeout: deployment.timeout
    };
  }

  return forks;
});

/* Block chain and UTXO */
RPC.prototype.getblockchaininfo = co(function* getblockchaininfo(args) {
  if (args.help || args.length !== 0)
    throw new RPCError('getblockchaininfo');

  return {
    chain: 'main',
    blocks: this.chain.height,
    headers: this.chain.height,
    bestblockhash: this.chain.tip.rhash(),
    difficulty: this._getDifficulty(),
    mediantime: yield this.chain.tip.getMedianTimeAsync(),
    verificationprogress: this.chain.getProgress(),
    chainwork: this.chain.tip.chainwork.toString('hex', 64),
    pruned: this.chain.options.prune,
    softforks: this._getSoftforks(),
    bip9_softforks: yield this._getBIP9Softforks(),
    pruneheight: this.chain.options.prune
      ? Math.max(0, this.chain.height - this.chain.db.keepBlocks)
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

RPC.prototype.getbestblockhash = co(function* getbestblockhash(args) {
  if (args.help || args.length !== 0)
    throw new RPCError('getbestblockhash');

  return this.chain.tip.rhash();
});

RPC.prototype.getblockcount = co(function* getblockcount(args) {
  if (args.help || args.length !== 0)
    throw new RPCError('getblockcount');

  return this.chain.tip.height;
});

RPC.prototype.getblock = co(function* getblock(args) {
  var hash, verbose, entry, block;

  if (args.help || args.length < 1 || args.length > 2)
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
        out.txid = input.prevout.rhash();
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

RPC.prototype.getblockhash = co(function* getblockhash(args) {
  var height, hash;

  if (args.help || args.length !== 1)
    throw new RPCError('getblockhash index');

  height = toNumber(args[0]);

  if (height < 0 || height > this.chain.height)
    throw new RPCError('Block height out of range.');

  hash = yield this.chain.db.getHash(height);

  if (!hash)
    throw new RPCError('Not found.');

  return util.revHex(hash);
});

RPC.prototype.getblockheader = co(function* getblockheader(args) {
  var hash, verbose, entry;

  if (args.help || args.length < 1 || args.length > 2)
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
  var medianTime = yield entry.getMedianTimeAsync();
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
  var medianTime = yield entry.getMedianTimeAsync();
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

RPC.prototype.getchaintips = co(function* getchaintips(args) {
  var i, hash, tips, result, entry, fork, main;

  if (args.help || args.length !== 0)
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

RPC.prototype.getdifficulty = co(function* getdifficulty(args) {
  if (args.help || args.length !== 0)
    throw new RPCError('getdifficulty');

  return this._getDifficulty();
});

RPC.prototype.getmempoolinfo = co(function* getmempoolinfo(args) {
  if (args.help || args.length !== 0)
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

RPC.prototype.getmempoolancestors = co(function* getmempoolancestors(args) {
  var out = [];
  var i, hash, verbose, entry, entries;

  if (args.help || args.length < 1 || args.length > 2)
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

  entries = this.mempool.getAncestors(entry.tx);

  if (verbose) {
    for (i = 0; i < entries.length; i++) {
      entry = entries[i];
      out.push(this._entryToJSON(entry));
    }
  } else {
    for (i = 0; i < entries.length; i++) {
      entry = entries[i];
      out.push(entry.tx.txid());
    }
  }

  return out;
});

RPC.prototype.getmempooldescendants = co(function* getmempooldescendants(args) {
  var out = [];
  var i, hash, verbose, entry, entries;

  if (args.help || args.length < 1 || args.length > 2)
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

  entries = this.mempool.getDescendants(entry.tx);

  if (verbose) {
    for (i = 0; i < entries.length; i++) {
      entry = entries[i];
      out.push(this._entryToJSON(entry));
    }
  } else {
    for (i = 0; i < entries.length; i++) {
      entry = entries[i];
      out.push(entry.tx.txid());
    }
  }

  return out;
});

RPC.prototype.getmempoolentry = co(function* getmempoolentry(args) {
  var hash, entry;

  if (args.help || args.length !== 1)
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

RPC.prototype.getrawmempool = co(function* getrawmempool(args) {
  var verbose;

  if (args.help || args.length > 1)
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
  var tx = entry.tx;
  return {
    size: entry.size,
    fee: Amount.btc(entry.fee, true),
    modifiedfee: Amount.btc(entry.fee, true),
    time: entry.ts,
    height: entry.height,
    startingpriority: entry.priority,
    currentpriority: entry.getPriority(this.chain.height),
    descendantcount: this.mempool.countDescendants(tx),
    descendantsize: entry.sizes,
    descendantfees: Amount.btc(entry.fee, true),
    ancestorcount: this.mempool.countAncestors(tx),
    ancestorsize: entry.sizes,
    ancestorfees: Amount.btc(entry.fee, true),
    depends: this.mempool.getDepends(tx).map(util.revHex)
  };
};

RPC.prototype.gettxout = co(function* gettxout(args) {
  var hash, index, mempool, coin;

  if (args.help || args.length < 2 || args.length > 3)
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

RPC.prototype.gettxoutproof = co(function* gettxoutproof(args) {
  var uniq = {};
  var i, txids, block, hash, txid, tx, coins;

  if (args.help || (args.length !== 1 && args.length !== 2))
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

RPC.prototype.verifytxoutproof = co(function* verifytxoutproof(args) {
  var out = [];
  var i, block, hash, entry;

  if (args.help || args.length !== 1)
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

RPC.prototype.gettxoutsetinfo = co(function* gettxoutsetinfo(args) {
  if (args.help || args.length !== 0)
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

RPC.prototype.verifychain = co(function* verifychain(args) {
  if (args.help || args.length > 2)
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
  var block, header, cb, cur;

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
    yield this.chain.add(block);
  } catch (err) {
    if (err.type === 'VerifyError') {
      this.logger.warning('RPC block rejected: %s (%s).',
        block.rhash(), err.reason);
      return false;
    }
    throw err;
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

RPC.prototype.getworklp = co(function* getworklp(args) {
  yield this._onBlock();
  return yield this._creatework();
});

RPC.prototype.getwork = co(function* getwork(args) {
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

RPC.prototype.submitblock = co(function* submitblock(args) {
  var block, tx;

  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('submitblock "hexdata" ( "jsonparametersobject" )');

  block = Block.fromRaw(toString(args[0]), 'hex');

  // Fix eloipool bug (witness nonce is not present).
  if (block.getCommitmentHash()) {
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
  this.logger.info('Handling submitted block: %s.', block.rhash());

  try {
    yield this.chain.add(block);
  } catch (err) {
    if (err.type === 'VerifyError') {
      this.logger.warning('RPC block rejected: %s (%s).',
        block.rhash(), err.reason);
      return 'rejected: ' + err.reason;
    }
    throw err;
  }

  return null;
});

RPC.prototype.getblocktemplate = co(function* getblocktemplate(args) {
  var mode = 'template';
  var version = -1;
  var coinbase = false;
  var i, opt, lpid, rules, cap, block;
  var coinbasevalue, coinbasetxn;

  if (args.help || args.length > 1)
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
      rules = [];
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

    if (!this.chain.isFull())
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
        vbavailable[name] = deploy.bit;
        if (rules) {
          if (rules.indexOf(name) === -1 && !deploy.force)
            block.version &= ~(1 << deploy.bit);
        }
        break;
      case common.thresholdStates.ACTIVE:
        if (rules) {
          if (rules.indexOf(name) === -1 && !deploy.force)
            throw new RPCError('Client must support ' + name + '.');
        }
        if (!deploy.force)
          name = '!' + name;
        vbrules.push(name);
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
    // NOTE: The BIP says this is supposed
    // to be big-endian, which is _incorrect_.
    target: attempt.target.toString('hex'),
    bits: util.hex32(block.bits),
    noncerange: '00000000ffffffff',
    curtime: block.ts,
    mintime: block.ts,
    maxtime: block.ts + 7200,
    expires: block.ts + 7200,
    sigoplimit: consensus.MAX_BLOCK_SIGOPS_COST / scale | 0,
    sizelimit: consensus.MAX_RAW_BLOCK_SIZE,
    weightlimit: consensus.MAX_BLOCK_WEIGHT,
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

RPC.prototype.getmininginfo = co(function* getmininginfo(args) {
  var attempt = this.attempt;
  var hashps;

  if (args.help || args.length !== 0)
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

RPC.prototype.getnetworkhashps = co(function* getnetworkhashps(args) {
  var lookup = 120;
  var height = -1;

  if (args.help || args.length > 2)
    throw new RPCError('getnetworkhashps ( blocks height )');

  if (args.length > 0)
    lookup = toNumber(args[0], 120);

  if (args.length > 1)
    height = toNumber(args[1], -1);

  return yield this._hashps(lookup, height);
});

RPC.prototype.prioritisetransaction = co(function* prioritisetransaction(args) {
  var hash, pri, fee, entry;

  if (args.help || args.length !== 3) {
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

/*
 * Coin generation
 */

RPC.prototype.getgenerate = co(function* getgenerate(args) {
  if (args.help || args.length !== 0)
    throw new RPCError('getgenerate');
  return this.mining;
});

RPC.prototype.setgenerate = co(function* setgenerate(args) {
  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('setgenerate mine ( proclimit )');

  this.mining = toBool(args[0]);
  this.proclimit = toNumber(args[1], 0);

  if (this.mining)
    this.miner.start().catch(util.nop);
  else
    yield this.miner.stop();

  return this.mining;
});

RPC.prototype.generate = co(function* generate(args) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._generate(args);
  } finally {
    unlock();
  }
});

RPC.prototype._generate = co(function* generate(args) {
  var numblocks;

  if (args.help || args.length < 1 || args.length > 2)
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
    yield this.chain.add(block);
  }

  return hashes;
});

RPC.prototype.generatetoaddress = co(function* generatetoaddress(args) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._generatetoaddress(args);
  } finally {
    unlock();
  }
});

RPC.prototype._generatetoaddress = co(function* generatetoaddress(args) {
  var numblocks, address;

  if (args.help || args.length < 2 || args.length > 3)
    throw new RPCError('generatetoaddress numblocks address ( maxtries )');

  numblocks = toNumber(args[0], 1);
  address = Address.fromBase58(toString(args[1]));

  return yield this._generateBlocks(numblocks, address);
});

/*
 * Raw transactions
 */

RPC.prototype.createrawtransaction = co(function* createrawtransaction(args) {
  var inputs, sendTo, tx, locktime;
  var i, input, output, hash, index, sequence;
  var keys, addrs, key, value, address, b58;

  if (args.help || args.length < 2 || args.length > 3) {
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

    address = Address.fromBase58(key);
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

RPC.prototype.decoderawtransaction = co(function* decoderawtransaction(args) {
  var tx;

  if (args.help || args.length !== 1)
    throw new RPCError('decoderawtransaction "hexstring"');

  tx = TX.fromRaw(toString(args[0]), 'hex');

  return this._txToJSON(tx);
});

RPC.prototype.decodescript = co(function* decodescript(args) {
  var data, script, address;

  if (args.help || args.length !== 1)
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

RPC.prototype.getrawtransaction = co(function* getrawtransaction(args) {
  var hash, verbose, json, tx;

  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('getrawtransaction "txid" ( verbose )');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter');

  verbose = false;

  if (args.length > 1)
    verbose = Boolean(args[1]);

  tx = yield this.node.getTX(hash);

  if (!tx)
    throw new RPCError('Transaction not found.');

  if (!verbose)
    return tx.toRaw().toString('hex');

  json = this._txToJSON(tx);
  json.hex = tx.toRaw().toString('hex');

  return json;
});

RPC.prototype.sendrawtransaction = co(function* sendrawtransaction(args) {
  var tx;

  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('sendrawtransaction "hexstring" ( allowhighfees )');

  if (!util.isHex(args[0]))
    throw new RPCError('Invalid parameter');

  tx = TX.fromRaw(args[0], 'hex');

  this.node.sendTX(tx).catch(util.nop);

  return tx.txid();
});

RPC.prototype.signrawtransaction = co(function* signrawtransaction(args) {
  var wallet = this.wallet;
  var tx;

  if (args.help || args.length < 1 || args.length > 4) {
    throw new RPCError('signrawtransaction'
      + ' "hexstring" ('
      + ' [{"txid":"id","vout":n,"scriptPubKey":"hex",'
      + 'redeemScript":"hex"},...] ["privatekey1",...]'
      + ' sighashtype )');
  }

  if (!util.isHex(args[0]))
    throw new RPCError('Invalid parameter');

  tx = MTX.fromRaw(args[0], 'hex');
  tx.view = yield wallet.getCoinView(tx);

  return yield this._signrawtransaction(wallet, tx, args);
});

RPC.prototype._signrawtransaction = co(function* signrawtransaction(wallet, tx, args) {
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

      key = KeyRing.fromSecret(secret);
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
  yield wallet.sign(tx, { type: type });

  return {
    hex: tx.toRaw().toString('hex'),
    complete: tx.isSigned()
  };
});

RPC.prototype.fundrawtransaction = co(function* fundrawtransaction(args) {
  var wallet = this.wallet;
  var tx, options, changeAddress, feeRate;

  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('fundrawtransaction "hexstring" ( options )');

  if (!util.isHex(args[0]))
    throw new RPCError('Invalid parameter.');

  tx = MTX.fromRaw(args[0], 'hex');

  if (tx.outputs.length === 0)
    throw new RPCError('TX must have at least one output.');

  if (args.length > 1) {
    options = toObject(args[1]);
    changeAddress = toString(options.changeAddress);

    if (changeAddress)
      changeAddress = Address.fromBase58(changeAddress);

    feeRate = options.feeRate;

    if (feeRate != null)
      feeRate = toSatoshi(feeRate);
  }

  options = {
    rate: feeRate,
    changeAddress: changeAddress
  };

  yield wallet.fund(tx, options);

  return {
    hex: tx.toRaw().toString('hex'),
    changepos: tx.changeIndex,
    fee: Amount.btc(tx.getFee(), true)
  };
});

RPC.prototype._createRedeem = co(function* _createRedeem(args) {
  var wallet = this.wallet;
  var i, m, n, keys, hash, script, key, ring;

  if (!util.isNumber(args[0])
      || !Array.isArray(args[1])
      || args[0] < 1
      || args[1].length < args[0]
      || args[1].length > 16) {
    throw new RPCError('Invalid parameter.');
  }

  m = args[0];
  n = args[1].length;
  keys = args[1];

  for (i = 0; i < keys.length; i++) {
    key = keys[i];

    if (!util.isBase58(key)) {
      if (!util.isHex(key))
        throw new RPCError('Invalid key.');
      keys[i] = new Buffer(key, 'hex');
      continue;
    }

    hash = Address.getHash(key, 'hex');

    if (!hash)
      throw new RPCError('Invalid key.');

    ring = yield wallet.getKey(hash);

    if (!ring)
      throw new RPCError('Invalid key.');

    keys[i] = ring.publicKey;
  }

  try {
    script = Script.fromMultisig(m, n, keys);
  } catch (e) {
    throw new RPCError('Invalid parameters.');
  }

  if (script.getSize() > consensus.MAX_SCRIPT_PUSH)
    throw new RPCError('Redeem script exceeds size limit.');

  return script;
});

/*
 * Utility Functions
 */

RPC.prototype.createmultisig = co(function* createmultisig(args) {
  var script, address;

  if (args.help || args.length < 2 || args.length > 2)
    throw new RPCError('createmultisig nrequired ["key",...]');

  script = yield this._createRedeem(args);
  address = script.getAddress();

  return {
    address: address.toBase58(this.network),
    redeemScript: script.toJSON()
  };
});

RPC.prototype.createwitnessaddress = co(function* createwitnessaddress(args) {
  var raw, script, program, address;

  if (args.help || args.length !== 1)
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

RPC.prototype.validateaddress = co(function* validateaddress(args) {
  var wallet = this.wallet;
  var b58, address, json, path, script;

  if (args.help || args.length !== 1)
    throw new RPCError('validateaddress "bitcoinaddress"');

  b58 = toString(args[0]);

  try {
    address = Address.fromBase58(b58);
  } catch (e) {
    return {
      isvalid: false
    };
  }

  path = yield wallet.getPath(address);
  script = Script.fromAddress(address);

  json = {
    isvalid: true,
    address: address.toBase58(this.network),
    scriptPubKey: script.toJSON(),
    ismine: path ? true : false,
    iswatchonly: path ? wallet.watchOnly : false,
    account: undefined,
    hdkeypath: undefined
  };

  if (!path)
    return json;

  json.account = path.name;
  json.hdkeypath = path.toPath();

  return json;
});

RPC.prototype.verifymessage = co(function* verifymessage(args) {
  var address, sig, msg, hash, key;

  if (args.help || args.length !== 3)
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

RPC.prototype.signmessagewithprivkey = co(function* signmessagewithprivkey(args) {
  var key, msg, sig;

  if (args.help || args.length !== 2)
    throw new RPCError('signmessagewithprivkey "privkey" "message"');

  key = toString(args[0]);
  msg = toString(args[1]);

  key = KeyRing.fromSecret(key);
  msg = new Buffer(RPC.magic + msg, 'utf8');
  msg = crypto.hash256(msg);

  sig = key.sign(msg);

  return sig.toString('base64');
});

RPC.prototype.estimatefee = co(function* estimatefee(args) {
  var blocks, fee;

  if (args.help || args.length !== 1)
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

RPC.prototype.estimatepriority = co(function* estimatepriority(args) {
  var blocks, pri;

  if (args.help || args.length !== 1)
    throw new RPCError('estimatepriority nblocks');

  if (!this.fees)
    throw new RPCError('Priority estimation not available.');

  blocks = toNumber(args[0], 1);

  if (blocks < 1)
    blocks = 1;

  pri = this.fees.estimatePriority(blocks, false);

  return pri;
});

RPC.prototype.estimatesmartfee = co(function* estimatesmartfee(args) {
  var blocks, fee;

  if (args.help || args.length !== 1)
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

RPC.prototype.estimatesmartpriority = co(function* estimatesmartpriority(args) {
  var blocks, pri;

  if (args.help || args.length !== 1)
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

RPC.prototype.invalidateblock = co(function* invalidateblock(args) {
  var hash;

  if (args.help || args.length !== 1)
    throw new RPCError('invalidateblock "hash"');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Block not found.');

  this.chain.setInvalid(hash);

  return null;
});

RPC.prototype.reconsiderblock = co(function* reconsiderblock(args) {
  var hash;

  if (args.help || args.length !== 1)
    throw new RPCError('reconsiderblock "hash"');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Block not found.');

  this.chain.removeInvalid(hash);

  return null;
});

RPC.prototype.setmocktime = co(function* setmocktime(args) {
  var ts, delta;

  if (args.help || args.length !== 1)
    throw new RPCError('setmocktime timestamp');

  ts = toNumber(args[0]);

  if (ts < 0)
    throw new RPCError('Invalid parameter.');

  this.network.time.offset = 0;

  delta = this.network.now() - ts;

  this.network.time.offset = -delta;

  return null;
});

/*
 * Wallet
 */

RPC.prototype.resendwallettransactions = co(function* resendwallettransactions(args) {
  var wallet = this.wallet;
  var hashes = [];
  var i, tx, txs;

  if (args.help || args.length !== 0)
    throw new RPCError('resendwallettransactions');

  txs = yield wallet.resend();

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    hashes.push(tx.txid());
  }

  return hashes;
});

RPC.prototype.addmultisigaddress = co(function* addmultisigaddress(args) {
  if (args.help || args.length < 2 || args.length > 3) {
    throw new RPCError('addmultisigaddress'
      + ' nrequired ["key",...] ( "account" )');
  }

  // Impossible to implement in bcoin (no address book).
  throw new Error('Not implemented.');
});

RPC.prototype.addwitnessaddress = co(function* addwitnessaddress(args) {
  if (args.help || args.length < 1 || args.length > 1)
    throw new RPCError('addwitnessaddress "address"');

  // Unlikely to be implemented.
  throw new Error('Not implemented.');
});

RPC.prototype.backupwallet = co(function* backupwallet(args) {
  var dest;

  if (args.help || args.length !== 1)
    throw new RPCError('backupwallet "destination"');

  dest = toString(args[0]);

  yield this.walletdb.backup(dest);

  return null;
});

RPC.prototype.dumpprivkey = co(function* dumpprivkey(args) {
  var wallet = this.wallet;
  var hash, ring;

  if (args.help || args.length !== 1)
    throw new RPCError('dumpprivkey "bitcoinaddress"');

  hash = Address.getHash(toString(args[0]), 'hex');

  if (!hash)
    throw new RPCError('Invalid address.');

  ring = yield wallet.getPrivateKey(hash);

  if (!ring)
    throw new RPCError('Key not found.');

  return ring.toSecret();
});

RPC.prototype.dumpwallet = co(function* dumpwallet(args) {
  var wallet = this.wallet;
  var i, file, time, address, fmt, str, out, hash, hashes, ring;

  if (args.help || args.length !== 1)
    throw new RPCError('dumpwallet "filename"');

  if (!args[0] || typeof args[0] !== 'string')
    throw new RPCError('Invalid parameter.');

  file = toString(args[0]);
  time = util.date();
  out = [
    util.fmt('# Wallet Dump created by BCoin %s', pkg.version),
    util.fmt('# * Created on %s', time),
    util.fmt('# * Best block at time of backup was %d (%s),',
      this.chain.height, this.chain.tip.rhash()),
    util.fmt('#   mined on %s', util.date(this.chain.tip.ts)),
    util.fmt('# * File: %s', file),
    ''
  ];

  hashes = yield wallet.getAddressHashes();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    ring = yield wallet.getPrivateKey(hash);

    if (!ring)
      continue;

    address = ring.getAddress('base58');
    fmt = '%s %s label= addr=%s';

    if (ring.branch === 1)
      fmt = '%s %s change=1 addr=%s';

    str = util.fmt(fmt, ring.toSecret(), time, address);

    out.push(str);
  }

  out.push('');
  out.push('# End of dump');
  out.push('');

  out = out.join('\n');

  if (fs.unsupported)
    return out;

  yield writeFile(file, out);

  return out;
});

RPC.prototype.encryptwallet = co(function* encryptwallet(args) {
  var wallet = this.wallet;
  var passphrase;

  if (!wallet.master.encrypted && (args.help || args.help !== 1))
    throw new RPCError('encryptwallet "passphrase"');

  if (wallet.master.encrypted)
    throw new RPCError('Already running with an encrypted wallet');

  passphrase = toString(args[0]);

  if (passphrase.length < 1)
    throw new RPCError('encryptwallet "passphrase"');

  yield wallet.setPassphrase(passphrase);

  return 'wallet encrypted; we do not need to stop!';
});

RPC.prototype.getaccountaddress = co(function* getaccountaddress(args) {
  var wallet = this.wallet;
  var account;

  if (args.help || args.length !== 1)
    throw new RPCError('getaccountaddress "account"');

  account = toString(args[0]);

  if (!account)
    account = 'default';

  account = yield wallet.getAccount(account);

  if (!account)
    return '';

  return account.receive.getAddress('base58');
});

RPC.prototype.getaccount = co(function* getaccount(args) {
  var wallet = this.wallet;
  var hash, path;

  if (args.help || args.length !== 1)
    throw new RPCError('getaccount "bitcoinaddress"');

  hash = Address.getHash(args[0], 'hex');

  if (!hash)
    throw new RPCError('Invalid address.');

  path = yield wallet.getPath(hash);

  if (!path)
    return '';

  return path.name;
});

RPC.prototype.getaddressesbyaccount = co(function* getaddressesbyaccount(args) {
  var wallet = this.wallet;
  var i, path, account, address, addrs, paths;

  if (args.help || args.length !== 1)
    throw new RPCError('getaddressesbyaccount "account"');

  account = toString(args[0]);

  if (!account)
    account = 'default';

  addrs = [];

  paths = yield wallet.getPaths(account);

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    address = path.toAddress();
    addrs.push(address.toBase58(this.network));
  }

  return addrs;
});

RPC.prototype.getbalance = co(function* getbalance(args) {
  var wallet = this.wallet;
  var minconf = 0;
  var account, value, balance;

  if (args.help || args.length > 3)
    throw new RPCError('getbalance ( "account" minconf includeWatchonly )');

  if (args.length >= 1) {
    account = toString(args[0]);

    if (!account)
      account = 'default';

    if (account === '*')
      account = null;
  }

  if (args.length >= 2)
    minconf = toNumber(args[1], 0);

  balance = yield wallet.getBalance(account);

  if (minconf)
    value = balance.confirmed;
  else
    value = balance.unconfirmed;

  return Amount.btc(value, true);
});

RPC.prototype.getnewaddress = co(function* getnewaddress(args) {
  var wallet = this.wallet;
  var account, address;

  if (args.help || args.length > 1)
    throw new RPCError('getnewaddress ( "account" )');

  if (args.length === 1)
    account = toString(args[0]);

  if (!account)
    account = 'default';

  address = yield wallet.createReceive(account);

  return address.getAddress('base58');
});

RPC.prototype.getrawchangeaddress = co(function* getrawchangeaddress(args) {
  var wallet = this.wallet;
  var address;

  if (args.help || args.length > 1)
    throw new RPCError('getrawchangeaddress');

  address = yield wallet.createChange();

  return address.getAddress('base58');
});

RPC.prototype.getreceivedbyaccount = co(function* getreceivedbyaccount(args) {
  var wallet = this.wallet;
  var minconf = 0;
  var total = 0;
  var filter = {};
  var lastConf = -1;
  var i, j, path, wtx, output, conf, hash, account, paths, txs;

  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('getreceivedbyaccount "account" ( minconf )');

  account = toString(args[0]);

  if (!account)
    account = 'default';

  if (args.length === 2)
    minconf = toNumber(args[1], 0);

  paths = yield wallet.getPaths(account);

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    filter[path.hash] = true;
  }

  txs = yield wallet.getHistory(account);

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];

    conf = wtx.getDepth(this.chain.height);

    if (conf < minconf)
      continue;

    if (lastConf === -1 || conf < lastConf)
      lastConf = conf;

    for (j = 0; j < wtx.tx.outputs.length; j++) {
      output = wtx.tx.outputs[j];
      hash = output.getHash('hex');
      if (hash && filter[hash])
        total += output.value;
    }
  }

  return Amount.btc(total, true);
});

RPC.prototype.getreceivedbyaddress = co(function* getreceivedbyaddress(args) {
  var wallet = this.wallet;
  var minconf = 0;
  var total = 0;
  var i, j, hash, wtx, output, txs;

  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('getreceivedbyaddress "bitcoinaddress" ( minconf )');

  hash = Address.getHash(toString(args[0]), 'hex');

  if (!hash)
    throw new RPCError('Invalid address');

  if (args.length === 2)
    minconf = toNumber(args[1], 0);

  txs = yield wallet.getHistory();

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];

    if (wtx.getDepth(this.chain.height) < minconf)
      continue;

    for (j = 0; j < wtx.tx.outputs.length; j++) {
      output = wtx.tx.outputs[j];
      if (output.getHash('hex') === hash)
        total += output.value;
    }
  }

  return Amount.btc(total, true);
});

RPC.prototype._toWalletTX = co(function* _toWalletTX(wtx) {
  var wallet = this.wallet;
  var details = yield wallet.toDetails(wtx);
  var det = [];
  var sent = 0;
  var received = 0;
  var receive = true;
  var i, member;

  if (!details)
    throw new RPCError('TX not found.');

  for (i = 0; i < details.inputs.length; i++) {
    member = details.inputs[i];
    if (member.path) {
      receive = false;
      break;
    }
  }

  for (i = 0; i < details.outputs.length; i++) {
    member = details.outputs[i];

    if (member.path) {
      if (member.path.branch === 1)
        continue;

      det.push({
        account: member.path.name,
        address: member.address.toBase58(this.network),
        category: 'receive',
        amount: Amount.btc(member.value, true),
        label: member.path.name,
        vout: i
      });

      received += member.value;

      continue;
    }

    if (receive)
      continue;

    det.push({
      account: '',
      address: member.address
        ? member.address.toBase58(this.network)
        : null,
      category: 'send',
      amount: -(Amount.btc(member.value, true)),
      fee: -(Amount.btc(details.fee, true)),
      vout: i
    });

    sent += member.value;
  }

  return {
    amount: Amount.btc(receive ? received : -sent, true),
    confirmations: details.confirmations,
    blockhash: details.block ? util.revHex(details.block) : null,
    blockindex: details.index,
    blocktime: details.ts,
    txid: util.revHex(details.hash),
    walletconflicts: [],
    time: details.ps,
    timereceived: details.ps,
    'bip125-replaceable': 'no',
    details: det,
    hex: details.tx.toRaw().toString('hex')
  };
});

RPC.prototype.gettransaction = co(function* gettransaction(args) {
  var wallet = this.wallet;
  var hash, wtx;

  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('gettransaction "txid" ( includeWatchonly )');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter');

  wtx = yield wallet.getTX(hash);

  if (!wtx)
    throw new RPCError('TX not found.');

  return yield this._toWalletTX(wtx);
});

RPC.prototype.abandontransaction = co(function* abandontransaction(args) {
  var wallet = this.wallet;
  var hash, result;

  if (args.help || args.length !== 1)
    throw new RPCError('abandontransaction "txid"');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter.');

  result = yield wallet.abandon(hash);

  if (!result)
    throw new RPCError('Transaction not in wallet.');

  return null;
});

RPC.prototype.getunconfirmedbalance = co(function* getunconfirmedbalance(args) {
  var wallet = this.wallet;
  var balance;

  if (args.help || args.length > 0)
    throw new RPCError('getunconfirmedbalance');

  balance = yield wallet.getBalance();

  return Amount.btc(balance.unconfirmed, true);
});

RPC.prototype.getwalletinfo = co(function* getwalletinfo(args) {
  var wallet = this.wallet;
  var balance;

  if (args.help || args.length !== 0)
    throw new RPCError('getwalletinfo');

  balance = yield wallet.getBalance();

  return {
    walletid: wallet.id,
    walletversion: 6,
    balance: Amount.btc(balance.unconfirmed, true),
    unconfirmed_balance: Amount.btc(balance.unconfirmed, true),
    txcount: wallet.txdb.state.tx,
    keypoololdest: 0,
    keypoolsize: 0,
    unlocked_until: wallet.master.until,
    paytxfee: this.feeRate != null
      ? Amount.btc(this.feeRate, true)
      : 0
  };
});

RPC.prototype.importprivkey = co(function* importprivkey(args) {
  var wallet = this.wallet;
  var secret, label, rescan, key;

  if (args.help || args.length < 1 || args.length > 3)
    throw new RPCError('importprivkey "bitcoinprivkey" ( "label" rescan )');

  secret = toString(args[0]);

  if (args.length > 1)
    label = toString(args[1]);

  if (args.length > 2)
    rescan = toBool(args[2]);

  if (rescan && this.chain.options.prune)
    throw new RPCError('Cannot rescan when pruned.');

  key = KeyRing.fromSecret(secret);

  yield wallet.importKey(0, key);

  if (rescan)
    yield this.walletdb.rescan(0);

  return null;
});

RPC.prototype.importwallet = co(function* importwallet(args) {
  var wallet = this.wallet;
  var file, keys, lines, line, parts;
  var i, secret, time, label, addr;
  var data, key, rescan;

  if (args.help || args.length !== 1)
    throw new RPCError('importwallet "filename" ( rescan )');

  if (fs.unsupported)
    throw new RPCError('FS not available.');

  file = toString(args[0]);

  if (args.length > 1)
    rescan = toBool(args[1]);

  if (rescan && this.chain.options.prune)
    throw new RPCError('Cannot rescan when pruned.');

  data = yield readFile(file, 'utf8');

  lines = data.split(/\n+/);
  keys = [];

  for (i = 0; i < lines.length; i++) {
    line = lines[i].trim();

    if (line.length === 0)
      continue;

    if (/^\s*#/.test(line))
      continue;

    parts = line.split(/\s+/);

    if (parts.length < 4)
      throw new RPCError('Malformed wallet.');

    secret = KeyRing.fromSecret(parts[0]);

    time = +parts[1];
    label = parts[2];
    addr = parts[3];

    keys.push(secret);
  }

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    yield wallet.importKey(0, key);
  }

  if (rescan)
    yield this.walletdb.rescan(0);

  return null;
});

RPC.prototype.importaddress = co(function* importaddress(args) {
  var wallet = this.wallet;
  var addr, label, rescan, p2sh;

  if (args.help || args.length < 1 || args.length > 4)
    throw new RPCError('importaddress "address" ( "label" rescan p2sh )');

  addr = toString(args[0]);

  if (args.length > 1)
    label = toString(args[1]);

  if (args.length > 2)
    rescan = toBool(args[2]);

  if (args.length > 3)
    p2sh = toBool(args[3]);

  if (rescan && this.chain.options.prune)
    throw new RPCError('Cannot rescan when pruned.');

  addr = Address.fromBase58(addr);

  yield wallet.importAddress(0, addr);

  if (rescan)
    yield this.walletdb.rescan(0);

  return null;
});

RPC.prototype.importpubkey = co(function* importpubkey(args) {
  var wallet = this.wallet;
  var pubkey, label, rescan, key;

  if (args.help || args.length < 1 || args.length > 4)
    throw new RPCError('importpubkey "pubkey" ( "label" rescan )');

  pubkey = toString(args[0]);

  if (!util.isHex(pubkey))
    throw new RPCError('Invalid parameter.');

  if (args.length > 1)
    label = toString(args[1]);

  if (args.length > 2)
    rescan = toBool(args[2]);

  if (rescan && this.chain.options.prune)
    throw new RPCError('Cannot rescan when pruned.');

  pubkey = new Buffer(pubkey, 'hex');

  key = KeyRing.fromPublic(pubkey, this.network);

  yield wallet.importKey(0, key);

  if (rescan)
    yield this.walletdb.rescan(0);

  return null;
});

RPC.prototype.keypoolrefill = co(function* keypoolrefill(args) {
  if (args.help || args.length > 1)
    throw new RPCError('keypoolrefill ( newsize )');
  return null;
});

RPC.prototype.listaccounts = co(function* listaccounts(args) {
  var wallet = this.wallet;
  var i, map, accounts, account, balance;

  if (args.help || args.length > 2)
    throw new RPCError('listaccounts ( minconf includeWatchonly)');

  map = {};
  accounts = yield wallet.getAccounts();

  for (i = 0; i < accounts.length; i++) {
    account = accounts[i];
    balance = yield wallet.getBalance(account);
    map[account] = Amount.btc(balance.unconfirmed, true);
  }

  return map;
});

RPC.prototype.listaddressgroupings = co(function* listaddressgroupings(args) {
  if (args.help)
    throw new RPCError('listaddressgroupings');
  throw new Error('Not implemented.');
});

RPC.prototype.listlockunspent = co(function* listlockunspent(args) {
  var wallet = this.wallet;
  var i, outpoints, outpoint, out;

  if (args.help || args.length > 0)
    throw new RPCError('listlockunspent');

  outpoints = wallet.getLocked();
  out = [];

  for (i = 0; i < outpoints.length; i++) {
    outpoint = outpoints[i];
    out.push({
      txid: outpoint.rhash(),
      vout: outpoint.index
    });
  }

  return out;
});

RPC.prototype.listreceivedbyaccount = co(function* listreceivedbyaccount(args) {
  var minconf = 0;
  var includeEmpty = false;

  if (args.help || args.length > 3) {
    throw new RPCError('listreceivedbyaccount'
      + ' ( minconf includeempty includeWatchonly )');
  }

  if (args.length > 0)
    minconf = toNumber(args[0], 0);

  if (args.length > 1)
    includeEmpty = toBool(args[1], false);

  return yield this._listReceived(minconf, includeEmpty, true);
});

RPC.prototype.listreceivedbyaddress = co(function* listreceivedbyaddress(args) {
  var minconf = 0;
  var includeEmpty = false;

  if (args.help || args.length > 3) {
    throw new RPCError('listreceivedbyaddress'
      + ' ( minconf includeempty includeWatchonly )');
  }

  if (args.length > 0)
    minconf = toNumber(args[0], 0);

  if (args.length > 1)
    includeEmpty = toBool(args[1], false);

  return yield this._listReceived(minconf, includeEmpty, false);
});

RPC.prototype._listReceived = co(function* _listReceived(minconf, empty, account) {
  var wallet = this.wallet;
  var out = [];
  var result = [];
  var map = {};
  var paths = yield wallet.getPaths();
  var i, j, path, wtx, output, conf, hash;
  var entry, address, keys, key, item, txs;

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    address = path.toAddress();
    map[path.hash] = {
      involvesWatchonly: wallet.watchOnly,
      address: address.toBase58(this.network),
      account: path.name,
      amount: 0,
      confirmations: -1,
      label: '',
    };
  }

  txs = yield wallet.getHistory();

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];

    conf = wtx.getDepth(this.chain.height);

    if (conf < minconf)
      continue;

    for (j = 0; j < wtx.tx.outputs.length; j++) {
      output = wtx.tx.outputs[j];
      address = output.getAddress();

      if (!address)
        continue;

      hash = address.getHash('hex');
      entry = map[hash];

      if (entry) {
        if (entry.confirmations === -1 || conf < entry.confirmations)
          entry.confirmations = conf;
        entry.address = address.toBase58(this.network);
        entry.amount += output.value;
      }
    }
  }

  keys = Object.keys(map);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    entry = map[key];
    out.push(entry);
  }

  if (account) {
    map = {};

    for (i = 0; i < out.length; i++) {
      entry = out[i];
      item = map[entry.account];
      if (!item) {
        map[entry.account] = entry;
        entry.address = undefined;
        continue;
      }
      item.amount += entry.amount;
    }

    out = [];
    keys = Object.keys(map);

    for (i = 0; i < keys.length; i++) {
      key = keys[i];
      entry = map[key];
      out.push(entry);
    }
  }

  for (i = 0; i < out.length; i++) {
    entry = out[i];

    if (!empty && entry.amount === 0)
      continue;

    if (entry.confirmations === -1)
      entry.confirmations = 0;

    entry.amount = Amount.btc(entry.amount, true);
    result.push(entry);
  }

  return result;
});

RPC.prototype.listsinceblock = co(function* listsinceblock(args) {
  var wallet = this.wallet;
  var minconf = 0;
  var out = [];
  var i, block, highest, height;
  var txs, wtx, json;

  if (args.help) {
    throw new RPCError('listsinceblock'
      + ' ( "blockhash" target-confirmations includeWatchonly)');
  }

  if (args.length > 0) {
    block = toHash(args[0]);
    if (!block)
      throw new RPCError('Invalid parameter.');
  }

  if (args.length > 1)
    minconf = toNumber(args[1], 0);

  height = yield this.chain.db.getHeight(block);

  if (height === -1)
    height = this.chain.height;

  txs = yield wallet.getHistory();

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];

    if (wtx.height < height)
      continue;

    if (wtx.getDepth(this.chain.height) < minconf)
      continue;

    if (!highest || wtx.height > highest)
      highest = wtx;

    json = yield this._toListTX(wtx);

    out.push(json);
  }

  return {
    transactions: out,
    lastblock: highest && highest.block
      ? util.revHex(highest.block)
      : encoding.NULL_HASH
  };
});

RPC.prototype._toListTX = co(function* _toListTX(wtx) {
  var wallet = this.wallet;
  var sent = 0;
  var received = 0;
  var receive = true;
  var sendMember, recMember, sendIndex, recIndex;
  var i, member, index;
  var details = yield wallet.toDetails(wtx);

  if (!details)
    throw new RPCError('TX not found.');

  for (i = 0; i < details.inputs.length; i++) {
    member = details.inputs[i];
    if (member.path) {
      receive = false;
      break;
    }
  }

  for (i = 0; i < details.outputs.length; i++) {
    member = details.outputs[i];

    if (member.path) {
      if (member.path.branch === 1)
        continue;
      received += member.value;
      recMember = member;
      recIndex = i;
      continue;
    }

    sent += member.value;
    sendMember = member;
    sendIndex = i;
  }

  if (receive) {
    member = recMember;
    index = recIndex;
  } else {
    member = sendMember;
    index = sendIndex;
  }

  // In the odd case where we send to ourselves.
  if (!member) {
    assert(!receive);
    member = recMember;
    index = recIndex;
  }

  return {
    account: member.path ? member.path.name : '',
    address: member.address
      ? member.address.toBase58(this.network)
      : null,
    category: receive ? 'receive' : 'send',
    amount: Amount.btc(receive ? received : -sent, true),
    label: member.path ? member.path.name : undefined,
    vout: index,
    confirmations: details.getDepth(),
    blockhash: details.block ? util.revHex(details.block) : null,
    blockindex: details.index,
    blocktime: details.ts,
    txid: util.revHex(details.hash),
    walletconflicts: [],
    time: details.ps,
    timereceived: details.ps,
    'bip125-replaceable': 'no'
  };
});

RPC.prototype.listtransactions = co(function* listtransactions(args) {
  var wallet = this.wallet;
  var account = null;
  var count = 10;
  var i, txs, wtx, json;

  if (args.help || args.length > 4) {
    throw new RPCError(
      'listtransactions ( "account" count from includeWatchonly)');
  }

  if (args.length > 0) {
    account = toString(args[0]);
    if (!account)
      account = 'default';
  }

  if (args.length > 1) {
    count = toNumber(args[1], 10);
    if (count < 0)
      count = 10;
  }

  txs = yield wallet.getHistory();

  sortTX(txs);

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];
    json = yield this._toListTX(wtx);
    txs[i] = json;
  }

  return txs;
});

RPC.prototype.listunspent = co(function* listunspent(args) {
  var wallet = this.wallet;
  var minDepth = 1;
  var maxDepth = 9999999;
  var out = [];
  var i, addresses, addrs, depth, address, hash, coins, coin, ring;

  if (args.help || args.length > 3) {
    throw new RPCError('listunspent'
      + ' ( minconf maxconf  ["address",...] )');
  }

  if (args.length > 0)
    minDepth = toNumber(args[0], 1);

  if (args.length > 1)
    maxDepth = toNumber(args[1], maxDepth);

  if (args.length > 2)
    addrs = toArray(args[2]);

  if (addrs) {
    addresses = {};
    for (i = 0; i < addrs.length; i++) {
      address = toString(addrs[i]);
      hash = Address.getHash(address, 'hex');

      if (!hash)
        throw new RPCError('Invalid address.');

      if (addresses[hash])
        throw new RPCError('Duplicate address.');

      addresses[hash] = true;
    }
  }

  coins = yield wallet.getCoins();

  sortCoins(coins);

  for (i = 0; i < coins.length; i++ ) {
    coin = coins[i];
    depth = coin.getDepth(this.chain.height);

    if (!(depth >= minDepth && depth <= maxDepth))
      continue;

    address = coin.getAddress();

    if (!address)
      continue;

    hash = coin.getHash('hex');

    if (addresses) {
      if (!hash || !addresses[hash])
        continue;
    }

    ring = yield wallet.getKey(hash);

    out.push({
      txid: coin.rhash(),
      vout: coin.index,
      address: address ? address.toBase58(this.network) : null,
      account: ring ? ring.name : undefined,
      redeemScript: ring && ring.script
        ? ring.script.toJSON()
        : undefined,
      scriptPubKey: coin.script.toJSON(),
      amount: Amount.btc(coin.value, true),
      confirmations: depth,
      spendable: !wallet.isLocked(coin),
      solvable: true
    });
  }

  return out;
});

RPC.prototype.lockunspent = co(function* lockunspent(args) {
  var wallet = this.wallet;
  var i, unlock, outputs, output, outpoint;

  if (args.help || args.length < 1 || args.length > 2) {
    throw new RPCError('lockunspent'
      + ' unlock ([{"txid":"txid","vout":n},...])');
  }

  unlock = toBool(args[0]);

  if (args.length === 1) {
    if (unlock)
      wallet.unlockCoins();
    return true;
  }

  outputs = toArray(args[1]);

  if (!outputs)
    throw new RPCError('Invalid parameter.');

  for (i = 0; i < outputs.length; i++) {
    output = outputs[i];

    if (!output || typeof output !== 'object')
      throw new RPCError('Invalid parameter.');

    outpoint = new Outpoint();
    outpoint.hash = toHash(output.txid);
    outpoint.index = toNumber(output.vout);

    if (!outpoint.hash)
      throw new RPCError('Invalid parameter.');

    if (outpoint.index < 0)
      throw new RPCError('Invalid parameter.');

    if (unlock) {
      wallet.unlockCoin(outpoint);
      continue;
    }

    wallet.lockCoin(outpoint);
  }

  return true;
});

RPC.prototype.move = co(function* move(args) {
  // Not implementing: stupid and deprecated.
  throw new Error('Not implemented.');
});

RPC.prototype._send = co(function* _send(account, address, amount, subtractFee) {
  var wallet = this.wallet;
  var tx, options;

  options = {
    account: account,
    subtractFee: subtractFee,
    rate: this.feeRate,
    outputs: [{
      address: address,
      value: amount
    }]
  };

  tx = yield wallet.send(options);

  return tx.txid();
});

RPC.prototype.sendfrom = co(function* sendfrom(args) {
  var account, address, amount;

  if (args.help || args.length < 3 || args.length > 6) {
    throw new RPCError('sendfrom'
      + ' "fromaccount" "tobitcoinaddress"'
      + ' amount ( minconf "comment" "comment-to" )');
  }

  account = toString(args[0]);
  address = Address.fromBase58(toString(args[1]));
  amount = toSatoshi(args[2]);

  if (!account)
    account = 'default';

  return yield this._send(account, address, amount, false);
});

RPC.prototype.sendmany = co(function* sendmany(args) {
  var wallet = this.wallet;
  var minconf = 1;
  var outputs = [];
  var uniq = {};
  var account, sendTo, comment, subtractFee;
  var i, keys, tx, key, value, address;
  var hash, output, options;

  if (args.help || args.length < 2 || args.length > 5) {
    throw new RPCError('sendmany'
      + ' "fromaccount" {"address":amount,...}'
      + ' ( minconf "comment" ["address",...] )');
  }

  account = toString(args[0]);
  sendTo = toObject(args[1]);

  if (!account)
    account = 'default';

  if (!sendTo)
    throw new RPCError('Invalid parameter.');

  if (args.length > 2)
    minconf = toNumber(args[2], 1);

  if (args.length > 3)
    comment = toString(args[3]);

  if (args.length > 4) {
    subtractFee = args[4];
    if (typeof subtractFee !== 'boolean') {
      if (!util.isNumber(subtractFee))
        throw new RPCError('Invalid parameter.');
    }
  }

  keys = Object.keys(sendTo);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    value = toSatoshi(sendTo[key]);
    address = Address.fromBase58(key);
    hash = address.getHash('hex');

    if (uniq[hash])
      throw new RPCError('Invalid parameter.');

    uniq[hash] = true;

    output = new Output();
    output.value = value;
    output.script.fromAddress(address);
    outputs.push(output);
  }

  options = {
    outputs: outputs,
    subtractFee: subtractFee,
    account: account,
    depth: minconf
  };

  tx = yield wallet.send(options);

  return tx.txid();
});

RPC.prototype.sendtoaddress = co(function* sendtoaddress(args) {
  var address, amount, subtractFee;

  if (args.help || args.length < 2 || args.length > 5) {
    throw new RPCError('sendtoaddress'
      + ' "bitcoinaddress" amount'
      + ' ( "comment" "comment-to"'
      + ' subtractfeefromamount )');
  }

  address = Address.fromBase58(toString(args[0]));
  amount = toSatoshi(args[1]);
  subtractFee = toBool(args[4]);

  return yield this._send(null, address, amount, subtractFee);
});

RPC.prototype.setaccount = co(function* setaccount(args) {
  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('setaccount "bitcoinaddress" "account"');

  // Impossible to implement in bcoin:
  throw new Error('Not implemented.');
});

RPC.prototype.settxfee = co(function* settxfee(args) {
  if (args.help || args.length < 1 || args.length > 1)
    throw new RPCError('settxfee amount');

  this.feeRate = toSatoshi(args[0]);

  return true;
});

RPC.prototype.signmessage = co(function* signmessage(args) {
  var wallet = this.wallet;
  var address, msg, sig, ring;

  if (args.help || args.length !== 2)
    throw new RPCError('signmessage "bitcoinaddress" "message"');

  address = toString(args[0]);
  msg = toString(args[1]);

  address = Address.getHash(address, 'hex');

  if (!address)
    throw new RPCError('Invalid address.');

  ring = yield wallet.getKey(address);

  if (!ring)
    throw new RPCError('Address not found.');

  if (!wallet.master.key)
    throw new RPCError('Wallet is locked.');

  msg = new Buffer(RPC.magic + msg, 'utf8');
  msg = crypto.hash256(msg);

  sig = ring.sign(msg);

  return sig.toString('base64');
});

RPC.prototype.walletlock = co(function* walletlock(args) {
  var wallet = this.wallet;

  if (args.help || (wallet.master.encrypted && args.length !== 0))
    throw new RPCError('walletlock');

  if (!wallet.master.encrypted)
    throw new RPCError('Wallet is not encrypted.');

  yield wallet.lock();

  return null;
});

RPC.prototype.walletpassphrasechange = co(function* walletpassphrasechange(args) {
  var wallet = this.wallet;
  var old, new_;

  if (args.help || (wallet.master.encrypted && args.length !== 2)) {
    throw new RPCError('walletpassphrasechange'
      + ' "oldpassphrase" "newpassphrase"');
  }

  if (!wallet.master.encrypted)
    throw new RPCError('Wallet is not encrypted.');

  old = toString(args[0]);
  new_ = toString(args[1]);

  if (old.length < 1 || new_.length < 1)
    throw new RPCError('Invalid parameter');

  yield wallet.setPassphrase(old, new_);

  return null;
});

RPC.prototype.walletpassphrase = co(function* walletpassphrase(args) {
  var wallet = this.wallet;
  var passphrase, timeout;

  if (args.help || (wallet.master.encrypted && args.length !== 2))
    throw new RPCError('walletpassphrase "passphrase" timeout');

  if (!wallet.master.encrypted)
    throw new RPCError('Wallet is not encrypted.');

  passphrase = toString(args[0]);
  timeout = toNumber(args[1]);

  if (passphrase.length < 1)
    throw new RPCError('Invalid parameter');

  if (timeout < 0)
    throw new RPCError('Invalid parameter');

  yield wallet.unlock(passphrase, timeout);

  return null;
});

RPC.prototype.importprunedfunds = co(function* importprunedfunds(args) {
  var tx, block, hash, label, height;

  if (args.help || args.length < 2 || args.length > 3) {
    throw new RPCError('importprunedfunds'
      + ' "rawtransaction" "txoutproof" ( "label" )');
  }

  tx = args[0];
  block = args[1];

  if (!util.isHex(tx) || !util.isHex(block))
    throw new RPCError('Invalid parameter.');

  tx = TX.fromRaw(tx, 'hex');
  block = MerkleBlock.fromRaw(block, 'hex');
  hash = block.hash('hex');

  if (args.length === 3)
    label = toString(args[2]);

  if (!block.verify())
    throw new RPCError('Invalid proof.');

  if (!block.hasTX(tx))
    throw new RPCError('Invalid proof.');

  height = yield this.chain.db.getHeight(hash);

  if (height === -1)
    throw new RPCError('Invalid proof.');

  block = {
    hash: hash,
    ts: block.ts,
    height: height
  };

  if (!(yield this.walletdb.addTX(tx, block)))
    throw new RPCError('No tracked address for TX.');

  return null;
});

RPC.prototype.removeprunedfunds = co(function* removeprunedfunds(args) {
  var wallet = this.wallet;
  var hash;

  if (args.help || args.length !== 1)
    throw new RPCError('removeprunedfunds "txid"');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter.');

  if (!(yield wallet.remove(hash)))
    throw new RPCError('Transaction not in wallet.');

  return null;
});

RPC.prototype.getmemory = co(function* getmemory(args) {
  var mem;

  if (args.help || args.length !== 0)
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

RPC.prototype.selectwallet = co(function* selectwallet(args) {
  var id, wallet;

  if (args.help || args.length !== 1)
    throw new RPCError('selectwallet "id"');

  id = toString(args[0]);
  wallet = yield this.walletdb.get(id);

  if (!wallet)
    throw new RPCError('Wallet not found.');

  this.wallet = wallet;

  return null;
});

RPC.prototype.setloglevel = co(function* setloglevel(args) {
  var name, level;

  if (args.help || args.length !== 1)
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

function writeFile(file, data) {
  return new Promise(function(resolve, reject) {
    fs.writeFile(file, data, co.wrap(resolve, reject));
  });
}

function readFile(file, enc) {
  return new Promise(function(resolve, reject) {
    fs.readFile(file, enc, co.wrap(resolve, reject));
  });
}

function sortTX(txs) {
  return txs.sort(function(a, b) {
    return a.ps - b.ps;
  });
}

function sortCoins(coins) {
  return coins.sort(function(a, b) {
    a = a.height === -1 ? 0x7fffffff : a.height;
    b = b.height === -1 ? 0x7fffffff : b.height;
    return a - b;
  });
}

/*
 * Expose
 */

module.exports = RPC;
