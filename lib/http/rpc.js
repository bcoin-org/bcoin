/*!
 * rpc.js - bitcoind-compatible json rpc for bcoin.
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var co = require('../utils/co');
var crypto = require('../crypto/crypto');
var assert = require('assert');
var constants = require('../protocol/constants');
var ec = require('../crypto/ec');
var Amount = require('../btc/amount');
var NetworkAddress = require('../primitives/netaddress');
var Script = require('../script/script');
var Address = require('../primitives/address');
var Block = require('../primitives/block');
var Coin = require('../primitives/coin');
var Headers = require('../primitives/headers');
var Input = require('../primitives/input');
var KeyRing = require('../primitives/keyring');
var Locker = require('../utils/locker');
var MerkleBlock = require('../primitives/merkleblock');
var MTX = require('../primitives/mtx');
var Network = require('../protocol/network');
var Outpoint = require('../primitives/outpoint');
var Output = require('../primitives/output');
var BufferReader = require('../utils/reader');
var TX = require('../primitives/tx');
var Logger = require('../node/logger');
var EventEmitter = require('events').EventEmitter;
var fs = require('fs');

function RPC(node) {
  if (!(this instanceof RPC))
    return new RPC(node);

  EventEmitter.call(this);

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

  this.locker = new Locker();

  this.feeRate = null;
  this.mining = false;
  this.proclimit = 0;

  this.attempt = null;
  this.start = 0;
  this._boundChain = false;
  this.coinbase = {};
}

util.inherits(RPC, EventEmitter);

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
      return Promise.reject(new Error('Method not found: ' + json.method + '.'));
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
    version: constants.USER_VERSION,
    protocolversion: constants.VERSION,
    walletversion: 0,
    balance: Amount.btc(balance.unconfirmed, true),
    blocks: this.chain.height,
    timeoffset: this.network.time.offset,
    connections: this.pool.peers.all.length,
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

RPC.prototype.help = function help(args) {
  var json;

  if (args.length === 0)
    return Promise.resolve('Select a command.');

  json = {
    method: args[0],
    params: []
  };

  json.params.help = true;

  return this.execute(json);
};

RPC.prototype.stop = function stop(args) {
  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('stop'));

  this.node.close();

  return Promise.resolve('Stopping.');
};

/*
 * P2P networking
 */

RPC.prototype.getnetworkinfo = function getnetworkinfo(args) {
  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('getnetworkinfo'));

  return Promise.resolve({
    version: constants.USER_VERSION,
    subversion: constants.USER_AGENT,
    protocolversion: constants.VERSION,
    localservices: this.pool.services,
    timeoffset: this.network.time.offset,
    connections: this.pool.peers.all.length,
    networks: [],
    relayfee: Amount.btc(this.network.getMinRelay(), true),
    localaddresses: [],
    warnings: ''
  });
};

RPC.prototype.addnode = function addnode(args) {
  var i, node, cmd, seed, addr, peer;

  if (args.help || args.length !== 2)
    return Promise.reject(new RPCError('addnode "node" "add|remove|onetry"'));

  node = toString(args[0]);
  cmd = toString(args[1]);
  addr = NetworkAddress.fromHostname(node, this.network);

  switch (cmd) {
    case 'add':
      this.pool.seeds.push(addr);
      break;
    case 'remove':
      for (i = 0; i < this.pool.seeds.length; i++) {
        seed = this.pool.seeds[i];
        if (seed.hostname === addr.hostname) {
          this.pool.seeds.splice(i, 1);
          break;
        }
      }
      break;
    case 'onetry':
      if (!this.pool.peers.get(addr)) {
        peer = this.pool.createPeer(addr);
        this.pool.peers.addPending(peer);
      }
      break;
  }

  return Promise.resolve();
};

RPC.prototype.disconnectnode = function disconnectnode(args) {
  var node, addr, peer;

  if (args.help || args.length !== 1)
    return Promise.reject(new RPCError('disconnectnode "node"'));

  node = toString(args[0]);
  addr = NetworkAddress.fromHostname(node, this.network);

  peer = this.pool.peers.get(addr);
  if (peer)
    peer.destroy();

  return Promise.resolve();
};

RPC.prototype.getaddednodeinfo = function getaddednodeinfo(args) {
  var out = [];
  var i, host, addr, peer, peers;

  if (args.help || args.length < 1 || args.length > 2)
    return Promise.reject(new RPCError('getaddednodeinfo dummy ( "node" )'));

  if (args.length === 2) {
    host = toString(args[1]);
    addr = NetworkAddress.fromHostname(host, this.network);
    peer = this.pool.peers.get(addr);
    if (!peer)
      return Promise.reject(new RPCError('Node has not been added.'));
    peers = [peer];
  } else {
    peers = this.pool.peers.all;
  }

  for (i = 0; i < peers.length; i++) {
    peer = peers[i];
    out.push({
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
    });
  }

  return Promise.resolve(out);
};

RPC.prototype.getconnectioncount = function getconnectioncount(args) {
  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('getconnectioncount'));

  return Promise.resolve(this.pool.peers.all.length);
};

RPC.prototype.getnettotals = function getnettotals(args) {
  var i, sent, recv, peer;

  if (args.help || args.length > 0)
    return Promise.reject(new RPCError('getnettotals'));

  sent = 0;
  recv = 0;

  for (i = 0; i < this.pool.peers.all.length; i++) {
    peer = this.pool.peers.all[i];
    sent += peer.socket.bytesWritten;
    recv += peer.socket.bytesRead;
  }

  return Promise.resolve({
    totalbytesrecv: recv,
    totalbytessent: sent,
    timemillis: util.ms()
  });
};

RPC.prototype.getpeerinfo = function getpeerinfo(args) {
  var peers = [];
  var i, peer;

  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('getpeerinfo'));

  for (i = 0; i < this.pool.peers.all.length; i++) {
    peer = this.pool.peers.all[i];
    peers.push({
      id: peer.id,
      addr: peer.hostname,
      addrlocal: peer.hostname,
      relaytxes: peer.outbound,
      lastsend: peer.lastSend / 1000 | 0,
      lastrecv: peer.lastRecv / 1000 | 0,
      bytessent: peer.socket.bytesWritten,
      bytesrecv: peer.socket.bytesRead,
      conntime: peer.ts !== 0 ? util.now() - peer.ts : 0,
      timeoffset: peer.version ? peer.version.ts - util.now() : 0,
      pingtime: peer.lastPing !== -1 ? peer.lastPing / 1000 : 0,
      minping: peer.minPing !== -1 ? peer.minPing / 1000 : 0,
      version: peer.version ? peer.version.version : 0,
      subver: peer.version ? peer.version.agent : '',
      inbound: !peer.outbound,
      startingheight: peer.version ? peer.version.height : -1,
      banscore: peer.banScore,
      inflight: [],
      whitelisted: false
    });
  }

  return Promise.resolve(peers);
};

RPC.prototype.ping = function ping(args) {
  var i;

  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('ping'));

  for (i = 0; i < this.pool.peers.all.length; i++)
    this.pool.peers.all[i].sendPing();

  return Promise.resolve();
};

RPC.prototype.setban = function setban(args) {
  var host, ip;

  if (args.help
      || args.length < 2
      || (args[1] !== 'add' && args[1] !== 'remove')) {
    return Promise.reject(new RPCError(
      'setban "ip(/netmask)" "add|remove" (bantime) (absolute)'));
  }

  host = toString(args[0]);
  ip = NetworkAddress.fromHostname(host, this.network);

  switch (args[1]) {
    case 'add':
      this.pool.ban(ip);
      break;
    case 'remove':
      this.pool.unban(ip);
      break;
  }

  return Promise.resolve();
};

RPC.prototype.listbanned = function listbanned(args) {
  var i, banned, keys, host, time;

  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('listbanned'));

  banned = [];
  keys = Object.keys(this.pool.hosts.misbehaving);

  for (i = 0; i < keys.length; i++) {
    host = keys[i];
    time = this.pool.hosts.misbehaving[host];
    banned.push({
      address: host,
      banned_until: time + constants.BAN_TIME,
      ban_created: time,
      ban_reason: ''
    });
  }

  return Promise.resolve(banned);
};

RPC.prototype.clearbanned = function clearbanned(args) {
  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('clearbanned'));

  this.pool.hosts.clear();

  return Promise.resolve();
};

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
      case constants.thresholdStates.DEFINED:
        state = 'defined';
        break;
      case constants.thresholdStates.STARTED:
        state = 'started';
        break;
      case constants.thresholdStates.LOCKED_IN:
        state = 'locked_in';
        break;
      case constants.thresholdStates.ACTIVE:
        state = 'active';
        break;
      case constants.thresholdStates.FAILED:
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
    headers: this.chain.bestHeight,
    bestblockhash: util.revHex(this.chain.tip.hash),
    difficulty: this._getDifficulty(),
    mediantime: yield this.chain.tip.getMedianTimeAsync(),
    verificationprogress: this.chain.getProgress(),
    chainwork: this.chain.tip.chainwork.toString('hex', 64),
    pruned: this.chain.db.options.prune,
    softforks: this._getSoftforks(),
    bip9_softforks: yield this._getBIP9Softforks(),
    pruneheight: this.chain.db.options.prune
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

RPC.prototype.getbestblockhash = function getbestblockhash(args) {
  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('getbestblockhash'));

  return Promise.resolve(this.chain.tip.rhash);
};

RPC.prototype.getblockcount = function getblockcount(args) {
  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('getblockcount'));

  return Promise.resolve(this.chain.tip.height);
};

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
    if (this.chain.db.options.spv)
      throw new RPCError('Block not available (spv mode)');

    if (this.chain.db.prune)
      throw new RPCError('Block not available (pruned data)');

    throw new RPCError('Can\'t read block from disk');
  }

  if (!verbose)
    return block.toRaw().toString('hex');

  return yield this._blockToJSON(entry, block, false);
});

RPC.prototype._txToJSON = function _txToJSON(tx) {
  var self = this;
  return {
    txid: tx.txid,
    hash: tx.wtxid,
    size: tx.getSize(),
    vsize: tx.getVirtualSize(),
    version: tx.version,
    locktime: tx.locktime,
    vin: tx.inputs.map(function(input) {
      var out = {};
      if (tx.isCoinbase()) {
        out.coinbase = input.script.toJSON();
      } else {
        out.txid = util.revHex(input.prevout.hash);
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
    blockhash: tx.block || null,
    confirmations: tx.getConfirmations(this.chain.height),
    time: tx.ts,
    blocktime: tx.ts
  };
};

RPC.prototype._scriptToJSON = function scriptToJSON(script, hex) {
  var out = {};
  var type, address;

  out.asm = script.toASM();

  if (hex)
    out.hex = script.toJSON();

  type = script.getType();
  out.type = Script.typesByVal[type];

  out.reqSigs = script.isMultisig() ? script.getSmall(0) : 1;

  address = script.getAddress();

  out.addresses = address ? [address.toBase58(this.network)] : [];

  return out;
};

RPC.prototype.getblockhash = co(function* getblockhash(args) {
  var height, entry;

  if (args.help || args.length !== 1)
    throw new RPCError('getblockhash index');

  height = toNumber(args[0]);

  if (height < 0 || height > this.chain.height)
    throw new RPCError('Block height out of range.');

  entry = yield this.chain.db.getEntry(height);

  if (!entry)
    throw new RPCError('Not found.');

  return entry.rhash;
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
    hash: util.revHex(entry.hash),
    confirmations: this.chain.height - entry.height + 1,
    height: entry.height,
    version: entry.version,
    merkleroot: util.revHex(entry.merkleRoot),
    time: entry.ts,
    mediantime: medianTime,
    bits: entry.bits,
    difficulty: this._getDifficulty(entry),
    chainwork: entry.chainwork.toString('hex', 64),
    previousblockhash: entry.prevBlock !== constants.NULL_HASH
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
    hash: util.revHex(entry.hash),
    confirmations: this.chain.height - entry.height + 1,
    strippedsize: block.getBaseSize(),
    size: block.getSize(),
    weight: block.getWeight(),
    height: entry.height,
    version: entry.version,
    merkleroot: util.revHex(entry.merkleRoot),
    tx: block.txs.map(function(tx) {
      if (txDetails)
        return self._txToJSON(tx);
      return tx.rhash;
    }),
    time: entry.ts,
    mediantime: medianTime,
    bits: entry.bits,
    difficulty: this._getDifficulty(entry),
    chainwork: entry.chainwork.toString('hex', 64),
    previousblockhash: entry.prevBlock !== constants.NULL_HASH
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
      hash: entry.rhash,
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

RPC.prototype.getdifficulty = function getdifficulty(args) {
  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('getdifficulty'));

  return Promise.resolve(this._getDifficulty());
};

RPC.prototype.getmempoolinfo = function getmempoolinfo(args) {
  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('getmempoolinfo'));

  if (!this.mempool)
    return Promise.reject(new RPCError('No mempool available.'));

  return Promise.resolve({
    size: this.mempool.totalTX,
    bytes: this.mempool.getSize(),
    usage: this.mempool.getSize(),
    maxmempool: constants.mempool.MAX_MEMPOOL_SIZE,
    mempoolminfee: Amount.btc(this.mempool.minRelay, true)
  });
};

RPC.prototype.getmempoolancestors = function getmempoolancestors(args) {
  var i, hash, verbose, entry, entries;

  if (args.help || args.length < 1 || args.length > 2)
    return Promise.reject(new RPCError('getmempoolancestors txid (verbose)'));

  if (!this.mempool)
    return Promise.reject(new RPCError('No mempool available.'));

  hash = toHash(args[0]);

  if (!hash)
    return Promise.reject(new RPCError('Invalid parameter.'));

  if (args.length > 1)
    verbose = toBool(args[1], false);

  entry = this.mempool.getEntry(hash);

  if (!entry)
    return Promise.reject(new RPCError('Transaction not in mempool.'));

  entries = this.mempool.getAncestors(entry.tx);

  if (verbose) {
    for (i = 0; i < entries.length; i++)
      entries[i] = this._entryToJSON(entries[i]);
  } else {
    for (i = 0; i < entries.length; i++)
      entries[i] = entries[i].tx.rhash;
  }

  return Promise.resolve(entries);
};

RPC.prototype.getmempooldescendants = function getmempooldescendants(args) {
  var i, hash, verbose, entry, entries;

  if (args.help || args.length < 1 || args.length > 2)
    return Promise.reject(new RPCError('getmempooldescendants txid (verbose)'));

  if (!this.mempool)
    return Promise.reject(new RPCError('No mempool available.'));

  hash = toHash(args[0]);

  if (!hash)
    return Promise.reject(new RPCError('Invalid parameter.'));

  if (args.length > 1)
    verbose = toBool(args[1], false);

  entry = this.mempool.getEntry(hash);

  if (!entry)
    return Promise.reject(new RPCError('Transaction not in mempool.'));

  entries = this.mempool.getDescendants(entry.tx);

  if (verbose) {
    for (i = 0; i < entries.length; i++)
      entries[i] = this._entryToJSON(entries[i]);
  } else {
    for (i = 0; i < entries.length; i++)
      entries[i] = entries[i].tx.rhash;
  }

  return Promise.resolve(entries);
};

RPC.prototype.getmempoolentry = function getmempoolentry(args) {
  var hash, entry;

  if (args.help || args.length !== 1)
    return Promise.reject(new RPCError('getmempoolentry txid'));

  if (!this.mempool)
    return Promise.reject(new RPCError('No mempool available.'));

  hash = toHash(args[0]);

  if (!hash)
    return Promise.reject(new RPCError('Invalid parameter.'));

  entry = this.mempool.getEntry(hash);

  if (!entry)
    return Promise.reject(new RPCError('Transaction not in mempool.'));

  return Promise.resolve(this._entryToJSON(entry));
};

RPC.prototype.getrawmempool = function getrawmempool(args) {
  var verbose;

  if (args.help || args.length > 1)
    return Promise.reject(new RPCError('getrawmempool ( verbose )'));

  verbose = false;

  if (args.length > 0)
    verbose = toBool(args[0], false);

  return this._mempoolToJSON(verbose);
};

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

      out[entry.tx.rhash] = this._entryToJSON(entry);
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

  if (this.chain.db.options.spv)
    throw new RPCError('Cannot get coins in SPV mode.');

  if (this.chain.db.options.prune)
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
    bestblock: this.chain.tip.rhash,
    confirmations: coin.getConfirmations(this.chain.height),
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

  if (this.chain.db.options.spv)
    throw new RPCError('Cannot get coins in SPV mode.');

  if (this.chain.db.options.prune)
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
    tx = yield this.chain.db.getTX(txid);
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
    if (!block.hasTX(txids[i]))
      throw new RPCError('Block does not contain all txids.');
  }

  block = MerkleBlock.fromHashes(block, txids);

  return block.toRaw().toString('hex');
});

RPC.prototype.verifytxoutproof = co(function* verifytxoutproof(args) {
  var now = this.network.now();
  var res = [];
  var i, block, hash, entry;

  if (args.help || args.length !== 1)
    throw new RPCError('verifytxoutproof "proof"');

  block = MerkleBlock.fromRaw(toString(args[0]), 'hex');

  if (!block.verify(now))
    return res;

  entry = yield this.chain.db.getEntry(block.hash('hex'));

  if (!entry)
    throw new RPCError('Block not found in chain.');

  for (i = 0; i < block.matches.length; i++) {
    hash = block.matches[i];
    res.push(util.revHex(hash));
  }

  return res;
});

RPC.prototype.gettxoutsetinfo = function gettxoutsetinfo(args) {
  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('gettxoutsetinfo'));

  if (this.chain.db.options.spv)
    return Promise.reject(new RPCError('Chainstate not available (SPV mode).'));

  return Promise.resolve({
    height: this.chain.height,
    bestblock: this.chain.tip.rhash,
    transactions: this.chain.db.state.tx,
    txouts: this.chain.db.state.coin,
    bytes_serialized: 0,
    hash_serialized: 0,
    total_amount: Amount.btc(this.chain.db.state.value, true)
  });
};

RPC.prototype.verifychain = function verifychain(args) {
  if (args.help || args.length > 2)
    return Promise.reject(new RPCError('verifychain ( checklevel numblocks )'));

  if (this.chain.db.options.spv)
    return Promise.reject(new RPCError('Cannot verify chain in SPV mode.'));

  if (this.chain.db.options.prune)
    return Promise.reject(new RPCError('Cannot verify chain when pruned.'));

  return null;
};

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
  var now = this.network.now();
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

  if (!header.verify(now))
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
    if (err.type === 'VerifyError')
      return false;
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
  var block;

  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('submitblock "hexdata" ( "jsonparametersobject" )');

  block = Block.fromRaw(toString(args[0]), 'hex');

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
  if (block.prevBlock !== this.chain.tip.hash)
    return 'rejected: inconclusive-not-best-prevblk';

  try {
    yield this.chain.add(block);
  } catch (err) {
    if (err.type === 'VerifyError')
      return 'rejected: ' + err.reason;
    throw err;
  }

  return null;
});

RPC.prototype.getblocktemplate = co(function* getblocktemplate(args) {
  var mode = 'template';
  var version = -1;
  var coinbase = true;
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
        }
      }

      if (!coinbasetxn)
        coinbase = false;
    }
  }

  if (!this.network.selfConnect) {
    if (this.pool.peers.all.length === 0)
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
  var txs = [];
  var txIndex = {};
  var attempt = yield this._getAttempt(false);
  var block = attempt.block;
  var i, j, tx, deps, input, dep, output, raw, rwhash;
  var keys, vbavailable, vbrules, mutable, template;
  var id, deployment, state;

  for (i = 1; i < block.txs.length; i++) {
    tx = block.txs[i];
    txIndex[tx.hash('hex')] = i;
  }

  for (i = 1; i < block.txs.length; i++) {
    tx = block.txs[i];
    deps = [];

    for (j = 0; j < tx.inputs.length; j++) {
      input = tx.inputs[j];
      dep = txIndex[input.prevout.hash];
      if (dep != null && deps.indexOf(dep) === -1) {
        assert(dep < i);
        deps.push(dep);
      }
    }

    txs.push({
      data: tx.toRaw().toString('hex'),
      txid: tx.rhash,
      hash: tx.rwhash,
      depends: deps,
      fee: tx.getFee(),
      sigops: tx.getSigops(),
      weight: tx.getWeight()
    });
  }

  keys = Object.keys(this.network.deployments);
  vbavailable = {};
  vbrules = [];
  mutable = ['time', 'transactions', 'prevblock'];

  if (version >= 2)
    mutable.push('version/force');

  for (i = 0; i < keys.length; i++) {
    id = keys[i];
    deployment = this.network.deployments[id];
    state = yield this.chain.getState(this.chain.tip, id);

    switch (state) {
      case constants.thresholdStates.DEFINED:
      case constants.thresholdStates.FAILED:
        break;
      case constants.thresholdStates.LOCKED_IN:
        block.version |= 1 << deployment.bit;
      case constants.thresholdStates.STARTED:
        vbavailable[id] = deployment.bit;
        if (rules) {
          if (rules.indexOf(id) === -1 && !deployment.force)
            block.version &= ~(1 << deployment.bit);
        }
        break;
      case constants.thresholdStates.ACTIVE:
        vbrules.push(id);
        if (rules) {
          if (rules.indexOf(id) === -1 && !deployment.force)
            throw new RPCError('Client must support ' + id + '.');
        }
        break;
    }
  }

  block.version >>>= 0;

  template = {
    capabilities: ['proposal'],
    version: block.version,
    rules: vbrules,
    vbavailable: vbavailable,
    vbrequired: 0,
    previousblockhash: util.revHex(block.prevBlock),
    transactions: txs,
    longpollid: this.chain.tip.rhash + util.pad32(this._totalTX()),
    target: util.revHex(attempt.target.toString('hex')),
    submitold: false,
    mintime: block.ts,
    maxtime: this.network.now() + 2 * 60 * 60,
    mutable: mutable,
    noncerange: '00000000ffffffff',
    sigoplimit: attempt.witness
      ? constants.block.MAX_SIGOPS_WEIGHT
      : constants.block.MAX_SIGOPS,
    sizelimit: constants.block.MAX_SIZE,
    weightlimit: constants.block.MAX_WEIGHT,
    curtime: block.ts,
    bits: util.hex32(block.bits),
    height: attempt.height
  };

  if (coinbase) {
    tx = attempt.coinbase;

    // We don't include the commitment
    // output (see bip145).
    if (attempt.witness) {
      output = tx.outputs.pop();
      assert(output.script.isCommitment());
      raw = tx.toRaw();
      rwhash = tx.rwhash;
      tx.outputs.push(output);
    } else {
      raw = tx.toRaw();
      rwhash = tx.rwhash;
    }

    template.coinbasetxn = {
      data: raw.toString('hex'),
      txid: tx.rhash,
      hash: rwhash,
      depends: [],
      fee: 0,
      sigops: tx.getSigops(),
      weight: tx.getWeight()
    };
  } else {
    template.coinbaseaux = {
      flags: attempt.coinbaseFlags.toString('hex')
    };
    template.coinbasevalue = attempt.coinbase.getOutputValue();
  }

  if (attempt.witness) {
    tx = attempt.coinbase;
    output = tx.outputs[tx.outputs.length - 1];
    assert(output.script.isCommitment());
    template.default_witness_commitment = output.script.toJSON();
  }

  return template;
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

  this.chain.on('connect', function() {
    if (!self.attempt)
      return;

    self._clearBlock();
  });

  if (!this.mempool)
    return;

  this.mempool.on('tx', function() {
    if (!self.attempt)
      return;

    if (util.now() - self.start > 10)
      self._clearBlock();
  });
};

RPC.prototype._getAttempt = co(function* _getAttempt(update) {
  var attempt = this.attempt;

  this._bindChain();

  if (attempt) {
    if (update) {
      attempt.updateNonce();
      this.coinbase[attempt.block.merkleRoot] = attempt.coinbase.clone();
    }
    return attempt;
  }

  attempt = yield this.miner.createBlock();

  this.attempt = attempt;
  this.start = util.now();
  this.coinbase[attempt.block.merkleRoot] = attempt.coinbase.clone();

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

RPC.prototype.getnetworkhashps = function getnetworkhashps(args) {
  var lookup = 120;
  var height = -1;

  if (args.help || args.length > 2)
    return Promise.reject(new RPCError('getnetworkhashps ( blocks height )'));

  if (args.length > 0)
    lookup = toNumber(args[0], 120);

  if (args.length > 1)
    height = toNumber(args[1], -1);

  return this._hashps(lookup, height);
};

RPC.prototype.prioritisetransaction = function prioritisetransaction(args) {
  var hash, pri, fee, entry;

  if (args.help || args.length !== 3) {
    return Promise.reject(new RPCError('prioritisetransaction'
      + ' <txid> <priority delta> <fee delta>'));
  }

  if (!this.mempool)
    return Promise.reject(new RPCError('No mempool available.'));

  hash = toHash(args[0]);
  pri = args[1];
  fee = args[2];

  if (!hash)
    return Promise.reject(new RPCError('Invalid parameter'));

  if (!util.isNumber(pri) || !util.isNumber(fee))
    return Promise.reject(new RPCError('Invalid parameter'));

  entry = this.mempool.getEntry(hash);

  if (!entry)
    return Promise.reject(new RPCError('Transaction not in mempool.'));

  entry.priority += pri;
  entry.fee += fee;

  if (entry.priority < 0)
    entry.priority = 0;

  if (entry.fee < 0)
    entry.fee = 0;

  return Promise.resolve(true);
};

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

RPC.prototype.getgenerate = function getgenerate(args) {
  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('getgenerate'));
  return Promise.resolve(this.mining);
};

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
    hashes.push(block.rhash);
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

RPC.prototype.createrawtransaction = function createrawtransaction(args) {
  var inputs, sendTo, tx, locktime;
  var i, input, output, hash, index, sequence;
  var keys, addrs, key, value, address, b58;

  if (args.help || args.length < 2 || args.length > 3) {
    return Promise.reject(new RPCError('createrawtransaction'
      + ' [{"txid":"id","vout":n},...]'
      + ' {"address":amount,"data":"hex",...}'
      + ' ( locktime )'));
  }

  inputs = toArray(args[0]);
  sendTo = toObject(args[1]);

  if (!inputs || !sendTo)
    return Promise.reject(new RPCError('Invalid parameter'));

  tx = new TX();

  if (args.length > 2 && args[2] != null) {
    locktime = toNumber(args[2]);
    if (locktime < 0 || locktime > 0xffffffff)
      return Promise.reject(new RPCError('Locktime out of range'));
    tx.locktime = locktime;
  }

  for (i = 0; i < inputs.length; i++) {
    input = inputs[i];

    if (!input)
      return Promise.reject(new RPCError('Invalid parameter'));

    hash = toHash(input.txid);
    index = input.vout;
    sequence = 0xffffffff;

    if (tx.locktime)
      sequence--;

    if (!hash
        || !util.isNumber(index)
        || index < 0) {
      return Promise.reject(new RPCError('Invalid parameter'));
    }

    if (util.isNumber(input.sequence)) {
      sequence = toNumber(input.sequence);
      if (input.sequence < 0 || input.sequence > 0xffffffff)
        return Promise.reject(new RPCError('Invalid parameter'));
    }

    input = new Input({
      prevout: {
        hash: util.revHex(hash),
        index: index
      },
      sequence: sequence
    });

    tx.inputs.push(input);
  }

  keys = Object.keys(sendTo);
  addrs = {};

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    value = sendTo[key];

    if (key === 'data') {
      value = new Buffer(value, 'hex');
      output = new Output({
        value: 0,
        script: Script.fromNulldata(value)
      });
      tx.outputs.push(output);
      continue;
    }

    address = Address.fromBase58(key);
    b58 = address.toBase58(this.network);

    if (addrs[b58])
      return Promise.reject(new RPCError('Duplicate address'));

    addrs[b58] = true;

    output = new Output({
      value: toSatoshi(value),
      address: address
    });

    tx.outputs.push(output);
  }

  return Promise.resolve(tx.toRaw().toString('hex'));
};

RPC.prototype.decoderawtransaction = function decoderawtransaction(args) {
  var tx;

  if (args.help || args.length !== 1)
    return Promise.reject(new RPCError('decoderawtransaction "hexstring"'));

  tx = TX.fromRaw(toString(args[0]), 'hex');

  return Promise.resolve(this._txToJSON(tx));
};

RPC.prototype.decodescript = function decodescript(args) {
  var data, script, hash, address;

  if (args.help || args.length !== 1)
    return Promise.reject(new RPCError('decodescript "hex"'));

  data = toString(args[0]);
  script = new Script();

  if (data.length > 0)
    script.fromRaw(new Buffer(data, 'hex'));

  hash = crypto.hash160(script.toRaw());
  address = Address.fromHash(hash, Script.types.SCRIPTHASH);

  script = this._scriptToJSON(script);
  script.p2sh = address.toBase58(this.network);

  return Promise.resolve(script);
};

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
    throw tx.toRaw().toString('hex');

  json = this._txToJSON(tx);
  json.hex = tx.toRaw().toString('hex');

  return json;
});

RPC.prototype.sendrawtransaction = function sendrawtransaction(args) {
  var tx;

  if (args.help || args.length < 1 || args.length > 2) {
    return Promise.reject(new RPCError('sendrawtransaction'
      + ' "hexstring" ( allowhighfees )'));
    }

  if (!util.isHex(args[0]))
    return Promise.reject(new RPCError('Invalid parameter'));

  tx = TX.fromRaw(args[0], 'hex');

  this.node.sendTX(tx);

  return tx.rhash;
};

RPC.prototype.signrawtransaction = co(function* signrawtransaction(args) {
  var raw, br, txs, merged;

  if (args.help || args.length < 1 || args.length > 4) {
    throw new RPCError('signrawtransaction'
      + ' "hexstring" ('
      + ' [{"txid":"id","vout":n,"scriptPubKey":"hex",'
      + 'redeemScript":"hex"},...] ["privatekey1",...]'
      + ' sighashtype )');
  }

  if (!util.isHex(args[0]))
    throw new RPCError('Invalid parameter');

  raw = new Buffer(args[0], 'hex');
  br = new BufferReader(raw);
  txs = [];

  while (br.left())
    txs.push(MTX.fromRaw(br));

  merged = txs[0];

  yield this._fillCoins(merged);
  yield this.wallet.fillCoins(merged);

  return yield this._signrawtransaction(merged, txs, args);
});

RPC.prototype._fillCoins = function _fillCoins(tx) {
  if (this.chain.db.options.spv)
    return Promise.resolve();

  return this.node.fillCoins(tx);
};

RPC.prototype._signrawtransaction = co(function* signrawtransaction(merged, txs, args) {
  var type = constants.hashType.ALL;
  var keys = [];
  var keyMap = {};
  var coins = [];
  var i, j, k, secret, key;
  var coin, prevout, prev;
  var hash, index, script, value;
  var redeem, op, parts, tx;

  if (args.length > 2 && Array.isArray(args[2])) {
    k = args[2];
    for (i = 0; i < k.length; i++) {
      secret = k[i];

      if (!util.isBase58(secret))
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

      if (!prev)
        throw new RPCError('Invalid parameter');

      hash = toHash(prev.txid);
      index = prev.vout;
      script = prev.scriptPubKey;
      value = toSatoshi(prev.amount);

      if (!hash
          || !util.isNumber(index)
          || index < 0
          || !util.isHex(script)) {
        throw new RPCError('Invalid parameter');
      }

      script = Script.fromRaw(script, 'hex');

      coin = new Coin();
      coin.hash = util.revHex(hash);
      coin.index = index;
      coin.script = script;
      coin.value = value;
      coin.coinbase = false;
      coin.height = -1;
      coins.push(coin);

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
            break;
          }
        }
      }
    }

    tx.fillCoins(coins);
  }

  if (args.length > 3) {
    parts = toString(args[3]).split('|');
    type = constants.hashType[parts[0]];

    if (type == null)
      throw new RPCError('Invalid parameter');

    if (parts.length > 2)
      throw new RPCError('Invalid parameter');

    if (parts.length === 2) {
      if (parts[1] !== 'ANYONECANPAY')
        throw new RPCError('Invalid parameter');
      type |= constants.hashType.ANYONECANPAY;
    }
  }

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    merged.sign(key, type);
  }

  yield this.wallet.sign(merged, { type: type });

  return {
    hex: merged.toRaw().toString('hex'),
    complete: merged.isSigned()
  };
});

RPC.prototype.fundrawtransaction = co(function* fundrawtransaction(args) {
  var tx, options, changeAddress, feeRate;

  if (args.help || args.length < 1 || args.length > 2)
      throw new RPCError('fundrawtransaction "hexstring" ( options )');

  tx = MTX.fromRaw(toString(args[0]), 'hex');

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

  yield this.wallet.fund(tx, options);

  return {
    hex: tx.toRaw().toString('hex'),
    changepos: tx.changeIndex,
    fee: Amount.btc(tx.getFee(), true)
  };
});

RPC.prototype._createRedeem = co(function* _createRedeem(args) {
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

    ring = yield this.wallet.getKey(hash);

    if (!ring)
      throw new RPCError('Invalid key.');

    keys[i] = ring.publicKey;
  }

  try {
    script = Script.fromMultisig(m, n, keys);
  } catch (e) {
    throw new RPCError('Invalid parameters.');
  }

  if (script.getSize() > constants.script.MAX_PUSH)
    throw new RPCError('Redeem script exceeds size limit.');

  return script;
});

/*
 * Utility Functions
 */

RPC.prototype.createmultisig = co(function* createmultisig(args) {
  var script;

  if (args.help || args.length < 2 || args.length > 2)
    throw new RPCError('createmultisig nrequired ["key",...]');

  script = yield this._createRedeem(args);

  return {
    address: script.getAddress().toBase58(this.network),
    redeemScript: script.toJSON()
  };
});

RPC.prototype.createwitnessaddress = function createwitnessaddress(args) {
  var raw, script, program;

  if (args.help || args.length !== 1)
    return Promise.reject(new RPCError('createwitnessaddress "script"'));

  raw = toString(args[1]);
  script = Script.fromRaw(raw, 'hex');
  program = script.forWitness();

  return Promise.resolve({
    address: program.getAddress().toBase58(this.network),
    witnessScript: program.toJSON()
  });
};

RPC.prototype.validateaddress = co(function* validateaddress(args) {
  var b58, address, json, path;

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

  path = yield this.wallet.getPath(address);

  json = {
    isvalid: true,
    address: address.toBase58(this.network),
    scriptPubKey: address.toScript().toJSON(),
    ismine: path ? true : false,
    iswatchonly: path ? this.wallet.watchOnly : false
  };

  if (!path)
    return json;

  json.account = path.name;
  json.hdkeypath = path.toPath();

  return json;
});

RPC.magic = 'Bitcoin Signed Message:\n';

RPC.prototype.verifymessage = function verifymessage(args) {
  var address, sig, msg, key;

  if (args.help || args.length !== 3) {
    return Promise.reject(new RPCError('verifymessage'
      + ' "bitcoinaddress" "signature" "message"'));
  }

  address = toString(args[0]);
  sig = toString(args[1]);
  msg = toString(args[2]);

  address = Address.getHash(address);

  if (!address)
    return Promise.reject(new RPCError('Invalid address.'));

  sig = new Buffer(sig, 'base64');
  msg = new Buffer(RPC.magic + msg, 'utf8');
  msg = crypto.hash256(msg);

  key = ec.recover(msg, sig, 0, true);

  if (!key)
    return Promise.resolve(false);

  key = crypto.hash160(key);

  return Promise.resolve(crypto.ccmp(key, address));
};

RPC.prototype.signmessagewithprivkey = function signmessagewithprivkey(args) {
  var key, msg, sig;

  if (args.help || args.length !== 2) {
    return Promise.reject(new RPCError(
      'signmessagewithprivkey "privkey" "message"'));
  }

  key = toString(args[0]);
  msg = toString(args[1]);

  key = KeyRing.fromSecret(key);
  msg = new Buffer(RPC.magic + msg, 'utf8');
  msg = crypto.hash256(msg);

  sig = key.sign(msg);

  return Promise.resolve(sig.toString('base64'));
};

RPC.prototype.estimatefee = function estimatefee(args) {
  var blocks, fee;

  if (args.help || args.length !== 1)
    return Promise.reject(new RPCError('estimatefee nblocks'));

  if (!this.fees)
    return Promise.reject(new RPCError('Fee estimation not available.'));

  blocks = toNumber(args[0], 1);

  if (blocks < 1)
    blocks = 1;

  fee = this.fees.estimateFee(blocks, false);

  if (fee === 0)
    fee = -1;
  else
    fee = Amount.btc(fee, true);

  return Promise.resolve(fee);
};

RPC.prototype.estimatepriority = function estimatepriority(args) {
  var blocks, pri;

  if (args.help || args.length !== 1)
    return Promise.reject(new RPCError('estimatepriority nblocks'));

  if (!this.fees)
    return Promise.reject(new RPCError('Priority estimation not available.'));

  blocks = toNumber(args[0], 1);

  if (blocks < 1)
    blocks = 1;

  pri = this.fees.estimatePriority(blocks, false);

  return Promise.resolve(pri);
};

RPC.prototype.estimatesmartfee = function estimatesmartfee(args) {
  var blocks, fee;

  if (args.help || args.length !== 1)
    return Promise.reject(new RPCError('estimatesmartfee nblocks'));

  if (!this.fees)
    return Promise.reject(new RPCError('Fee estimation not available.'));

  blocks = toNumber(args[0], 1);

  if (blocks < 1)
    blocks = 1;

  fee = this.fees.estimateFee(blocks, true);

  if (fee === 0)
    fee = -1;
  else
    fee = Amount.btc(fee, true);

  return Promise.resolve({
    fee: fee,
    blocks: blocks
  });
};

RPC.prototype.estimatesmartpriority = function estimatesmartpriority(args) {
  var blocks, pri;

  if (args.help || args.length !== 1)
    return Promise.reject(new RPCError('estimatesmartpriority nblocks'));

  if (!this.fees)
    return Promise.reject(new RPCError('Priority estimation not available.'));

  blocks = toNumber(args[0], 1);

  if (blocks < 1)
    blocks = 1;

  pri = this.fees.estimatePriority(blocks, true);

  return Promise.resolve({
    priority: pri,
    blocks: blocks
  });
};

RPC.prototype.invalidateblock = function invalidateblock(args) {
  var hash;

  if (args.help || args.length !== 1)
    return Promise.reject(new RPCError('invalidateblock "hash"'));

  hash = toHash(args[0]);

  if (!hash)
    return Promise.reject(new RPCError('Block not found.'));

  this.chain.invalid[hash] = true;

  return Promise.resolve();
};

RPC.prototype.reconsiderblock = function reconsiderblock(args) {
  var hash;

  if (args.help || args.length !== 1)
    return Promise.reject(new RPCError('reconsiderblock "hash"'));

  hash = toHash(args[0]);

  if (!hash)
    return Promise.reject(new RPCError('Block not found.'));

  delete this.chain.invalid[hash];

  return Promise.resolve();
};

RPC.prototype.setmocktime = function setmocktime(args) {
  var ts, delta;

  if (args.help || args.length !== 1)
    return Promise.reject(new RPCError('setmocktime timestamp'));

  ts = toNumber(args[0]);

  if (ts < 0)
    return Promise.reject(new RPCError('Invalid parameter.'));

  delta = this.network.now() - ts;

  this.network.time.offset = -delta;

  return Promise.resolve();
};

/*
 * Wallet
 */

RPC.prototype.resendwallettransactions = co(function* resendwallettransactions(args) {
  var hashes = [];
  var i, tx, txs;

  if (args.help || args.length !== 0)
    throw new RPCError('resendwallettransactions');

  txs = yield this.wallet.resend();

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    hashes.push(tx.rhash);
  }

  return hashes;
});

RPC.prototype.addmultisigaddress = function addmultisigaddress(args) {
  if (args.help || args.length < 2 || args.length > 3) {
    return Promise.reject(new RPCError('addmultisigaddress'
      + ' nrequired ["key",...] ( "account" )'));
  }
  // Impossible to implement in bcoin (no address book).
  Promise.reject(new Error('Not implemented.'));
};

RPC.prototype.addwitnessaddress = function addwitnessaddress(args) {
  if (args.help || args.length < 1 || args.length > 1)
    return Promise.reject(new RPCError('addwitnessaddress "address"'));
  // Unlikely to be implemented.
  Promise.reject(new Error('Not implemented.'));
};

RPC.prototype.backupwallet = co(function* backupwallet(args) {
  var dest;

  if (args.help || args.length !== 1)
    throw new RPCError('backupwallet "destination"');

  dest = toString(args[0]);

  yield this.walletdb.backup(dest);

  return null;
});

RPC.prototype.dumpprivkey = co(function* dumpprivkey(args) {
  var hash, ring;

  if (args.help || args.length !== 1)
    throw new RPCError('dumpprivkey "bitcoinaddress"');

  hash = Address.getHash(toString(args[0]), 'hex');

  if (!hash)
    throw new RPCError('Invalid address.');

  ring = yield this.wallet.getKey(hash);

  if (!ring)
    throw new RPCError('Key not found.');

  if (!this.wallet.master.key)
    throw new RPCError('Wallet is locked.');

  return ring.toSecret();
});

RPC.prototype.dumpwallet = co(function* dumpwallet(args) {
  var i, file, time, address, fmt, str, out, hash, hashes, ring;

  if (args.help || args.length !== 1)
    throw new RPCError('dumpwallet "filename"');

  if (!args[0] || typeof args[0] !== 'string')
    throw new RPCError('Invalid parameter.');

  file = toString(args[0]);
  time = util.date();
  out = [
    util.fmt('# Wallet Dump created by BCoin %s', constants.USER_VERSION),
    util.fmt('# * Created on %s', time),
    util.fmt('# * Best block at time of backup was %d (%s),',
      this.chain.height, this.chain.tip.rhash),
    util.fmt('#   mined on %s', util.date(this.chain.tip.ts)),
    util.fmt('# * File: %s', file),
    ''
  ];

  hashes = yield this.wallet.getAddressHashes();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    ring = yield this.wallet.getKey(hash);

    if (!ring)
      continue;

    if (!this.wallet.master.key)
      throw new RPCError('Wallet is locked.');

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
  var passphrase;

  if (!this.wallet.master.encrypted && (args.help || args.help !== 1))
    throw new RPCError('encryptwallet "passphrase"');

  if (this.wallet.master.encrypted)
    throw new RPCError('Already running with an encrypted wallet');

  passphrase = toString(args[0]);

  if (passphrase.length < 1)
    throw new RPCError('encryptwallet "passphrase"');

  yield this.wallet.setPassphrase(passphrase);

  return 'wallet encrypted; we do not need to stop!';
});

RPC.prototype.getaccountaddress = co(function* getaccountaddress(args) {
  var account;

  if (args.help || args.length !== 1)
    throw new RPCError('getaccountaddress "account"');

  account = toString(args[0]);

  if (!account)
    account = 'default';

  account = yield this.wallet.getAccount(account);

  if (!account)
    return '';

  return account.receive.getAddress('base58');
});

RPC.prototype.getaccount = co(function* getaccount(args) {
  var hash, path;

  if (args.help || args.length !== 1)
    throw new RPCError('getaccount "bitcoinaddress"');

  hash = Address.getHash(args[0], 'hex');

  if (!hash)
    throw new RPCError('Invalid address.');

  path = yield this.wallet.getPath(hash);

  if (!path)
    return '';

  return path.name;
});

RPC.prototype.getaddressesbyaccount = co(function* getaddressesbyaccount(args) {
  var i, path, account, addrs, paths;

  if (args.help || args.length !== 1)
    throw new RPCError('getaddressesbyaccount "account"');

  account = toString(args[0]);

  if (!account)
    account = 'default';

  addrs = [];

  paths = yield this.wallet.getPaths(account);

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    addrs.push(path.toAddress().toBase58(this.network));
  }

  return addrs;
});

RPC.prototype.getbalance = co(function* getbalance(args) {
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

  balance = yield this.wallet.getBalance(account);

  if (minconf)
    value = balance.confirmed;
  else
    value = balance.unconfirmed;

  return Amount.btc(value, true);
});

RPC.prototype.getnewaddress = co(function* getnewaddress(args) {
  var account, address;

  if (args.help || args.length > 1)
    throw new RPCError('getnewaddress ( "account" )');

  if (args.length === 1)
    account = toString(args[0]);

  if (!account)
    account = 'default';

  address = yield this.wallet.createReceive(account);

  return address.getAddress('base58');
});

RPC.prototype.getrawchangeaddress = co(function* getrawchangeaddress(args) {
  var address;

  if (args.help || args.length > 1)
    throw new RPCError('getrawchangeaddress');

  address = yield this.wallet.createChange();

  return address.getAddress('base58');
});

RPC.prototype.getreceivedbyaccount = co(function* getreceivedbyaccount(args) {
  var minconf = 0;
  var total = 0;
  var filter = {};
  var lastConf = -1;
  var i, j, path, tx, output, conf, hash, account, paths, txs;

  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('getreceivedbyaccount "account" ( minconf )');

  account = toString(args[0]);

  if (!account)
    account = 'default';

  if (args.length === 2)
    minconf = toNumber(args[1], 0);

  paths = yield this.wallet.getPaths(account);

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    filter[path.hash] = true;
  }

  txs = yield this.wallet.getHistory(account);

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];

    if (minconf) {
      if (tx.height === -1)
        continue;
      if (!(this.chain.height - tx.height + 1 >= minconf))
        continue;
    }

    conf = tx.getConfirmations(this.chain.height);

    if (lastConf === -1 || conf < lastConf)
      lastConf = conf;

    for (j = 0; j < tx.outputs.length; j++) {
      output = tx.outputs[j];
      hash = output.getHash('hex');
      if (hash && filter[hash])
        total += output.value;
    }
  }

  return Amount.btc(total, true);
});

RPC.prototype.getreceivedbyaddress = co(function* getreceivedbyaddress(args) {
  var minconf = 0;
  var total = 0;
  var i, j, hash, tx, output, txs;

  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('getreceivedbyaddress "bitcoinaddress" ( minconf )');

  hash = Address.getHash(toString(args[0]), 'hex');

  if (!hash)
    throw new RPCError('Invalid address');

  if (args.length === 2)
    minconf = toNumber(args[1], 0);

  txs = yield this.wallet.getHistory();

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    if (minconf) {
      if (tx.height === -1)
        continue;
      if (!(this.chain.height - tx.height + 1 >= minconf))
        continue;
    }
    for (j = 0; j < tx.outputs.length; j++) {
      output = tx.outputs[j];
      if (output.getHash('hex') === hash)
        total += output.value;
    }
  }

  return Amount.btc(total, true);
});

RPC.prototype._toWalletTX = co(function* _toWalletTX(tx) {
  var i, det, receive, member, sent, received, json, details;

  details = yield this.wallet.toDetails(tx);

  if (!details)
    throw new RPCError('TX not found.');

  det = [];
  sent = 0;
  received = 0;
  receive = true;

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

  json = {
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

  return json;
});

RPC.prototype.gettransaction = co(function* gettransaction(args) {
  var hash, tx;

  if (args.help || args.length < 1 || args.length > 2)
    throw new RPCError('gettransaction "txid" ( includeWatchonly )');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter');

  tx = yield this.wallet.getTX(hash);

  if (!tx)
    throw new RPCError('TX not found.');

  return yield this._toWalletTX(tx);
});

RPC.prototype.abandontransaction = co(function* abandontransaction(args) {
  var hash, result;

  if (args.help || args.length !== 1)
    throw new RPCError('abandontransaction "txid"');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter.');

  result = yield this.wallet.abandon(hash);

  if (!result)
    throw new RPCError('Transaction not in wallet.');

  return null;
});

RPC.prototype.getunconfirmedbalance = co(function* getunconfirmedbalance(args) {
  var balance;

  if (args.help || args.length > 0)
    throw new RPCError('getunconfirmedbalance');

  balance = yield this.wallet.getBalance();

  return Amount.btc(balance.unconfirmed, true);
});

RPC.prototype.getwalletinfo = co(function* getwalletinfo(args) {
  var balance;

  if (args.help || args.length !== 0)
    throw new RPCError('getwalletinfo');

  balance = yield this.wallet.getBalance();

  return {
    walletid: this.wallet.id,
    walletversion: 6,
    balance: Amount.btc(balance.unconfirmed, true),
    unconfirmed_balance: Amount.btc(balance.unconfirmed, true),
    txcount: this.wallet.state.tx,
    keypoololdest: 0,
    keypoolsize: 0,
    unlocked_until: this.wallet.master.until,
    paytxfee: this.feeRate != null
      ? Amount.btc(this.feeRate, true)
      : 0
  };
});

RPC.prototype.importprivkey = co(function* importprivkey(args) {
  var secret, label, rescan, key;

  if (args.help || args.length < 1 || args.length > 3)
    throw new RPCError('importprivkey "bitcoinprivkey" ( "label" rescan )');

  secret = toString(args[0]);

  if (args.length > 1)
    label = toString(args[1]);

  if (args.length > 2)
    rescan = toBool(args[2]);

  if (rescan && this.chain.db.options.prune)
    throw new RPCError('Cannot rescan when pruned.');

  key = KeyRing.fromSecret(secret);

  yield this.wallet.importKey(0, key);

  if (rescan)
    yield this.walletdb.rescan(0);

  return null;
});

RPC.prototype.importwallet = co(function* importwallet(args) {
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

  if (rescan && this.chain.db.options.prune)
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
    yield this.wallet.importKey(0, key);
  }

  if (rescan)
    yield this.walletdb.rescan(0);

  return null;
});

RPC.prototype.importaddress = co(function* importaddress(args) {
  var addr, label, rescan, p2sh;

  if (args.help || args.length < 1 || args.length > 4) {
    return Promise.reject(new RPCError(
      'importaddress "address" ( "label" rescan p2sh )'));
  }

  addr = toString(args[0]);

  if (args.length > 1)
    label = toString(args[1]);

  if (args.length > 2)
    rescan = toBool(args[2]);

  if (args.length > 3)
    p2sh = toBool(args[3]);

  if (rescan && this.chain.db.options.prune)
    throw new RPCError('Cannot rescan when pruned.');

  addr = Address.fromBase58(addr);

  yield this.wallet.importAddress(0, addr);

  if (rescan)
    yield this.walletdb.rescan(0);

  return null;
});

RPC.prototype.importpubkey = co(function* importpubkey(args) {
  var pubkey, label, rescan, key;

  if (args.help || args.length < 1 || args.length > 4)
    throw new RPCError('importpubkey "pubkey" ( "label" rescan )');

  pubkey = toString(args[0]);

  if (!util.isHex(pubkey))
    throw new RPCError('Invalid paremeter.');

  if (args.length > 1)
    label = toString(args[1]);

  if (args.length > 2)
    rescan = toBool(args[2]);

  if (rescan && this.chain.db.options.prune)
    throw new RPCError('Cannot rescan when pruned.');

  pubkey = new Buffer(pubkey, 'hex');

  key = KeyRing.fromPublic(pubkey, this.network);

  yield this.wallet.importKey(0, key);

  if (rescan)
    yield this.walletdb.rescan(0);

  return null;
});

RPC.prototype.keypoolrefill = function keypoolrefill(args) {
  if (args.help || args.length > 1)
    return Promise.reject(new RPCError('keypoolrefill ( newsize )'));
  return Promise.resolve();
};

RPC.prototype.listaccounts = co(function* listaccounts(args) {
  var i, map, accounts, account, balance;

  if (args.help || args.length > 2)
    throw new RPCError('listaccounts ( minconf includeWatchonly)');

  map = {};
  accounts = yield this.wallet.getAccounts();

  for (i = 0; i < accounts.length; i++) {
    account = accounts[i];
    balance = yield this.wallet.getBalance(account);
    map[account] = Amount.btc(balance.unconfirmed, true);
  }

  return map;
});

RPC.prototype.listaddressgroupings = function listaddressgroupings(args) {
  if (args.help)
    return Promise.reject(new RPCError('listaddressgroupings'));
  return Promise.resolve(new Error('Not implemented.'));
};

RPC.prototype.listlockunspent = function listlockunspent(args) {
  var i, outpoints, outpoint, out;

  if (args.help || args.length > 0)
    return Promise.reject(new RPCError('listlockunspent'));

  outpoints = this.wallet.getLocked();
  out = [];

  for (i = 0; i < outpoints.length; i++) {
    outpoint = outpoints[i];
    out.push({
      txid: util.revHex(outpoint.hash),
      vout: outpoint.index
    });
  }

  return Promise.resolve(out);
};

RPC.prototype.listreceivedbyaccount = function listreceivedbyaccount(args) {
  var minconf = 0;
  var includeEmpty = false;

  if (args.help || args.length > 3) {
    return Promise.reject(new RPCError(
      'listreceivedbyaccount ( minconf includeempty includeWatchonly )'));
  }

  if (args.length > 0)
    minconf = toNumber(args[0], 0);

  if (args.length > 1)
    includeEmpty = toBool(args[1], false);

  return this._listReceived(minconf, includeEmpty, true);
};

RPC.prototype.listreceivedbyaddress = function listreceivedbyaddress(args) {
  var minconf = 0;
  var includeEmpty = false;

  if (args.help || args.length > 3) {
    return Promise.reject(new RPCError(
      'listreceivedbyaddress ( minconf includeempty includeWatchonly )'));
  }

  if (args.length > 0)
    minconf = toNumber(args[0], 0);

  if (args.length > 1)
    includeEmpty = toBool(args[1], false);

  return this._listReceived(minconf, includeEmpty, false);
};

RPC.prototype._listReceived = co(function* _listReceived(minconf, empty, account) {
  var out = [];
  var result = [];
  var map = {};
  var i, j, path, tx, output, conf, hash;
  var entry, address, keys, key, item, paths, txs;

  paths = yield this.wallet.getPaths();

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    map[path.hash] = {
      involvesWatchonly: this.wallet.watchOnly,
      address: path.toAddress().toBase58(this.network),
      account: path.name,
      amount: 0,
      confirmations: -1,
      label: '',
    };
  }

  txs = yield this.wallet.getHistory();

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];

    if (minconf) {
      if (tx.height === -1)
        continue;
      if (!(this.chain.height - tx.height + 1 >= minconf))
        continue;
    }

    conf = tx.getConfirmations(this.chain.height);

    for (j = 0; j < tx.outputs.length; j++) {
      output = tx.outputs[j];
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
  var block, conf, out, highest;
  var i, height, txs, tx, json;

  if (args.help) {
    throw new RPCError('listsinceblock'
      + ' ( "blockhash" target-confirmations includeWatchonly)');
  }

  if (args.length > 0) {
    block = toHash(args[0]);
    if (!block)
      throw new RPCError('Invalid parameter.');
  }

  conf = 0;

  if (args.length > 1)
    conf = toNumber(args[1], 0);

  out = [];

  height = yield this.chain.db.getHeight(block);

  if (height === -1)
    height = this.chain.height;

  txs = yield this.wallet.getHistory();

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];

    if (tx.height < height)
      continue;

    if (tx.getConfirmations(this.chain.height) < conf)
      continue;

    if (!highest || tx.height > highest)
      highest = tx;

    json = yield this._toListTX(tx);

    out.push(json);
  }

  return {
    transactions: out,
    lastblock: highest && highest.block
      ? util.revHex(highest.block)
      : constants.NULL_HASH
  };
});

RPC.prototype._toListTX = co(function* _toListTX(tx) {
  var i, receive, member, det, sent, received, index;
  var sendMember, recMember, sendIndex, recIndex, json;
  var details;

  details = yield this.wallet.toDetails(tx);

  if (!details)
    throw new RPCError('TX not found.');

  det = [];
  sent = 0;
  received = 0;
  receive = true;

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

  json = {
    account: member.path ? member.path.name : '',
    address: member.address
      ? member.address.toBase58(this.network)
      : null,
    category: receive ? 'receive' : 'send',
    amount: Amount.btc(receive ? received : -sent, true),
    label: member.path ? member.path.name : undefined,
    vout: index,
    confirmations: details.confirmations,
    blockhash: details.block ? util.revHex(details.block) : null,
    blockindex: details.index,
    blocktime: details.ts,
    txid: util.revHex(details.hash),
    walletconflicts: [],
    time: details.ps,
    timereceived: details.ps,
    'bip125-replaceable': 'no'
  };

  return json;
});

RPC.prototype.listtransactions = co(function* listtransactions(args) {
  var i, account, count, txs, tx, json;

  if (args.help || args.length > 4) {
    throw new RPCError(
      'listtransactions ( "account" count from includeWatchonly)');
  }

  account = null;

  if (args.length > 0) {
    account = toString(args[0]);
    if (!account)
      account = 'default';
  }

  count = 10;

  if (args.length > 1)
    count = toNumber(args[1], 10);

  if (count < 0)
    count = 10;

  txs = yield this.wallet.getHistory();

  sortTX(txs);

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    json = yield this._toListTX(tx);
    txs[i] = json;
  }

  return txs;
});

RPC.prototype.listunspent = co(function* listunspent(args) {
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

  coins = yield this.wallet.getCoins();

  sortCoins(coins);

  for (i = 0; i < coins.length; i++ ) {
    coin = coins[i];

    depth = coin.height !== -1
      ? this.chain.height - coin.height + 1
      : 0;

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

    ring = yield this.wallet.getKey(hash);

    out.push({
      txid: util.revHex(coin.hash),
      vout: coin.index,
      address: address ? address.toBase58(this.network) : null,
      account: ring ? ring.name : undefined,
      redeemScript: ring && ring.script
        ? ring.script.toJSON()
        : undefined,
      scriptPubKey: coin.script.toJSON(),
      amount: Amount.btc(coin.value, true),
      confirmations: depth,
      spendable: !this.wallet.isLocked(coin),
      solvable: true
    });
  }

  return out;
});

RPC.prototype.lockunspent = function lockunspent(args) {
  var i, unlock, outputs, output, outpoint;

  if (args.help || args.length < 1 || args.length > 2) {
    return Promise.reject(new RPCError('lockunspent'
      + ' unlock ([{"txid":"txid","vout":n},...])'));
  }

  unlock = toBool(args[0]);

  if (args.length === 1) {
    if (unlock)
      this.wallet.unlockCoins();
    return Promise.resolve(true);
  }

  outputs = toArray(args[1]);

  if (!outputs)
    return Promise.reject(new RPCError('Invalid paremeter.'));

  for (i = 0; i < outputs.length; i++) {
    output = outputs[i];

    if (!output || typeof output !== 'object')
      return Promise.reject(new RPCError('Invalid paremeter.'));

    outpoint = new Outpoint();
    outpoint.hash = toHash(output.txid);
    outpoint.index = toNumber(output.vout);

    if (!outpoint.txid)
      return Promise.reject(new RPCError('Invalid paremeter.'));

    if (outpoint.index < 0)
      return Promise.reject(new RPCError('Invalid paremeter.'));

    if (unlock)
      this.wallet.unlockCoin(outpoint);
    else
      this.wallet.lockCoin(outpoint);
  }

  return Promise.resolve(true);
};

RPC.prototype.move = function move(args) {
  // Not implementing: stupid and deprecated.
  return Promise.reject(new Error('Not implemented.'));
};

RPC.prototype._send = co(function* _send(account, address, amount, subtractFee) {
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

  tx = yield this.wallet.send(options);

  return tx.rhash;
});

RPC.prototype.sendfrom = function sendfrom(args) {
  var account, address, amount;

  if (args.help || args.length < 3 || args.length > 6) {
    return Promise.reject(new RPCError('sendfrom'
      + ' "fromaccount" "tobitcoinaddress"'
      + ' amount ( minconf "comment" "comment-to" )'));
  }

  account = toString(args[0]);
  address = Address.fromBase58(toString(args[1]));
  amount = toSatoshi(args[2]);

  if (!account)
    account = 'default';

  return this._send(account, address, amount, false);
};

RPC.prototype.sendmany = co(function* sendmany(args) {
  var account, sendTo, minDepth, comment, subtractFee;
  var i, outputs, keys, uniq, tx;
  var key, value, address, hash, output, options;

  if (args.help || args.length < 2 || args.length > 5) {
    return Promise.reject(new RPCError('sendmany'
      + ' "fromaccount" {"address":amount,...}'
      + ' ( minconf "comment" ["address",...] )'));
  }

  account = toString(args[0]);
  sendTo = toObject(args[1]);
  minDepth = 1;

  if (!account)
    account = 'default';

  if (!sendTo)
    throw new RPCError('Invalid parameter.');

  if (args.length > 2)
    minDepth = toNumber(args[2], 1);

  if (args.length > 3)
    comment = toString(args[3]);

  if (args.length > 4)
    subtractFee = toArray(args[4]);

  outputs = [];
  keys = Object.keys(sendTo);
  uniq = {};

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
    confirmations: minDepth
  };

  tx = yield this.wallet.send(options);

  return tx.rhash;
});

RPC.prototype.sendtoaddress = function sendtoaddress(args) {
  var address, amount, subtractFee;

  if (args.help || args.length < 2 || args.length > 5) {
    return Promise.reject(new RPCError('sendtoaddress'
      + ' "bitcoinaddress" amount'
      + ' ( "comment" "comment-to"'
      + ' subtractfeefromamount )'));
  }

  address = Address.fromBase58(toString(args[0]));
  amount = toSatoshi(args[1]);
  subtractFee = toBool(args[4]);

  return this._send(null, address, amount, subtractFee);
};

RPC.prototype.setaccount = function setaccount(args) {
  if (args.help || args.length < 1 || args.length > 2) {
    return Promise.reject(new RPCError(
      'setaccount "bitcoinaddress" "account"'));
  }
  // Impossible to implement in bcoin:
  return Promise.reject(new Error('Not implemented.'));
};

RPC.prototype.settxfee = function settxfee(args) {
  if (args.help || args.length < 1 || args.length > 1)
    return Promise.reject(new RPCError('settxfee amount'));

  this.feeRate = toSatoshi(args[0]);

  return Promise.resolve(true);
};

RPC.prototype.signmessage = co(function* signmessage(args) {
  var address, msg, sig, ring;

  if (args.help || args.length !== 2)
    throw new RPCError('signmessage "bitcoinaddress" "message"');

  address = toString(args[0]);
  msg = toString(args[1]);

  address = Address.getHash(address, 'hex');

  if (!address)
    throw new RPCError('Invalid address.');

  ring = yield this.wallet.getKey(address);

  if (!ring)
    throw new RPCError('Address not found.');

  if (!this.wallet.master.key)
    throw new RPCError('Wallet is locked.');

  msg = new Buffer(RPC.magic + msg, 'utf8');
  msg = crypto.hash256(msg);

  sig = ring.sign(msg);

  return sig.toString('base64');
});

RPC.prototype.walletlock = co(function* walletlock(args) {
  if (args.help || (this.wallet.master.encrypted && args.length !== 0))
    throw new RPCError('walletlock');

  if (!this.wallet.master.encrypted)
    throw new RPCError('Wallet is not encrypted.');

  yield this.wallet.lock();

  return null;
});

RPC.prototype.walletpassphrasechange = co(function* walletpassphrasechange(args) {
  var old, new_;

  if (args.help || (this.wallet.master.encrypted && args.length !== 2)) {
    throw new RPCError('walletpassphrasechange'
      + ' "oldpassphrase" "newpassphrase"');
  }

  if (!this.wallet.master.encrypted)
    throw new RPCError('Wallet is not encrypted.');

  old = toString(args[0]);
  new_ = toString(args[1]);

  if (old.length < 1 || new_.length < 1)
    throw new RPCError('Invalid parameter');

  yield this.wallet.setPassphrase(old, new_);

  return null;
});

RPC.prototype.walletpassphrase = co(function* walletpassphrase(args) {
  var passphrase, timeout;

  if (args.help || (this.wallet.master.encrypted && args.length !== 2))
    throw new RPCError('walletpassphrase "passphrase" timeout');

  if (!this.wallet.master.encrypted)
    throw new RPCError('Wallet is not encrypted.');

  passphrase = toString(args[0]);
  timeout = toNumber(args[1]);

  if (passphrase.length < 1)
    throw new RPCError('Invalid parameter');

  if (timeout < 0)
    throw new RPCError('Invalid parameter');

  yield this.wallet.unlock(passphrase, timeout);

  return null;
});

RPC.prototype.importprunedfunds = co(function* importprunedfunds(args) {
  var now = this.network.now();
  var tx, block, label, height;

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

  if (args.length === 3)
    label = toString(args[2]);

  if (!block.verify(now))
    throw new RPCError('Invalid proof.');

  if (!block.hasTX(tx))
    throw new RPCError('Invalid proof.');

  height = yield this.chain.db.getHeight(block.hash('hex'));

  if (height === -1)
    throw new RPCError('Invalid proof.');

  tx.index = block.indexOf(tx);
  tx.block = block.hash('hex');
  tx.ts = block.ts;
  tx.height = height;

  if (!(yield this.walletdb.addTX(tx)))
    throw new RPCError('No tracked address for TX.');

  return null;
});

RPC.prototype.removeprunedfunds = co(function* removeprunedfunds(args) {
  var hash;

  if (args.help || args.length !== 1)
    throw new RPCError('removeprunedfunds "txid"');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter.');

  if (!(yield this.wallet.remove(hash)))
    throw new RPCError('Transaction not in wallet.');

  return null;
});

RPC.prototype.getmemory = function getmemory(args) {
  var mem;

  if (args.help || args.length !== 0)
    return Promise.reject(new RPCError('getmemory'));

  if (!process.memoryUsage)
    return Promise.resolve({});

  mem = process.memoryUsage();

  return Promise.resolve({
    rss: util.mb(mem.rss),
    jsheap: util.mb(mem.heapUsed),
    jsheaptotal: util.mb(mem.heapTotal),
    nativeheap: util.mb(mem.rss - mem.heapTotal)
  });
};

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

RPC.prototype.setloglevel = function setloglevel(args) {
  var name, level;

  if (args.help || args.length !== 1)
    return Promise.reject(new RPCError('setloglevel "level"'));

  name = toString(args[0]);
  level = Logger.levels[name];

  if (level == null)
    return Promise.reject(new RPCError('Bad log level.'));

  this.logger.level = level;

  return Promise.resolve(null);
};

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
