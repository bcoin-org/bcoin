/*!
 * rpc.js - bitcoind-compatible json rpc for bcoin.
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var utils = require('../utils');
var IP = require('../ip');
var constants = bcoin.protocol.constants;

function RPC(node) {
  if (!(this instanceof RPC))
    return new RPC(node);

  this.node = node;
  this.network = node.network;
  this.chain = node.chain;
  this.mempool = node.mempool;
  this.pool = node.pool;
  this.fees = node.fees;
  this.miner = node.miner;
  this.wallet = node.wallet;
  this.walletdb = node.walletdb;

  this.feeRate = null;
  this.mining = false;
  this.proclimit = 0;
}

RPC.prototype.execute = function execute(json, callback) {
  switch (json.method) {
    case 'stop':
      return this.stop(json.params, callback);
    case 'help':
      return this.help(json.params, callback);

    case 'getblockchaininfo':
      return this.getblockchaininfo(json.params, callback);
    case 'getbestblockhash':
      return this.getbestblockhash(json.params, callback);
    case 'getblockcount':
      return this.getblockcount(json.params, callback);
    case 'getblock':
      return this.getblock(json.params, callback);
    case 'getblockhash':
      return this.getblockhash(json.params, callback);
    case 'getblockheader':
      return this.getblockheader(json.params, callback);
    case 'getchaintips':
      return this.getchaintips(json.params, callback);
    case 'getdifficulty':
      return this.getdifficulty(json.params, callback);
    case 'getmempoolancestors':
      return this.getmempoolancestors(json.params, callback);
    case 'getmempooldescendants':
      return this.getmempooldescendants(json.params, callback);
    case 'getmempoolentry':
      return this.getmempoolentry(json.params, callback);
    case 'getmempoolinfo':
      return this.getmempoolinfo(json.params, callback);
    case 'getrawmempool':
      return this.getrawmempool(json.params, callback);
    case 'gettxout':
      return this.gettxout(json.params, callback);
    case 'gettxoutsetinfo':
      return this.gettxoutsetinfo(json.params, callback);
    case 'verifychain':
      return this.verifychain(json.params, callback);

    case 'invalidateblock':
      return this.invalidateblock(json.params, callback);
    case 'reconsiderblock':
      return this.reconsiderblock(json.params, callback);

    case 'getnetworkhashps':
      return this.getnetworkhashps(json.params, callback);
    case 'getmininginfo':
      return this.getmininginfo(json.params, callback);
    case 'prioritisetransaction':
      return this.prioritisetransaction(json.params, callback);
    case 'getblocktemplate':
      return this.getblocktemplate(json.params, callback);
    case 'submitblock':
      return this.submitblock(json.params, callback);

    case 'setgenerate':
      return this.setgenerate(json.params, callback);
    case 'getgenerate':
      return this.getgenerate(json.params, callback);
    case 'generate':
      return this.generate(json.params, callback);
    case 'generatetoaddress':
      return this.generatetoaddress(json.params, callback);

    case 'estimatefee':
      return this.estimatefee(json.params, callback);
    case 'estimatepriority':
      return this.estimatepriority(json.params, callback);
    case 'estimatesmartfee':
      return this.estimatesmartfee(json.params, callback);
    case 'estimatesmartpriority':
      return this.estimatesmartpriority(json.params, callback);

    case 'getinfo':
      return this.getinfo(json.params, callback);
    case 'validateaddress':
      return this.validateaddress(json.params, callback);
    case 'createmultisig':
      return this.createmultisig(json.params, callback);
    case 'createwitnessaddress':
      return this.createwitnessaddress(json.params, callback);
    case 'verifymessage':
      return this.verifymessage(json.params, callback);
    case 'signmessagewithprivkey':
      return this.signmessagewithprivkey(json.params, callback);

    case 'setmocktime':
      return this.setmocktime(json.params, callback);

    case 'getconnectioncount':
      return this.getconnectioncount(json.params, callback);
    case 'ping':
      return this.ping(json.params, callback);
    case 'getpeerinfo':
      return this.getpeerinfo(json.params, callback);
    case 'addnode':
      return this.addnode(json.params, callback);
    case 'disconnectnode':
      return this.disconnectnode(json.params, callback);
    case 'getaddednodeinfo':
      return this.getaddednodeinfo(json.params, callback);
    case 'getnettotals':
      return this.getnettotals(json.params, callback);
    case 'getnetworkinfo':
      return this.getnetworkinfo(json.params, callback);
    case 'setban':
      return this.setban(json.params, callback);
    case 'listbanned':
      return this.listbanned(json.params, callback);
    case 'clearbanned':
      return this.clearbanned(json.params, callback);

    case 'getrawtransaction':
      return this.getrawtransaction(json.params, callback);
    case 'createrawtransaction':
      return this.createrawtransaction(json.params, callback);
    case 'decoderawtransaction':
      return this.decoderawtransaction(json.params, callback);
    case 'decodescript':
      return this.decodescript(json.params, callback);
    case 'sendrawtransaction':
      return this.sendrawtransaction(json.params, callback);
    case 'signrawtransaction':
      return this.signrawtransaction(json.params, callback);

    case 'gettxoutproof':
      return this.gettxoutproof(json.params, callback);
    case 'verifytxoutproof':
      return this.verifytxoutproof(json.params, callback);

    case 'fundrawtransaction':
      return this.fundrawtransaction(json.params, callback);
    case 'resendwallettransactions':
      return this.resendwallettransactions(json.params, callback);
    case 'abandontransaction':
      return this.abandontransaction(json.params, callback);
    case 'addmultisigaddress':
      return this.addmultisigaddress(json.params, callback);
    case 'addwitnessaddress':
      return this.addwitnessaddress(json.params, callback);
    case 'backupwallet':
      return this.backupwallet(json.params, callback);
    case 'dumpprivkey':
      return this.dumpprivkey(json.params, callback);
    case 'dumpwallet':
      return this.dumpwallet(json.params, callback);
    case 'encryptwallet':
      return this.encryptwallet(json.params, callback);
    case 'getaccountaddress':
      return this.getaccountaddress(json.params, callback);
    case 'getaccount':
      return this.getaccount(json.params, callback);
    case 'getaddressesbyaccount':
      return this.getaddressesbyaccount(json.params, callback);
    case 'getbalance':
      return this.getbalance(json.params, callback);
    case 'getnewaddress':
      return this.getnewaddress(json.params, callback);
    case 'getrawchangeaddress':
      return this.getrawchangeaddress(json.params, callback);
    case 'getreceivedbyaccount':
      return this.getreceivedbyaccount(json.params, callback);
    case 'getreceivedbyaddress':
      return this.getreceivedbyaddress(json.params, callback);
    case 'gettransaction':
      return this.gettransaction(json.params, callback);
    case 'getunconfirmedbalance':
      return this.getunconfirmedbalance(json.params, callback);
    case 'getwalletinfo':
      return this.getwalletinfo(json.params, callback);
    case 'importprivkey':
      return this.importprivkey(json.params, callback);
    case 'importwallet':
      return this.importwallet(json.params, callback);
    case 'importaddress':
      return this.importaddress(json.params, callback);
    case 'importprunedfunds':
      return this.importprunedfunds(json.params, callback);
    case 'importpubkey':
      return this.importpubkey(json.params, callback);
    case 'keypoolrefill':
      return this.keypoolrefill(json.params, callback);
    case 'listaccounts':
      return this.listaccounts(json.params, callback);
    case 'listaddressgroupings':
      return this.listaddressgroupings(json.params, callback);
    case 'listlockunspent':
      return this.listlockunspent(json.params, callback);
    case 'listreceivedbyaccount':
      return this.listreceivedbyaccount(json.params, callback);
    case 'listreceivedbyaddress':
      return this.listreceivedbyaddress(json.params, callback);
    case 'listsinceblock':
      return this.listsinceblock(json.params, callback);
    case 'listtransactions':
      return this.listtransactions(json.params, callback);
    case 'listunspent':
      return this.listunspent(json.params, callback);
    case 'lockunspent':
      return this.lockunspent(json.params, callback);
    case 'move':
      return this.move(json.params, callback);
    case 'sendfrom':
      return this.sendfrom(json.params, callback);
    case 'sendmany':
      return this.sendmany(json.params, callback);
    case 'sendtoaddress':
      return this.sendtoaddress(json.params, callback);
    case 'setaccount':
      return this.setaccount(json.params, callback);
    case 'settxfee':
      return this.settxfee(json.params, callback);
    case 'signmessage':
      return this.signmessage(json.params, callback);
    case 'walletlock':
      return this.walletlock(json.params, callback);
    case 'walletpassphrasechange':
      return this.walletpassphrasechange(json.params, callback);
    case 'walletpassphrase':
      return this.walletpassphrase(json.params, callback);
    case 'removeprunedfunds':
      return this.removeprunedfunds(json.params, callback);

    default:
      return callback(new Error('Method not found.'));
  }
};

/*
 * Overall control/query calls
 */

RPC.prototype.getinfo = function getinfo(args, callback) {
  var self = this;

  if (args.help || args.length !== 0)
    return callback(new Error('getinfo'));

  this.wallet.getBalance(function(err, balance) {
    if (err)
      return callback(err);

    callback(null, {
      version: constants.USER_VERSION,
      protocolversion: constants.VERSION,
      walletversion: 0,
      balance: +utils.btc(balance.total),
      blocks: self.chain.height,
      timeoffset: bcoin.time.offset,
      connections: self.pool.peers.all.length,
      proxy: '',
      difficulty: self._getDifficulty(),
      testnet: self.network.type !== 'main',
      keypoololdest: 0,
      keypoolsize: 0,
      unlocked_until: self.wallet.master.until,
      paytxfee: +utils.btc(self.network.getRate()),
      relayfee: +utils.btc(self.network.getMinRelay()),
      errors: ''
    });
  });
};

RPC.prototype.help = function help(args, callback) {
  if (args.length === 0)
    return callback(null, 'Select a command.');

  args = args.slice(1);
  args.help = true;

  this.execute(args, callback);
};

RPC.prototype.stop = function stop(args, callback) {
  if (args.help || args.length !== 0)
    return callback(new Error('stop'));

  callback(null, 'Stopping.');
  this.node.close();
};

/*
 * P2P networking
 */

RPC.prototype.getnetworkinfo = function getnetworkinfo(args, callback) {
  callback(null, {
    version: constants.USER_VERSION,
    subversion: constants.USER_AGENT,
    protocolversion: constants.VERSION,
    localservices: this.pool.services,
    timeoffset: bcoin.time.offset,
    connections: this.pool.peers.all.length,
    networks: [
      {
        name: 'ipv4',
        limited: false,
        reachable: false,
        proxy: '',
        proxy_randomize_credentials: false
      },
      {
        name: 'ipv6',
        limited: false,
        reachable: false,
        proxy: '',
        proxy_randomize_credentials: false
      },
      {
        name: 'onion',
        limited: false,
        reachable: false,
        proxy: '',
        proxy_randomize_credentials: false
      }
    ],
    relayfee: this.network.getMinRelay() / 100000000,
    localaddresses: [],
    warnings: ''
  });
};

RPC.prototype.addnode = function addnode(args, callback) {
  var i, node, cmd, host, seed;

  if (args.help || args.length !== 2)
    return callback(new Error('addnode "node" "add|remove|onetry"'));

  node = String(args[0]);
  cmd = String(args[1]);
  host = bcoin.packets.NetworkAddress.fromHostname(node, this.network);

  switch (cmd) {
    case 'add':
      this.pool.seeds.push(host);
      break;
    case 'remove':
      for (i = 0; i < this.pool.seeds.length; i++) {
        seed = this.pool.seeds[i];
        if (seed.host === host.host) {
          this.pool.seeds.splice(i, 1);
          break;
        }
      }
      break;
    case 'onetry':
      break;
  }

  callback(null, null);
};

RPC.prototype.disconnectnode = function disconnectnode(args, callback) {
  var node, peer;

  if (args.help || args.length !== 1)
    return callback(new Error('disconnectnode "node"'));

  node = String(args[0]);
  node = IP.normalize(node);

  peer = this.pool.getPeer(node);
  if (peer)
    peer.destroy();

  callback(null, null);
};

RPC.prototype.getaddednodeinfo = function getaddednodeinfo(args, callback) {
  if (args.help || args.length < 1 || args.length > 2)
    return callback(new Error('getaddednodeinfo dummy ( "node" )'));
  callback(new Error('Not implemented.'));
};

RPC.prototype.getconnectioncount = function getconnectioncount(args, callback) {
  if (args.help || args.length !== 0)
    return callback(new Error('getconnectioncount'));
  callback(null, this.pool.peers.all.length);
};

RPC.prototype.getnettotals = function getnettotals(args, callback) {
  if (args.help || args.length < 1 || args.length > 2)
    return callback(new Error('getnettotals'));

  callback(null, {
    totalbytesrecv: 0,
    totalbytessent: 0,
    timemillis: utils.ms(),
    uploadtarget: {
      timeframe: 86400,
      target: 0,
      target_reached: false,
      serve_historical_blocks: !this.pool.options.selfish
        && !this.pool.options.spv
        && !this.chain.db.options.prune,
      bytes_left_in_cycle: 0,
      time_left_in_cycle: 0
    }
  });
};

RPC.prototype.getpeerinfo = function getpeerinfo(args, callback) {
  var peers = [];
  var i, peer;

  if (args.help || args.length !== 0)
    return callback(new Error('getpeerinfo'));

  for (i = 0; i < this.pool.peers.all.length; i++) {
    peer = this.pool.peers.all[i];
    peers.push({
      id: peer.id,
      addr: peer.hostname,
      addrlocal: peer.hostname,
      relaytxes: peer.type !== bcoin.peer.types.LEECH,
      lastsend: 0,
      lastrecv: 0,
      bytessent: 0,
      bytesrecv: 0,
      conntime: utils.now() - peer.ts,
      timeoffset: bcoin.time.known[peer.host] || 0,
      pingtime: peer.lastPing,
      minping: peer.minPing,
      version: peer.version ? peer.version.version : 0,
      subver: peer.version ? peer.version.agent : '',
      inbound: peer.type === bcoin.peer.types.LEECH,
      startingheight: peer.version ? peer.version.height : -1,
      banscore: peer.banScore,
      synced_headers: 0,
      synced_blocks: 0,
      inflight: [],
      whitelisted: false
    });
  }

  callback(null, peers);
};

RPC.prototype.ping = function ping(args, callback) {
  var i;

  if (args.help || args.length !== 0)
    return callback(new Error('ping'));

  for (i = 0; i < this.pool.peers.all.length; i++)
    this.pool.peers.all[i].sendPing();

  callback(null, null);
};

RPC.prototype.setban = function setban(args, callback) {
  var peer, ip;

  if (args.help
      || args.length < 2
      || (args[1] !== 'add' && args[1] !== 'remove')) {
    return callback(new Error(
      'setban "ip(/netmask)" "add|remove" (bantime) (absolute)'));
  }

  ip = IP.normalize(args[0]);

  switch (args[1]) {
    case 'add':
      peer = this.pool.getPeer(ip);
      if (peer)
        peer.setMisbehavior(100);
      else
        this.pool.peers.misbehaving[ip] = utils.now();
      break;
    case 'remove':
      delete this.pool.peers.misbehaving[ip];
      break;
  }

  callback(null, null);
};

RPC.prototype.listbanned = function listbanned(args, callback) {
  var i, banned, keys, host, time;

  if (args.help || args.length !== 0)
    return callback(new Error('listbanned'));

  banned = [];
  keys = Object.keys(this.pool.peers.misbehaving);

  for (i = 0; i < keys.length; i++) {
    host = keys[i];
    time = this.pool.peers.misbehaving[host];
    banned.push({
      address: host,
      banned_until: time + constants.BAN_TIME,
      ban_created: time,
      ban_reason: ''
    });
  }

  callback(null, banned);
};

RPC.prototype.clearbanned = function clearbanned(args, callback) {
  if (args.help || args.length !== 0)
    return callback(new Error('clearbanned'));

  this.pool.peers.ignored = {};
  this.pool.peers.misbehaving = {};

  callback(null, null);
};

RPC.prototype._deployment = function _deployment(id, version, status) {
  return {
    id: id,
    version: version,
    enforce: {
      status: status,
      found: status ? this.network.block.majorityWindow : 0,
      required: this.network.block.majorityEnforceUpgrade,
      window: this.network.block.majorityWindow
    },
    reject: {
      status: status,
      found: status ? this.network.block.majorityWindow : 0,
      required: this.network.block.majorityRejectOutdated,
      window: this.network.block.majorityWindow
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

RPC.prototype._getBIP9Softforks = function _getBIP9Softforks(callback) {
  var self = this;
  var forks = [];
  var keys = Object.keys(this.network.deployments);

  utils.forEachSerial(keys, function(id, next) {
    self.chain.getState(self.chain.tip, id, function(err, state) {
      if (err)
        return next(err);

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

      forks.push({
        id: id,
        state: state
      });

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, forks);
  });
};

/* Block chain and UTXO */
RPC.prototype.getblockchaininfo = function getblockchaininfo(args, callback) {
  var self = this;

  if (args.help || args.length !== 0)
    return callback(new Error('getblockchaininfo'));

  this.chain.tip.getMedianTimeAsync(function(err, medianTime) {
    if (err)
      return callback(err);

    self._getBIP9Softforks(function(err, forks) {
      if (err)
        return callback(err);

      callback(null, {
        chain: self.network.type,
        blocks: self.chain.height,
        headers: self.chain.bestHeight,
        bestblockhash: utils.revHex(self.chain.tip.hash),
        difficulty: self._getDifficulty(),
        mediantime: medianTime,
        verificationprogress: self.chain.getProgress(),
        chainwork: self.chain.tip.chainwork.toString('hex', 64),
        pruned: self.chain.db.options.prune,
        softforks: self._getSoftforks(),
        bip9_softforks: forks,
        pruneheight: self.chain.db.prune
          ? Math.max(0, self.chain.height - self.chain.db.keepBlocks)
          : null
      });
    });
  });
};

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

RPC.prototype.getbestblockhash = function getbestblockhash(args, callback) {
  if (args.help || args.length !== 0)
    return callback(new Error('getbestblockhash'));

  callback(null, this.chain.tip.rhash);
};

RPC.prototype.getblockcount = function getblockcount(args, callback) {
  if (args.help || args.length !== 0)
    return callback(new Error('getblockcount'));

  callback(null, this.chain.tip.height);
};

RPC.prototype.getblock = function getblock(args, callback) {
  var self = this;
  var hash, verbose;

  if (args.help || args.length < 1 || args.length > 2)
    return callback(new Error('getblock "hash" ( verbose )'));

  hash = utils.revHex(String(args[0]));

  verbose = true;

  if (args.length > 1)
    verbose = Boolean(args[1]);

  this.chain.db.get(hash, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback(new Error('Block not found'));

    self.chain.db.getBlock(entry.hash, function(err, block) {
      if (err)
        return callback(err);

      if (!block) {
        if (self.chain.db.prune)
          return callback(new Error('Block not available (pruned data)'));
        return callback(new Error('Can\'t read block from disk'));
      }

      if (!verbose)
        return callback(null, block.toRaw().toString('hex'));

      return self.blockToJSON(entry, block, false, callback);
    });
  });
};

RPC.prototype.txToJSON = function txToJSON(tx) {
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
        out.txid = utils.revHex(input.prevout.hash);
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
        value: +utils.btc(output.value),
        n: i,
        scriptPubKey: scriptToJSON(output.script, true)
      };
    }),
    blockhash: tx.block || null,
    confirmations: tx.getConfirmations(),
    time: tx.ts,
    blocktime: tx.ts
  };
};

function scriptToJSON(script, hex) {
  var out = {};
  var type, address;

  out.asm = script.toASM();

  if (hex)
    out.hex = script.toJSON();

  type = script.getType();
  out.type = bcoin.script.typesByVal[type];

  out.reqSigs = script.isMultisig() ? script.getSmall(0) : 1;

  address = script.getAddress();

  out.addresses = address ? [address.toBase58()] : [];

  return out;
}

RPC.prototype.getblockhash = function getblockhash(args, callback) {
  var height;

  if (args.help || args.length !== 1)
    return callback(new Error('getblockhash index'));

  height = args[0];

  if (height < 0 || height > this.chain.height)
    return callback(new Error('Block height out of range.'));

  this.chain.db.get(height, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback(new Error('Not found.'));

    return callback(null, entry.rhash);
  });
};

RPC.prototype.getblockheader = function getblockheader(args, callback) {
  var self = this;
  var hash, verbose;

  if (args.help || args.length < 1 || args.length > 2)
    return callback(new Error('getblockheader "hash" ( verbose )'));

  hash = utils.revHex(String(args[0]));

  verbose = true;

  if (args.length > 1)
    verbose = Boolean(args[1]);

  this.chain.db.get(hash, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback(new Error('Block not found'));

    if (!verbose)
      return callback(null, entry.toRaw().toString('hex', 0, 80));

    return self.blockheaderToJSON(entry, callback);
  });
};

RPC.prototype.blockheaderToJSON = function blockheaderToJSON(entry, callback) {
  var self = this;
  entry.getMedianTimeAsync(function(err, medianTime) {
    if (err)
      return callback(err);

    self.chain.db.getNextHash(entry.hash, function(err, nextHash) {
      if (err)
        return callback(err);

      return callback(null, {
        hash: utils.revHex(entry.hash),
        confirmations: self.chain.height - entry.height + 1,
        height: entry.height,
        version: entry.version,
        merkleroot: utils.revHex(entry.merkleRoot),
        time: entry.ts,
        mediantime: medianTime,
        bits: entry.bits,
        difficulty: self._getDifficulty(entry),
        chainwork: entry.chainwork.toString('hex', 64),
        previousblockhash: entry.prevBlock !== constants.NULL_HASH
          ? utils.revHex(entry.prevBlock)
          : null,
        nextblockhash: nextHash ? utils.revHex(nextHash) : null
      });
    });
  });
};

RPC.prototype.blockToJSON = function blockToJSON(entry, block, txDetails, callback) {
  var self = this;
  entry.getMedianTimeAsync(function(err, medianTime) {
    if (err)
      return callback(err);

    self.chain.db.getNextHash(entry.hash, function(err, nextHash) {
      if (err)
        return callback(err);

      return callback(null, {
        hash: utils.revHex(entry.hash),
        confirmations: self.chain.height - entry.height + 1,
        strippedsize: block.getBaseSize(),
        size: block.getSize(),
        cost: block.getCost(),
        height: entry.height,
        version: entry.version,
        merkleroot: utils.revHex(entry.merkleRoot),
        tx: block.txs.map(function(tx) {
          if (txDetails)
            return self.txToJSON(tx);
          return tx.rhash;
        }),
        time: entry.ts,
        mediantime: medianTime,
        bits: entry.bits,
        difficulty: self._getDifficulty(entry),
        chainwork: entry.chainwork.toString('hex', 64),
        previousblockhash: entry.prevBlock !== constants.NULL_HASH
          ? utils.revHex(entry.prevBlock)
          : null,
        nextblockhash: nextHash ? utils.revHex(nextHash) : null
      });
    });
  });
};

RPC.prototype.getchaintips = function getchaintips(args, callback) {
  if (args.help || args.length !== 0)
    return callback(new Error('getchaintips'));

  callback(null, [{
    height: this.chain.height,
    hash: this.chain.tip.rhash,
    branchlen: 0,
    status: 'active'
  }]);
};

RPC.prototype.getdifficulty = function getdifficulty(args, callback) {
  if (args.help || args.length !== 0)
    return callback(new Error('getdifficulty'));

  callback(null, this._getDifficulty());
};

RPC.prototype.getmempoolinfo = function getmempoolinfo(args, callback) {
  callback(null, {
    size: this.mempool.total,
    bytes: this.mempool.size,
    usage: this.mempool.size,
    maxmempool: constants.mempool.MAX_MEMPOOL_SIZE,
    mempoolminfee: this.mempool.minFeeRate / constants.COIN
  });
};

RPC.prototype.getrawmempool = function getrawmempool(args, callback) {
  var verbose;

  if (args.help || args.length > 1)
    return callback(new Error('getrawmempool ( verbose )'));

  verbose = false;

  if (args.length > 0)
    verbose = Boolean(args[0]);

  return this.mempoolToJSON(verbose, callback);
};

RPC.prototype.mempoolToJSON = function mempoolToJSON(verbose, callback) {
  var self = this;
  var out = {};
  var tx;

  if (verbose) {
    return this.mempool.getSnapshot(function(err, hashes) {
      if (err)
        return callback(err);

      utils.forEachSerial(hashes, function(hash, next) {
        self.mempool.getEntry(hash, function(err, entry) {
          if (err)
            return callback(err);

          tx = entry;

          out[tx.rhash] = {
            size: entry.size,
            fee: entry.fee,
            modifiedfee: entry.fees,
            time: entry.ts,
            height: entry.height,
            startingpriority: entry.priority,
            currentpriority: entry.getPriority(self.chain.height),
            descendantcount: -1,
            descendantsize: -1,
            descendantfees: -1,
            depends: tx.getPrevout()
          };

          next();
        });
      }, function(err) {
        if (err)
          return callback(err);
        return callback(null, out);
      });
    });
  }

  this.mempool.getSnapshot(function(err, hashes) {
    if (err)
      return callback(err);

    return callback(null, hashes.map(utils.revHex));
  });
};

RPC.prototype.gettxout = function gettxout(args, callback) {
  var self = this;
  var hash, index, mempool;

  if (args.help || args.length < 2 || args.length > 3)
    return callback(new Error('gettxout "txid" n ( includemempool )'));

  hash = utils.revHex(String(args[0]));
  index = Number(args[1]);
  mempool = true;

  if (args.length > 2)
    mempool = Boolean(args[2]);

  function getCoin(callback) {
    if (mempool)
      return self.node.getCoin(hash, index, callback);
    self.chain.db.getCoin(hash, index, callback);
  }

  getCoin(function(err, coin) {
    if (err)
      return callback(err);

    if (!coin)
      return callback(null, null);

    callback(null, {
      bestblock: utils.revHex(self.chain.tip.hash),
      confirmations: coin.getConfirmations(),
      value: +utils.btc(coin.value),
      scriptPubKey: scriptToJSON(coin.script, true),
      version: coin.version,
      coinbase: coin.coinbase
    });
  });
};

RPC.prototype.gettxoutproof = function gettxoutproof(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.verifytxoutproof = function verifytxoutproof(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.gettxoutsetinfo = function gettxoutsetinfo(args, callback) {
  if (args.help || args.length !== 0)
    return callback(new Error('gettxoutsetinfo'));

  callback(null, {
    height: this.chain.height,
    bestblock: this.chain.tip.rhash,
    transactions: 0,
    txouts: 0,
    bytes_serialized: 0,
    hash_serialized: 0,
    total_amount: 0
  });
};

RPC.prototype.verifychain = function verifychain(args, callback) {
  if (args.help || args.length > 2)
    return callback(new Error('verifychain ( checklevel numblocks )'));

  callback();
};

/*
 * Mining
 */

RPC.prototype.getblocktemplate = function getblocktemplate(args, callback) {
  var self = this;
  var txs = [];
  var txIndex = {};
  var i, j, tx, deps, input, dep, block;

  if (args.help || args.length > 1)
    return callback(new Error('getblocktemplate ( "jsonrequestobject" )'));

  this.miner.createBlock(function(err, attempt) {
    if (err)
      return callback(err);

    block = attempt.block;

    for (i = 1; i < block.txs.length; i++) {
      tx = block.txs[i];
      txIndex[tx.hash('hex')] = i;
      deps = [];

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];
        dep = txIndex[input.prevout.hash];
        if (dep != null)
          deps.push(dep);
      }

      txs.push({
        data: tx.toRaw().toString('hex'),
        txid: tx.rhash,
        hash: tx.rwhash,
        depends: deps,
        fee: tx.getFee(),
        sigops: tx.getSigops(),
        cost: tx.getCost()
      });
    }

    callback(null, {
      capabilities: ['proposal'],
      previousblockhash: utils.revHex(block.prevBlock),
      transactions: txs,
      coinbaseaux: attempt.coinbaseFlags.toString('hex'),
      coinbasevalue: attempt.coinbase.outputs[0].value,
      longpollid: self.chain.tip.rhash + self.mempool.total,
      target: attempt.target.toString('hex'),
      mintime: attempt.ts,
      mutable: ['time', 'transactions', 'prevblock', 'version/force'],
      noncerange: '00000000ffffffff',
      sigoplimit: constants.block.MAX_SIGOPS_COST,
      sizelimit: constants.block.MAX_SIZE,
      costlimit: constants.block.MAX_COST,
      curtime: block.ts,
      bits: block.bits,
      height: attempt.height,
      default_witness_commitment: attempt.witness
        ? attempt.coinbase.outputs[1].script.toJSON()
        : undefined
    });
  });
};

RPC.prototype.getmininginfo = function getmininginfo(args, callback) {
  if (args.help || args.length !== 0)
    return callback(new Error('getmininginfo'));
  callback(new Error('Not implemented.'));
};

RPC.prototype.getnetworkhashps = function getnetworkhashps(args, callback) {
  var lookup, height;

  if (args.help || args.length > 2)
    return callback(new Error('getnetworkhashps ( blocks height )'));

  lookup = args.length > 0 ? Number(args[0]) : 120;
  height = args.length > 1 ? Number(args[1]) : -1;

  return this._hashps(lookup, height, callback);
};

RPC.prototype.prioritisetransaction = function prioritisetransaction(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.submitblock = function submitblock(args, callback) {
  var block;

  if (args.help || args.length < 1 || args.length > 2)
    return callback(new Error('submitblock "hexdata" ( "jsonparametersobject" )'));

  block = bcoin.block.fromRaw(args[0], 'hex');

  this.chain.add(block, function(err, total) {
    if (err)
      return callback(null, 'rejected');
    return callback(null, 'valid');
  });
};

RPC.prototype._hashps = function _hashps(lookup, height, callback) {
  var self = this;
  var minTime, maxTime, pb0, time, workDiff, timeDiff, ps;

  function getPB(callback) {
    if (height >= 0 && height < self.chain.tip.height)
      return self.chain.db.get(height, callback);
    return callback(null, self.chain.tip);
  }

  getPB(function(err, pb) {
    if (err)
      return callback(err);

    if (!pb)
      return callback(null, 0);

    if (lookup <= 0)
      lookup = pb.height % self.network.pow.retargetInterval + 1;

    if (lookup > pb.height)
      lookup = pb.height;

    minTime = pb.ts;
    maxTime = minTime;
    pb0 = pb;

    utils.forRangeSerial(0, lookup, function(i, next) {
      pb0.getPrevious(function(err, entry) {
        if (err)
          return callback(err);

        if (!entry)
          return callback(new Error('Not found.'));

        pb0 = entry;
        time = pb0.ts;
        minTime = Math.min(time, minTime);
        maxTime = Math.max(time, maxTime);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      if (minTime === maxTime)
        return callback(null, 0);

      workDiff = pb.chainwork.sub(pb0.chainwork);
      timeDiff = maxTime - minTime;
      ps = +workDiff.toString(10) / timeDiff;

      return callback(null, ps);
    });
  });
};

/*
 * Coin generation
 */

RPC.prototype.getgenerate = function getgenerate(args, callback) {
  callback(null, this.mining);
};

RPC.prototype.setgenerate = function setgenerate(args, callback) {
  this.mining = Boolean(args[0]);
  this.proclimit = Number(args[1]);

  if (this.mining)
    this.miner.start();
  else
    this.miner.stop();

  callback(null, this.mining);
};

RPC.prototype.generate = function generate(args, callback) {
  var self = this;
  var numblocks, hashes;

  if (args.help || args.length < 1 || args.length > 2)
    return callback(new Error('generate numblocks ( maxtries )'));

  numblocks = Number(args[0]);
  hashes = [];

  utils.forRangeSerial(0, numblocks, function(i, next) {
    self.miner.mineBlock(function(err, block) {
      if (err)
        return next(err);
      hashes.push(block.rhash);
      self.chain.add(block, next);
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, hashes);
  });
};

RPC.prototype.generatetoaddress = function generatetoaddress(args, callback) {
  var self = this;
  var address;

  if (args.help || args.length < 2 || args.length > 3)
    return callback(new Error('generatetoaddress numblocks address (maxtries)'));

  address = this.miner.address;
  this.miner.address = bcoin.address.fromBase58(args[1]);

  this.generate(args, function(err, hashes) {
    if (err)
      return callback(err);
    self.miner.address = address;
    return callback(null, hashes);
  });
};

/*
 * Raw transactions
 */

RPC.prototype.createrawtransaction = function createrawtransaction(args, callback) {
  var inputs, sendTo, tx, locktime;
  var i, input, output, hash, index, sequence;
  var keys, addrs, key, value, address, b58;

  if (args.help || args.length < 2 || args.length > 3) {
    return callback(new Error('createrawtransaction'
      + ' [{"txid":"id","vout":n},...]'
      + ' {"address":amount,"data":"hex",...}'
      + ' ( locktime )'));
  }

  if (!args[0] || !args[1])
    return callback(new Error('Invalid parameter'));

  inputs = args[0];
  sendTo = args[1];

  if (!Array.isArray(inputs) || typeof sendTo !== 'object')
    return callback(new Error('Invalid parameter'));

  tx = bcoin.tx();

  if (args.length > 2 && args[2] != null) {
    locktime = Number(args[2]);
    if (locktime < 0 || locktime > 0xffffffff)
      return callback(new Error('Invalid parameter, locktime out of range'));
    tx.locktime = locktime;
  }

  for (i = 0; i < inputs.length; i++) {
    input = inputs[i];

    if (!input)
      return callback(new Error('Invalid parameter'));

    hash = input.txid;
    index = input.vout;
    sequence = 0xffffffff;

    if (tx.locktime)
      sequence--;

    if (!utils.isHex(hash)
        || hash.length !== 64
        || !utils.isNumber(index)
        || index < 0) {
      return callback(new Error('Invalid parameter'));
    }

    if (utils.isNumber(input.sequence)) {
      if (input.sequence < 0 || input.sequence > 0xffffffff)
        return callback(new Error('Invalid parameter'));
      sequence = input.sequence;
    }

    input = new bcoin.input({
      prevout: {
        hash: utils.revHex(hash),
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
      output = new bcoin.output({
        value: 0,
        script: bcoin.script.fromNulldata(value)
      });
      tx.outputs.push(output);
      continue;
    }

    address = bcoin.address.fromBase58(key);
    b58 = address.toBase58();

    if (addrs[b58])
      return callback(new Error('Duplicate address'));

    addrs[b58] = true;

    output = new bcoin.output({
      value: utils.satoshi(value),
      address: address
    });

    tx.outputs.push(output);
  }

  callback(null, tx.toRaw().toString('hex'));
};

RPC.prototype.decoderawtransaction = function decoderawtransaction(args, callback) {
  var tx;

  if (args.help || args.length !== 1)
    return callback(new Error('decoderawtransaction "hexstring"'));

  if (!utils.isHex(args[0]))
    return callback(new Error('Invalid parameter'));

  tx = bcoin.tx.fromRaw(args[0], 'hex');

  callback(null, this.txToJSON(tx));
};

RPC.prototype.decodescript = function decodescript(args, callback) {
  var data, script, hash, address;

  if (args.help || args.length !== 1)
    return callback(new Error('decodescript \"hex\"'));

  data = String(args[0]);
  script = new bcoin.script();

  if (data.length > 0)
    script.fromRaw(new Buffer(data, 'hex'));

  hash = utils.hash160(script.toRaw());
  address = bcoin.address.fromHash(hash, bcoin.script.types.SCRIPTHASH);

  script = scriptToJSON(script);
  script.p2sh = address.toBase58();

  callback(null, script);
};

RPC.prototype.getrawtransaction = function getrawtransaction(args, callback) {
  var self = this;
  var hash, verbose;

  if (args.help || args.length < 1 || args.length > 2)
    return callback(new Error('getrawtransaction "txid" ( verbose )'));

  hash = args[0];

  if (!utils.isHex(hash) || hash.length !== 64)
    return callback(new Error('Invalid parameter'));

  verbose = false;

  if (args.length > 1)
    verbose = Boolean(args[1]);

  this.node.getTX(utils.revHex(hash), function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback(new Error('No information available about transaction'));

    if (!verbose)
      return callback(null, tx.toRaw().toString('hex'));

    tx = self.txToJSON(tx);
    tx.hex = tx.toRaw().toString('hex');

    callback(null, tx);
  });
};

RPC.prototype.sendrawtransaction = function sendrawtransaction(args, callback) {
  var tx;

  if (args.help || args.length < 1 || args.length > 2) {
    return callback(new Error('sendrawtransaction'
      + ' "hexstring" ( allowhighfees )'));
    }

  if (!utils.isHex(args[0]))
    return callback(new Error('Invalid parameter'));

  tx = bcoin.tx.fromRaw(args[0], 'hex');

  this.node.sendTX(tx);

  callback(null, tx.rhash);
};

RPC.prototype.signrawtransaction = function signrawtransaction(args, callback) {
  var self = this;
  var raw, p, txs, merged;

  if (args.help || args.length < 1 || args.length > 4) {
    return callback(new Error('signrawtransaction'
      + ' "hexstring" ('
      + ' [{"txid":"id","vout":n,"scriptPubKey":"hex",'
      + 'redeemScript":"hex"},...] ["privatekey1",...]'
      + ' sighashtype )'));
  }

  raw = new Buffer(args[0], 'hex');
  p = new bcoin.reader(raw);
  txs = [];

  while (p.left())
    txs.push(bcoin.mtx.fromRaw(p));

  merged = txs[0];

  this.node.fillCoins(merged, function(err) {
    if (err)
      return callback(err);
    self.wallet.fillCoins(merged, function(err) {
      if (err)
        return callback(err);
      self._signrawtransaction(merged, txs, args, callback);
    });
  });
};

RPC.prototype._signrawtransaction = function signrawtransaction(merged, txs, args, callback) {
  var keys = [];
  var keyMap = {};
  var k, i, secret, key, addr;
  var coins, prevout, prev;
  var hash, index, script, value;
  var redeem, op, j;
  var type, parts, tx;

  if (args.length > 2 && Array.isArray(args[2])) {
    k = args[2];
    for (i = 0; i < k.length; i++) {
      secret = k[i];
      if (!utils.isBase58(secret))
        return callback(new Error('Invalid parameter'));
      key = bcoin.keypair.fromSecret(secret);
      addr = new bcoin.keyring({ publicKey: key.getPublicKey() });
      key = { addr: addr, key: key.getPrivateKey() };
      keyMap[addr.getPublicKey('hex')] = key;
      keys.push(key);
    }
  }

  coins = [];
  if (args.length > 1 && Array.isArray(args[1])) {
    prevout = args[1];
    for (i = 0; i < prevout.length; i++) {
      prev = prevout[i];
      if (!prev)
        return callback(new Error('Invalid parameter'));
      hash = prev.txid;
      index = prev.vout;
      script = prev.scriptPubKey;
      value = utils.satoshi(prev.amount || 0);
      if (!utils.isHex(hash)
          || hash.length !== 64
          || !utils.isNumber(index)
          || index < 0
          || !utils.isHex(script)) {
        return callback(new Error('Invalid parameter'));
      }

      script = bcoin.script.fromRaw(script, 'hex');
      coins.push(new bcoin.coin({
        hash: utils.revHex(hash),
        index: index,
        script: script,
        value: value,
        coinbase: false,
        height: -1
      }));

      if (keys.length === 0 || !utils.isHex(prev.redeemScript))
        continue;

      if (script.isScripthash() || script.isWitnessScripthash()) {
        redeem = bcoin.script.fromRaw(prev.redeemScript, 'hex');
        if (!redeem.isMultisig())
          continue;
        for (j = 1; j < redeem.length - 2; j++) {
          op = redeem.get(j);
          key = keyMap[op.toString('hex')];
          if (key) {
            key.addr.type = 'multisig';
            key.addr.m = redeem.getSmall(0);
            key.addr.n = redeem.getSmall(redeem.length - 1);
            key.addr.keys = redeem.slice(1, -2);
            key.addr.witness = script.isWitnessScripthash();
            break;
          }
        }
      }
    }
    tx.fillCoins(coins);
  }

  type = constants.hashType.ALL;
  if (args.length > 3 && typeof args[3] === 'string') {
    parts = args[3].split('|');
    type = constants.hashType[parts[0]];
    if (type == null)
      return callback(new Error('Invalid parameter'));
    if (parts.length > 2)
      return callback(new Error('Invalid parameter'));
    if (parts.length === 2) {
      if (parts[1] !== 'ANYONECANPAY')
        return callback(new Error('Invalid parameter'));
      type |= constants.hashType.ANYONECANPAY;
    }
  }

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    key.addr.sign(merged, key.key, null, type);
  }

  this.node.wallet.sign(merged, { type: type }, function(err) {
    if (err)
      return callback(err);

    for (i = 1; i < txs.length; i++) {
      tx = txs[i];
      mergeSigs(merged, tx);
    }

    callback(null, {
      hex: merged.toRaw().toString('hex'),
      complete: merged.isSigned()
    });
  });
};

function mergeSigs(a, b) {
  var map = {};
  var i, input, prev, key, ia, ib;

  for (i = 0; i < b.inputs.length; i++) {
    input = b.inputs[i];
    prev = input.prevout;
    key = prev.hash + '/' + prev.index;
    map[key] = input;
  }

  for (i = 0; i < b.inputs.length; i++) {
    ia = a.inputs[i];
    if (!ia || ia.length !== 0)
      break;
    key = prev.hash + '/' + prev.index;
    ib = map[key];
    if (ib)
      ia.script = ib.script;
  }
}

RPC.prototype.fundrawtransaction = function fundrawtransaction(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype._createRedeem = function _createRedeem(args, callback) {
  var self = this;
  var m, n, keys, hash, script;

  if (!utils.isNumber(args[0])
      || !Array.isArray(args[1])
      || args[0] < 1
      || args[1].length < args[0]
      || args[1].length > 16) {
    return callback(new Error('Invalid parameter.'));
  }

  m = args[0];
  n = args[1].length;
  keys = args[1];

  utils.forEachSerial(keys, function(key, next, i) {
    if (!utils.isBase58(key)) {
      if (!utils.isHex(key))
        return next(new Error('Invalid key.'));
      keys[i] = new Buffer(key, 'hex');
      return next();
    }

    hash = bcoin.address.getHash(key, 'hex');
    if (!hash)
      return next(new Error('Invalid key.'));

    self.node.wallet.getKeyring(hash, function(err, address) {
      if (err)
        return next(err);

      if (!address)
        return next(new Error('Invalid key.'));

      keys[i] = address.getPublicKey();

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    script = bcoin.script.fromMultisig(m, n, keys);

    if (script.toRaw().length > constants.script.MAX_PUSH)
      return callback(new Error('Redeem script exceeds size limit.'));

    callback(null, script);
  });
};

/* Utility functions */
RPC.prototype.createmultisig = function createmultisig(args, callback) {
  if (args.help || args.length < 2 || args.length > 2)
    return callback(new Error('createmultisig nrequired ["key",...]'));

  this._createRedeem(args, function(err, script) {
    if (err)
      return callback(err);

    callback(null, {
      address: script.getAddress().toBase58(),
      redeemScript: script.toJSON()
    });
  });
};

RPC.prototype._scriptForWitness = function scriptForWitness(script) {
  var hash;

  if (script.isPubkey()) {
    hash = utils.hash160(script.get(0));
    return bcoin.script.fromProgram(0, hash);
  }

  if (script.isPubkeyhash()) {
    hash = script.get(2);
    return bcoin.script.fromProgram(0, hash);
  }

  hash = utils.sha256(script.toRaw());
  return bcoin.script.fromProgram(0, hash);
};

RPC.prototype.createwitnessaddress = function createwitnessaddress(args, callback) {
  var raw, script, program;

  if (args.help || args.length !== 1)
    return callback(new Error('createwitnessaddress "script"'));

  raw = args[1];

  if (!utils.isHex(raw))
    return callback(new Error('Invalid parameter'));

  script = bcoin.script.fromRaw(raw, 'hex');
  program = this._scriptForWitness(script);

  callback(null, {
    address: program.getAddress().toBase58(),
    witnessScript: program.toJSON()
  });
};

RPC.prototype.validateaddress = function validateaddress(args, callback) {
  var b58, address, json;

  if (args.help || args.length !== 1)
    return callback(new Error('validateaddress "bitcoinaddress"'));

  b58 = String(args[0]);

  try {
    address = bcoin.address.fromBase58(b58);
  } catch (e) {
    return callback(null, {
      isvalid: false
    });
  }

  this.wallet.getKeyring(address.getHash('hex'), function(err, ring) {
    if (err)
      return callback(err);

    json = {
      isvalid: true,
      address: address.toBase58(),
      scriptPubKey: address.toScript().toJSON(),
      ismine: ring ? true : false,
      iswatchonly: false
    };

    if (!ring)
      return callback(null, json);

    json.account = ring.name;
    json.hdkeypath = ring.account + '/' + ring.change + '/' + ring.index;

    callback(null, json);
  });
};

RPC.magic = 'Bitcoin Signed Message:\n';

RPC.prototype.verifymessage = function verifymessage(args, callback) {
  var address, sig, msg, key;

  if (args.help || args.length !== 3) {
    return callback(new Error('verifymessage'
      + ' "bitcoinaddress" "signature" "message"'));
  }

  address = String(args[0]);
  sig = String(args[1]);
  msg = String(args[2]);

  address = bcoin.address.getHash(address);

  if (!address)
    return callback(new Error('Invalid address.'));

  sig = new Buffer(sig, 'base64');
  msg = new Buffer(RPC.magic + msg, 'utf8');
  msg = utils.hash256(msg);

  key = bcoin.ec.recover(msg, sig, 0, true);

  if (!key)
    return callback(null, false);

  key = utils.hash160(key);

  callback(null, utils.ccmp(key, address));
};

RPC.prototype.signmessagewithprivkey = function signmessagewithprivkey(args, callback) {
  var key, msg, sig;

  if (args.help || args.length !== 2)
    return callback(new Error('signmessagewithprivkey "privkey" "message"'));

  key = String(args[0]);
  msg = String(args[1]);

  key = bcoin.keypair.fromSecret(key).getPrivateKey();
  msg = new Buffer(RPC.magic + msg, 'utf8');
  msg = utils.hash256(msg);

  sig = bcoin.ec.sign(msg, key);

  callback(null, sig.toString('base64'));
};

RPC.prototype.estimatefee = function estimatefee(args, callback) {
  var blocks, fee;

  if (args.help || args.length !== 1)
    return callback(new Error('estimatefee nblocks'));

  blocks = Number(args[0]);

  if (!utils.isNumber(blocks))
    blocks = -1;

  if (blocks < 1)
    blocks = 1;

  fee = this.fees.estimateFee(blocks, false);

  if (fee === 0)
    fee = -1;
  else
    fee = +utils.btc(fee);

  callback(null, fee);
};

RPC.prototype.estimatepriority = function estimatepriority(args, callback) {
  var blocks, pri;

  if (args.help || args.length !== 1)
    return callback(new Error('estimatepriority nblocks'));

  blocks = Number(args[0]);

  if (!utils.isNumber(blocks))
    blocks = -1;

  if (blocks < 1)
    blocks = 1;

  pri = this.fees.estimatePriority(blocks, false);

  callback(null, pri);
};

RPC.prototype.estimatesmartfee = function estimatesmartfee(args, callback) {
  var blocks, fee;

  if (args.help || args.length !== 1)
    return callback(new Error('estimatesmartfee nblocks'));

  blocks = Number(args[0]);

  if (!utils.isNumber(blocks))
    blocks = -1;

  if (blocks < 1)
    blocks = 1;

  fee = this.fees.estimateFee(blocks, true);

  if (fee === 0)
    fee = -1;
  else
    fee = +utils.btc(fee);

  callback(null, {
    fee: fee,
    blocks: blocks
  });
};

RPC.prototype.estimatesmartpriority = function estimatesmartpriority(args, callback) {
  var blocks, pri;

  if (args.help || args.length !== 1)
    return callback(new Error('estimatesmartpriority nblocks'));

  blocks = Number(args[0]);

  if (!utils.isNumber(blocks))
    blocks = -1;

  if (blocks < 1)
    blocks = 1;

  pri = this.fees.estimatePriority(blocks, true);

  callback(null, {
    priority: pri,
    blocks: blocks
  });
};

RPC.prototype.invalidateblock = function invalidateblock(args, callback) {
  var hash;

  if (args.help || args.length !== 1)
    return callback(new Error('invalidateblock "hash"'));

  hash = args[0];

  if (!utils.isHex(hash) || hash.length !== 64)
    return callback(new Error('Block not found.'));

  hash = utils.revHex(hash);

  this.chain.invalid[hash] = true;

  callback(null, null);
};

RPC.prototype.reconsiderblock = function reconsiderblock(args, callback) {
  var hash;

  if (args.help || args.length !== 1)
    return callback(new Error('reconsiderblock "hash"'));

  hash = args[0];

  if (!utils.isHex(hash) || hash.length !== 64)
    return callback(new Error('Block not found.'));

  hash = utils.revHex(hash);

  delete this.chain.invalid[hash];

  callback(null, null);
};

RPC.prototype.setmocktime = function setmocktime(args, callback) {
  var time, delta;

  if (args.help || args.length !== 1)
    return callback(new Error('setmocktime timestamp'));

  time = args[0];

  if (!utils.isNumber(time))
    return callback(new Error('Invalid parameter.'));

  delta = bcoin.now() - time;
  bcoin.time.offset = -delta;

  callback(null, null);
};

/*
 * Wallet
 */

RPC.prototype.resendwallettransactions = function resendwallettransactions(args, callback) {
  var self = this;
  var hashes = [];
  var i, tx;

  if (args.help || args.length !== 0)
    return callback(new Error('resendwallettransactions'));

  this.walletdb.getUnconfirmed(function(err, txs) {
    if (err)
      return callback(err);

    for (i = 0; i < txs.length; i++) {
      tx = txs[i];
      hashes.push(tx.rhash);
      self.pool.broadcast(tx);
    }

    callback(null, hashes);
  });
};

RPC.prototype.addmultisigaddress = function addmultisigaddress(args, callback) {
  if (args.help || args.length < 2 || args.length > 3) {
    return callback(new Error('addmultisigaddress'
      + ' nrequired ["key",...] ( "account" )'));
  }
  // Impossible to implement in bcoin (no address book).
  callback(new Error('Not implemented.'));
};

RPC.prototype.addwitnessaddress = function addwitnessaddress(args, callback) {
  if (args.help || args.length < 1 || args.length > 1)
    return callback(new Error('addwitnessaddress \"address\"'));
  // Unlikely to be implemented.
  callback(new Error('Not implemented.'));
};

RPC.prototype.backupwallet = function backupwallet(args, callback) {
  if (args.help || args.length !== 1)
    return callback(new Error('backupwallet "destination"'));
  // Unlikely to be implemented.
  callback(new Error('Not implemented.'));
};

RPC.prototype.dumpprivkey = function dumpprivkey(args, callback) {
  var self = this;
  var hash, key;

  if (args.help || args.length !== 1)
    return callback(new Error('dumpprivkey "bitcoinaddress"'));

  hash = bcoin.address.getHash(String(args[0]), 'hex');

  if (!hash)
    return callback(new Error('Invalid address.'));

  this.wallet.getKeyring(hash, function(err, ring) {
    if (err)
      return callback(err);

    if (!ring)
      return callback(new Error('Key not found.'));

    key = self.wallet.master.key;

    if (!key)
      return callback(new Error('Wallet is locked.'));

    key = key.deriveAccount44(ring.account);
    key = key.derive(ring.change).derive(ring.index);

    callback(null, key.toSecret());
  });
};

RPC.prototype.dumpwallet = function dumpwallet(args, callback) {
  var self = this;
  var file, time, key, address, fmt, str, out;

  if (args.help || args.length !== 1)
    return callback(new Error('dumpwallet "filename"'));

  file = utils.normalize(String(args[0]));
  time = utils.date();
  out = [
    utils.fmt('# Wallet Dump created by BCoin %s', constants.USER_VERSION),
    utils.fmt('# * Created on %s', time),
    utils.fmt('# * Best block at time of backup was %d (%s),',
      this.chain.height, this.chain.tip.rhash),
    utils.fmt('#   mined on %s', utils.date(this.chain.tip.ts)),
    utils.fmt('# * File: %s', file),
    ''
  ];

  this.walletdb.getAddresses(this.wallet.id, function(err, hashes) {
    if (err)
      return callback(err);

    utils.forEachSerial(hashes, function(hash, next) {
      self.wallet.getKeyring(hash, function(err, ring) {
        if (err)
          return callback(err);

        if (!ring)
          return next();

        key = self.wallet.master.key;

        if (!key)
          return callback(new Error('Wallet is locked.'));

        key = key.deriveAccount44(ring.account);
        key = key.derive(ring.change).derive(ring.index);
        address = ring.getAddress('base58');
        fmt = '%s %s label= addr=%s';

        if (address.change)
          fmt = '%s %s change=1 addr=%s';

        str = utils.fmt(fmt, key.toSecret(), time, address);

        out.push(str);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      out.push('');
      out.push('# End of dump');
      out.push('');

      out = out.join('\n');

      callback(null, out);
    });
  });
};

RPC.prototype.encryptwallet = function encryptwallet(args, callback) {
  var passphrase;

  if (!this.wallet.master.encrypted && (args.help || args.help !== 1))
    return callback(new Error('encryptwallet "passphrase"'));

  if (this.wallet.master.encrypted)
    return callback(new Error('Already running with an encrypted wallet'));

  passphrase = args[0];

  if (typeof passphrase !== 'string' || passphrase.length < 1)
    return callback(new Error('encryptwallet "passphrase"'));

  this.wallet.setPassphrase(passphrase, function(err) {
    if (err)
      return callback(err);
    callback(null, 'wallet encrypted; we do not need to stop!');
  });
};

RPC.prototype.getaccountaddress = function getaccountaddress(args, callback) {
  var account;

  if (args.help || args.length !== 1)
    return callback(new Error('getaccountaddress "account"'));

  account = String(args[0]);

  if (!account)
    account = 'default';

  this.wallet.getAccount(account, function(err, account) {
    if (err)
      return callback(err);

    if (!account)
      return callback(null, '');

    callback(null, account.receiveAddress.getAddress('base58'));
  });
};

RPC.prototype.getaccount = function getaccount(args, callback) {
  var hash;

  if (args.help || args.length !== 1)
    return callback(new Error('getaccount "bitcoinaddress"'));

  hash = bcoin.address.getHash(args[0], 'hex');

  if (!hash)
    return callback(new Error('Invalid address.'));

  this.wallet.getKeyring(hash, function(err, address) {
    if (err)
      return callback(err);

    if (!address)
      return callback(null, '');

    return callback(null, address.name);
  });
};

RPC.prototype.getaddressesbyaccount = function getaddressesbyaccount(args, callback) {
  var self = this;
  var account, addrs;

  if (args.help || args.length !== 1)
    return callback(new Error('getaddressesbyaccount "account"'));

  account = String(args[0]);

  if (!account)
    account = 'default';

  addrs = [];

  this.walletdb.getAddresses(this.wallet.id, function(err, hashes) {
    if (err)
      return callback(err);

    utils.forEachSerial(hashes, function(hash, next) {
      self.wallet.getKeyring(hash, function(err, address) {
        if (err)
          return callback(err);

        if (address && address.name === account)
          addrs.push(address.getAddress('base58'));

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      callback(null, addrs);
    });
  });
};

RPC.prototype.getbalance = function getbalance(args, callback) {
  var minconf = 0;
  var account, value;

  if (args.help || args.length > 3)
    return callback(new Error('getbalance ( "account" minconf includeWatchonly )'));

  if (args.length >= 1) {
    account = String(args[0]);
    if (!account)
      account = 'default';
    if (account === '*')
      account = null;
  }

  if (args.length >= 2)
    minconf = Number(args[1]);

  this.wallet.getBalance(account, function(err, balance) {
    if (err)
      return callback(err);

    if (minconf >= 1)
      value = balance.confirmed;
    else
      value = balance.total;

    callback(null, +utils.btc(value));
  });
};

RPC.prototype.getnewaddress = function getnewaddress(args, callback) {
  var account;

  if (args.help || args.length > 1)
    return callback(new Error('getnewaddress ( "account" )'));

  if (args.length === 1)
    account = String(args[0]);

  if (!account)
    account = 'default';

  this.wallet.createReceive(account, function(err, address) {
    if (err)
      return callback(err);
    callback(null, address.getAddress('base58'));
  });
};

RPC.prototype.getrawchangeaddress = function getrawchangeaddress(args, callback) {
  if (args.help || args.length > 1)
    return callback(new Error('getrawchangeaddress'));

  this.wallet.createChange(function(err, address) {
    if (err)
      return callback(err);
    callback(null, address.getAddress('base58'));
  });
};

RPC.prototype.getreceivedbyaccount = function getreceivedbyaccount(args, callback) {
  var self = this;
  var minconf = 0;
  var total = 0;
  var i, j, account, tx, output;

  if (args.help || args.length < 1 || args.length > 2)
    return callback(new Error('getreceivedbyaccount "account" ( minconf )'));

  account = String(args[0]);

  if (!account)
    account = 'default';

  if (args.length === 2)
    minconf = Number(args[1]);

  this.wallet.getHistory(account, function(err, txs) {
    if (err)
      return callback(err);

    for (i = 0; i < txs.length; i++) {
      tx = txs[i];
      if (minconf) {
        if (tx.height === -1)
          continue;
        if (!(self.chain.height - tx.height + 1 >= minconf))
          continue;
      }
      for (j = 0; j < tx.outputs.length; j++) {
        output = tx.outputs[j];
        total += output.value;
      }
    }

    callback(null, +utils.btc(total));
  });
};

RPC.prototype.getreceivedbyaddress = function getreceivedbyaddress(args, callback) {
  var self = this;
  var minconf = 0;
  var total = 0;
  var i, j, hash, tx, output;

  if (args.help || args.length < 1 || args.length > 2)
    return callback(new Error('getreceivedbyaddress "bitcoinaddress" ( minconf )'));

  hash = bcoin.address.getHash(String(args[0]), 'hex');

  if (!hash)
    return callback(new Error('Invalid address'));

  if (args.length === 2)
    minconf = Number(args[1]);

  this.wallet.getHistory(function(err, txs) {
    if (err)
      return callback(err);

    for (i = 0; i < txs.length; i++) {
      tx = txs[i];
      if (minconf) {
        if (tx.height === -1)
          continue;
        if (!(self.chain.height - tx.height + 1 >= minconf))
          continue;
      }
      for (j = 0; j < tx.outputs.length; j++) {
        output = tx.outputs[j];
        if (output.getHash('hex') === hash)
          total += output.value;
      }
    }

    callback(null, +utils.btc(total));
  });
};

RPC.prototype.gettransaction = function gettransaction(args, callback) {
  var hash;

  if (args.help || args.length < 1 || args.length > 2)
    return callback(new Error('gettransaction "txid" ( includeWatchonly )'));

  hash = String(args[0]);

  if (!utils.isHex(hash) || hash.length !== 64)
    return callback(new Error('Invalid parameter'));

  hash = utils.revHex(hash);

  // XXX TODO
  callback(new Error('Not implemented.'));
};

RPC.prototype.abandontransaction = function abandontransaction(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.getunconfirmedbalance = function getunconfirmedbalance(args, callback) {
  if (args.help || args.length > 0)
    return callback(new Error('getunconfirmedbalance'));

  this.wallet.getBalance(function(err, balance) {
    if (err)
      return callback(err);

    callback(null, +utils.btc(balance.unconfirmed));
  });
};

RPC.prototype.getwalletinfo = function getwalletinfo(args, callback) {
  var self = this;

  if (args.help || args.length !== 0)
    return callback(new Error('getwalletinfo'));

  this.wallet.getBalance(function(err, balance) {
    if (err)
      return callback(err);

    self.walletdb.tx.getHistoryHashes(self.wallet.id, function(err, hashes) {
      if (err)
        return callback(err);

      callback(null, {
        walletversion: 0,
        balance: +utils.btc(balance.total),
        unconfirmed_balance: +utils.btc(balance.unconfirmed),
        txcount: hashes.length,
        keypoololdest: 0,
        keypoolsize: 0,
        unlocked_until: self.wallet.master.until,
        paytxfee: self.feeRate != null
          ? +utils.btc(self.feeRate)
          : +utils.btc(0)
      });
    });
  });
};

RPC.prototype.importprivkey = function importprivkey(args, callback) {
  if (args.help || args.length < 1 || args.length > 3) {
    return callback(new Error('importprivkey'
      + ' "bitcoinprivkey" ( "label" rescan )'));
  }
  // Impossible to implement in bcoin.
  callback(new Error('Not implemented.'));
};

RPC.prototype.importwallet = function importwallet(args, callback) {
  if (args.help || args.length !== 1)
    return callback(new Error('importwallet "filename"'));
  // Impossible to implement in bcoin.
  callback(new Error('Not implemented.'));
};

RPC.prototype.importaddress = function importaddress(args, callback) {
  if (args.help || args.length < 1 || args.length > 4) {
    return callback(new Error('importaddress'
      + ' "address" ( "label" rescan p2sh )'));
  }
  // Impossible to implement in bcoin.
  callback(new Error('Not implemented.'));
};

RPC.prototype.importpubkey = function importpubkey(args, callback) {
  if (args.help || args.length < 1 || args.length > 4)
    return callback(new Error('importpubkey "pubkey" ( "label" rescan )'));
  // Impossible to implement in bcoin.
  callback(new Error('Not implemented.'));
};

RPC.prototype.keypoolrefill = function keypoolrefill(args, callback) {
  if (args.help || args.length > 1)
    return callback(new Error('keypoolrefill ( newsize )'));
  callback(null, null);
};

RPC.prototype.listaccounts = function listaccounts(args, callback) {
  var self = this;
  var map;

  if (args.help || args.length > 2)
    return callback(new Error('listaccounts ( minconf includeWatchonly)'));

  map = {};

  this.walletdb.getAccounts(this.wallet.id, function(err, accounts) {
    if (err)
      return callback(err);

    utils.forEachSerial(accounts, function(account, next) {
      self.wallet.getBalance(account, function(err, balance) {
        if (err)
          return next(err);

        map[account] = +utils.btc(balance.total);
        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      callback(null, map);
    });
  });
};

RPC.prototype.listaddressgroupings = function listaddressgroupings(args, callback) {
  if (args.help)
    return callback(new Error('listaddressgroupings'));
  callback(new Error('Not implemented.'));
};

RPC.prototype.listlockunspent = function listlockunspent(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.listreceivedbyaccount = function listreceivedbyaccount(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.listreceivedbyaddress = function listreceivedbyaddress(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.listsinceblock = function listsinceblock(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.listtransactions = function listtransactions(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.listunspent = function listunspent(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.lockunspent = function lockunspent(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.move = function move(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype._send = function _send(account, address, amount, subtractFee, callback) {
  var self = this;

  var options = {
    account: account,
    subtractFee: subtractFee,
    rate: this.feeRate,
    outputs: [{
      address: address,
      value: amount
    }]
  };

  this.wallet.createTX(options, function(err, tx) {
    if (err)
      return callback(err);

    self.wallet.sign(tx, function(err) {
      if (err)
        return callback(err);

      self.node.sendTX(tx, function(err) {
        if (err)
          return callback(err);
        callback(null, tx);
      });
    });
  });
};

RPC.prototype.sendfrom = function sendfrom(args, callback) {
  var account, address, amount;

  if (args.help || args.length < 3 || args.length > 6) {
    return callback(new Error('sendfrom'
      + ' "fromaccount" "tobitcoinaddress"'
      + ' amount ( minconf "comment" "comment-to" )'));
  }

  account = String(args[0]);
  address = bcoin.address.fromBase58(String(args[1]));
  amount = utils.satoshi(String(args[2]));

  if (!account)
    account = 'default';

  this._send(account, address, amount, false, function(err, tx) {
    if (err)
      return callback(err);
    callback(null, tx.rhash);
  });
};

RPC.prototype.sendmany = function sendmany(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.sendtoaddress = function sendtoaddress(args, callback) {
  var address, amount, subtractFee;

  if (args.help || args.length < 2 || args.length > 5) {
    return callback(new Error('sendtoaddress'
      + ' "bitcoinaddress" amount'
      + ' ( "comment" "comment-to"'
      + ' subtractfeefromamount )'));
  }

  address = bcoin.address.fromBase58(String(args[0]));
  amount = utils.satoshi(String(args[1]));
  subtractFee = Boolean(args[4]);

  this._send(null, address, amount, subtractFee, function(err, tx) {
    if (err)
      return callback(err);
    callback(null, tx.rhash);
  });
};

RPC.prototype.setaccount = function setaccount(args, callback) {
  if (args.help || args.length < 1 || args.length > 2)
    return callback(new Error('setaccount "bitcoinaddress" "account"'));
  // Impossible to implement in bcoin:
  callback(new Error('Not implemented.'));
};

RPC.prototype.settxfee = function settxfee(args, callback) {
  if (args.help || args.length < 1 || args.length > 1)
    return callback(new Error('settxfee amount'));

  this.feeRate = utils.satoshi(args[0]);

  callback(null, true);
};

RPC.prototype.signmessage = function signmessage(args, callback) {
  var self = this;
  var address, msg, key, sig;

  if (args.help || args.length !== 2)
    return callback(new Error('signmessage "bitcoinaddress" "message"'));

  address = String(args[0]);
  msg = String(args[1]);

  address = bcoin.address.getHash(address, 'hex');

  if (!address)
    return callback(new Error('Invalid address.'));

  this.wallet.getKeyring(address, function(err, address) {
    if (err)
      return callback(err);

    if (!address)
      return callback(new Error('Address not found.'));

    key = self.wallet.master.key;

    if (!key)
      return callback(new Error('Wallet is locked.'));

    key = key.deriveAccount44(address.account);
    key = key.derive(address.change).derive(address.index);

    msg = new Buffer(RPC.magic + msg, 'utf8');
    msg = utils.hash256(msg);

    sig = bcoin.ec.sign(msg, key);

    callback(null, sig.toString('base64'));
  });
};

RPC.prototype.walletlock = function walletlock(args, callback) {
  if (args.help || (this.wallet.master.encrypted && args.length !== 0))
    return callback(new Error('walletlock'));

  if (!this.wallet.master.encrypted)
    return callback(new Error('Wallet is not encrypted.'));

  this.wallet.lock();
  callback(null, null);
};

RPC.prototype.walletpassphrasechange = function walletpassphrasechange(args, callback) {
  var old, new_;

  if (args.help || (this.wallet.master.encrypted && args.length !== 2)) {
    return callback(new Error('walletpassphrasechange'
      + ' "oldpassphrase" "newpassphrase"'));
  }

  if (!this.wallet.master.encrypted)
    return callback(new Error('Wallet is not encrypted.'));

  if (typeof args[0] !== 'string' || typeof args[1] !== 'string')
    return callback(new Error('Invalid parameter'));

  old = args[0];
  new_ = args[1];

  if (old.length < 1 || new_.length < 1)
    return callback(new Error('Invalid parameter'));

  this.wallet.setPassphrase(old, new_, function(err) {
    if (err)
      return callback(err);

    callback(null, null);
  });
};

RPC.prototype.walletpassphrase = function walletpassphrase(args, callback) {
  if (args.help || (this.wallet.master.encrypted && args.length !== 2))
    return callback(new Error('walletpassphrase "passphrase" timeout'));

  if (!this.wallet.master.encrypted)
    return callback(new Error('Wallet is not encrypted.'));

  if (typeof args[0] !== 'string' || args[0].length < 1)
    return callback(new Error('Invalid parameter'));

  if (!utils.isNumber(args[1]) || args[1] < 0)
    return callback(new Error('Invalid parameter'));

  this.wallet.unlock(args[0], args[1], function(err) {
    if (err)
      return callback(err);
    callback(null, null);
  });
};

module.exports = RPC;
