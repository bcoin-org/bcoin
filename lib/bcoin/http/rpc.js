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
    case 'resendwallettransactions':
    case 'abandontransaction':
    case 'addmultisigaddress':
    case 'addwitnessaddress':
    case 'backupwallet':
    case 'dumpprivkey':
    case 'dumpwallet':
    case 'encryptwallet':
    case 'getaccountaddress':
    case 'getaccount':
    case 'getaddressesbyaccount':
    case 'getbalance':
    case 'getnewaddress':
    case 'getrawchangeaddress':
    case 'getreceivedbyaccount':
    case 'getreceivedbyaddress':
    case 'gettransaction':
    case 'getunconfirmedbalance':
    case 'getwalletinfo':
    case 'importprivkey':
    case 'importwallet':
    case 'importaddress':
    case 'importprunedfunds':
    case 'importpubkey':
    case 'keypoolrefill':
    case 'listaccounts':
    case 'listaddressgroupings':
    case 'listlockunspent':
    case 'listreceivedbyaccount':
    case 'listreceivedbyaddress':
    case 'listsinceblock':
    case 'listtransactions':
    case 'listunspent':
    case 'lockunspent':
    case 'move':
    case 'sendfrom':
    case 'sendmany':
    case 'sendtoaddress':
    case 'setaccount':
    case 'settxfee':
    case 'signmessage':
    case 'walletlock':
    case 'walletpassphrasechange':
    case 'walletpassphrase':
    case 'removeprunedfunds':
      return callback(new Error('Method not found.'));

    default:
      return callback(new Error('Method not found.'));
  }
};

/*
 * Overall control/query calls
 */

RPC.prototype.getinfo = function getinfo(args, callback) {
  return callback(null, {
    version: constants.USER_VERSION,
    protocolversion: constants.VERSION,
    walletversion: 0,
    balance: 0,
    blocks: this.chain.height,
    timeoffset: bcoin.time.offset,
    connections: this.pool.peers.all.length,
    proxy: '',
    difficulty: this._getDifficulty(),
    testnet: this.network.type !== 'main',
    keypoololdest: 0,
    keypoolsize: 0,
    unlocked_until: 0,
    paytxfee: this.network.getRate() / constants.COIN,
    relayfee: this.network.getMinRelay() / constants.COIN,
    errors: ''
  });
};

RPC.prototype.help = function help(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.stop = function stop(args, callback) {
  callback(null, 'Stopping.');

  utils.nextTick(function() {
    process.exit(0);
  });
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
        if (seed.host === host.host)
          break;
      }

      if (i === this.pool.seeds.length)
        break;

      this.pool.seeds.splice(i, 1);
      break;
    case 'onetry':
      break;
  }

  callback(null, null);
};

RPC.prototype.disconnectnode = function disconnectnode(args, callback) {
  var node, peer;

  if (args.help || args.length !== 1)
    return callback(new Error('disconnectnode "node" '));

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
      window: this.network.block.majorityWindow,
    },
    reject: {
      status: status,
      found: status ? this.network.block.majorityWindow : 0,
      required: this.network.block.majorityRejectOutdated,
      winodw: this.network.block.majorityWindow,
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
        chainwork: self.chain.tip.chainwork
          .toArrayLike(Buffer, 'be', 32).toString('hex'),
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

  callback(null, this.chain.tip.height + 1);
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
        return callback(new Error('Can"t read block from disk'));
      }

      if (!verbose)
        return callback(null, block.toRaw('hex'));

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
        out.coinbase = input.script.toRaw().toString('hex');
      } else {
        out.txid = utils.revHex(input.prevout.hash);
        out.vout = input.prevout.index;
        out.scriptSig = {
          asm: input.script.toASM(),
          hex: input.script.toRaw().toString('hex')
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
        value: utils.btc(output.value),
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
    out.hex = script.toRaw().toString('hex');

  type = script.getType();
  out.type = bcoin.script.typesByVal[type];

  out.reqSigs = script.isMultisig() ? bcoin.script.getSmall(script.code[0]) : 1;

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
        confirmations: this.chain.height - entry.height + 1,
        height: entry.height,
        version: entry.version,
        merkleroot: utils.revHex(entry.merkleRoot),
        time: entry.ts,
        mediantime: medianTime,
        bits: entry.bits,
        difficulty: self._getDifficulty(entry),
        chainwork: entry.chainwork.toString('hex'),
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

    self.chain.db.getNextHash(entry, function(err, nextHash) {
      if (err)
        return callback(err);

      return callback(null, {
        hash: utils.revHex(entry.hash),
        confirmations: this.chain.height - entry.height + 1,
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
        chainwork: entry.chainwork.toString('hex'),
        previousblockhash: entry.prevBlock !== constants.NULL_HASH
          ? utils.revHex(entry.prevBlock)
          : null,
        nextblockhash: nextHash ? utils.revHex(nextHash) : null
      });
    });
  });
};

RPC.prototype.getchaintips = function getchaintips(args, callback) {
  callback(new Error('Not implemented.'));
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
    verbose = !!args[0];

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
      value: utils.btc(coin.value),
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
    bestblock: utils.revHex(this.chain.tip.hash),
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
        ? attempt.coinbase.outputs[1].script.toRaw().toString('hex')
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
  callback(new Error('Not implemented.'));
};

RPC.prototype.decoderawtransaction = function decoderawtransaction(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.decodescript = function decodescript(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.getrawtransaction = function getrawtransaction(args, callback) {
  if (args.help || args.length < 1 || args.length > 2)
    return callback(new Error('getrawtransaction "txid" ( verbose )'));
  callback(new Error('Not implemented.'));
};

RPC.prototype.sendrawtransaction = function sendrawtransaction(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.signrawtransaction = function signrawtransaction(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.fundrawtransaction = function fundrawtransaction(args, callback) {
  callback(new Error('Not implemented.'));
};

/* Utility functions */
RPC.prototype.createmultisig = function createmultisig(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.createwitnessaddress = function createwitnessaddress(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.validateaddress = function validateaddress(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.verifymessage = function verifymessage(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.estimatefee = function estimatefee(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.estimatepriority = function estimatepriority(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.estimatesmartfee = function estimatesmartfee(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.estimatesmartpriority = function estimatesmartpriority(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.invalidateblock = function invalidateblock(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.reconsiderblock = function reconsiderblock(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.setmocktime = function setmocktime(args, callback) {
  callback(new Error('Not implemented.'));
};

/*
 * Wallet
 */

RPC.prototype.resendwallettransactions = function resendwallettransactions(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.addmultisigaddress = function addmultisigaddress(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.addwitnessaddress = function addwitnessaddress(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.backupwallet = function backupwallet(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.dumpprivkey = function dumpprivkey(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.dumpwallet = function dumpwallet(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.encryptwallet = function encryptwallet(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.getaccountaddress = function getaccountaddress(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.getaccount = function getaccount(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.getaddressesbyaccount = function getaddressesbyaccount(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.getbalance = function getbalance(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.getnewaddress = function getnewaddress(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.getrawchangeaddress = function getrawchangeaddress(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.getreceivedbyaccount = function getreceivedbyaccount(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.getreceivedbyaddress = function getreceivedbyaddress(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.gettransaction = function gettransaction(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.abandontransaction = function abandontransaction(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.getunconfirmedbalance = function getunconfirmedbalance(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.getwalletinfo = function getwalletinfo(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.importprivkey = function importprivkey(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.importwallet = function importwallet(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.importaddress = function importaddress(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.importpubkey = function importpubkey(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.keypoolrefill = function keypoolrefill(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.listaccounts = function listaccounts(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.listaddressgroupings = function listaddressgroupings(args, callback) {
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

RPC.prototype.sendfrom = function sendfrom(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.sendmany = function sendmany(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.sendtoaddress = function sendtoaddress(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.setaccount = function setaccount(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.settxfee = function settxfee(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.signmessage = function signmessage(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.walletlock = function walletlock(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.walletpassphrasechange = function walletpassphrasechange(args, callback) {
  callback(new Error('Not implemented.'));
};

RPC.prototype.walletpassphrase = function walletpassphrase(args, callback) {
  callback(new Error('Not implemented.'));
};

module.exports = RPC;
