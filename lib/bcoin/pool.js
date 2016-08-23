/*!
 * pool.js - peer management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var AsyncObject = require('./async');
var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var IP = require('./ip');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var VerifyError = bcoin.errors.VerifyError;
var NetworkAddress = bcoin.packets.NetworkAddress;
var InvItem = bcoin.packets.InvItem;

/**
 * A pool of peers for handling all network activity.
 * @exports Pool
 * @constructor
 * @param {Object} options
 * @param {Chain} options.chain
 * @param {Mempool?} options.mempool
 * @param {Number?} [options.maxPeers=8] - Maximum number of peers.
 * @param {Boolean?} options.spv - Do an SPV sync.
 * @param {Boolean?} options.relay - Whether to ask
 * for relayed transactions.
 * @param {Boolean?} options.headers - Whether
 * to use `getheaders` for sync.
 * @param {Number?} [options.feeRate] - Fee filter rate.
 * @param {Number?} [options.loadTimeout=120000] - Sync timeout before
 * finding a new loader peer.
 * @param {Number?} [options.loadInterval=20000] - Timeout before attempting to
 * send another getblocks request.
 * @param {Number?} [options.requestTimeout=120000] - Timeout for in-flight
 * blocks.
 * @param {Number?} [options.invTimeout=60000] - Timeout for broadcasted
 * objects.
 * @param {Boolean?} options.listen - Whether to spin up a server socket
 * and listen for peers.
 * @param {Boolean?} options.selfish - A selfish pool. Will not serve blocks,
 * headers, hashes, utxos, or transactions to peers.
 * @param {Boolean?} options.broadcast - Whether to automatically broadcast
 * transactions accepted to our mempool.
 * @param {Boolean?} options.witness - Request witness blocks and transactions.
 * Only deal with witness peers.
 * @param {Boolean} options.ignoreDiscovery - Automatically discover new
 * peers.
 * @param {String[]} options.seeds
 * @param {Function?} options.createSocket - Custom function to create a socket.
 * Must accept (port, host) and return a node-like socket.
 * @param {Function?} options.createServer - Custom function to create a server.
 * Must return a node-like server.
 * @emits Pool#block
 * @emits Pool#block
 * @emits Pool#tx
 * @emits Pool#peer
 * @emits Pool#open
 * @emits Pool#close
 * @emits Pool#error
 * @emits Pool#fork
 * @emits Pool#invalid
 * @emits Pool#exists
 * @emits Pool#orphan
 * @emits Pool#full
 * @emits Pool#blocks
 * @emits Pool#txs
 * @emits Pool#chain-progress
 * @emits Pool#alert
 * @emits Pool#reject
 * @emits Pool#addr
 * @emits Pool#version
 * @emits Pool#ack
 * @emits Pool#watched
 * @emits Pool#leech
 */

function Pool(options) {
  var i, seeds, hostname, seed;

  if (!(this instanceof Pool))
    return new Pool(options);

  AsyncObject.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.chain = options.chain;
  this.logger = options.logger || this.chain.logger;
  this.mempool = options.mempool;

  assert(this.chain, 'Pool requires a blockchain.');

  this.network = this.chain.network;

  if (options.relay == null)
    options.relay = !options.spv;

  if (options.headers == null)
    options.headers = options.spv;

  seeds = options.seeds || this.network.seeds;

  if (options.preferredSeed) {
    seeds = seeds.slice();
    seeds.unshift(options.preferredSeed);
  }

  this.seeds = [];
  this.hosts = [];
  this.hostMap = {};

  for (i = 0; i < seeds.length; i++) {
    hostname = seeds[i];
    seed = NetworkAddress.fromHostname(hostname, this.network);
    this.seeds.push(seed);
  }

  this.services = constants.LOCAL_SERVICES;

  if (!this.options.witness)
    this.services &= ~constants.services.WITNESS;

  this.port = this.options.port != null
    ? this.options.port
    : this.network.port;

  this.address = new NetworkAddress({
    ts: utils.now(),
    services: this.services,
    host: '0.0.0.0',
    port: this.port
  });

  this.server = null;
  this.maxPeers = options.maxPeers || 8;
  this.maxLeeches = options.maxLeeches || 8;
  this.connected = false;
  this.uid = 0;
  this._createServer = options.createServer;
  this.locker = new bcoin.locker(this);
  this.proxyServer = options.proxyServer;
  this.auth = null;
  this.identityKey = null;

  if (this.options.bip150) {
    this.options.bip151 = true;
    this.auth = new bcoin.bip150.AuthDB();

    if (options.authPeers)
      this.auth.setAuthorized(options.authPeers);

    if (options.knownPeers)
      this.auth.setKnown(options.knownPeers);

    this.identityKey = options.identityKey || bcoin.ec.generatePrivateKey();

    assert(Buffer.isBuffer(this.identityKey), 'Identity key must be a buffer.');
    assert(bcoin.ec.privateKeyVerify(this.identityKey),
      'Invalid identity key.');
  }

  this.syncing = false;
  this.synced = false;
  this._scheduled = false;
  this._pendingWatch = null;
  this._timer = null;
  this._interval = null;

  this.load = {
    timeout: options.loadTimeout || 120000,
    interval: options.loadInterval || 20000
  };

  this.requestTimeout = options.requestTimeout || 20 * 60000;

  this.feeRate = options.feeRate != null ? options.feeRate : -1;

  this.spvFilter = options.spv
    ? bcoin.bloom.fromRate(10000, 0.001, constants.bloom.NONE)
    : null;

  this.localNonce = utils.nonce();

  this.peers = {
    // Peers that are loading blocks themselves
    regular: [],
    // Peers that are still connecting
    pending: [],
    // Peers that connected to us
    leeches: [],
    // Peers that are loading block ids
    load: null,
    // All peers
    all: [],
    // Misbehaving hosts
    misbehaving: {},
    // Ignored hosts
    ignored: {},
    // Map of hosts
    map: {}
  };

  this.block = {
    versionHeight: 0,
    bestHash: null,
    type: !options.spv
      ? constants.inv.BLOCK
      : constants.inv.FILTERED_BLOCK
  };

  this.tx = {
    filter: !this.mempool
      ? new bcoin.bloom.rolling(50000, 0.000001)
      : null,
    type: constants.inv.TX
  };

  this.rejects = new bcoin.bloom.rolling(120000, 0.000001);

  if (this.options.witness) {
    this.block.type |= constants.WITNESS_MASK;
    this.tx.type |= constants.WITNESS_MASK;
    if (this.options.compact) {
      this.logger.warning('Disabling compact blocks due to segwit.');
      this.options.compact = false;
    }
  }

  this.request = {
    map: {},
    active: 0,
    activeBlocks: 0,
    activeTX: 0
  };

  // Currently broadcasted objects
  this.inv = {
    items: [],
    map: {},
    timeout: options.invTimeout || 60000,
    interval: options.invInterval || 3000
  };

  this._init();
};

utils.inherits(Pool, AsyncObject);

/**
 * Initialize the pool.
 * @private
 */

Pool.prototype._init = function _init() {
  var self = this;

  if (this.mempool) {
    this.mempool.on('bad orphan', function(tx) {
      self.rejects.add(tx.hash());
    });
  }

  this.chain.on('block', function(block, entry) {
    self.emit('block', block, entry);
  });

  this.chain.on('competitor', function(block, entry) {
    self.emit('competitor', block, entry);
  });

  this.chain.on('fork', function(block, height, expected) {
    self.emit('fork', block, height, expected);
  });

  this.chain.on('invalid', function(block, height) {
    self.emit('invalid', block, height);
  });

  this.chain.on('exists', function(block, height) {
    self.emit('exists', block, height);
  });

  this.chain.on('orphan', function(block, height) {
    self.emit('orphan', block, height);
  });

  this.chain.on('full', function() {
    self._stopTimer();
    self._stopInterval();

    if (!self.synced) {
      // Ask loader for a mempool snapshot.
      if (self.network.requestMempool) {
        if (self.peers.load)
          self.peers.load.sendMempool();
      }

      // Ask all peers for their latest blocks.
      self.sync();
    }

    self.synced = true;
    self.emit('full');

    self.logger.info('Chain is fully synced (height=%d).', self.chain.height);
  });
};

/**
 * Invoke mutex lock.
 * @private
 */

Pool.prototype._lock = function _lock(func, args, force) {
  return this.locker.lock(func, args, force);
};

/**
 * Open the pool, wait for the chain to load.
 * @alias Pool#open
 * @param {Function} callback
 */

Pool.prototype._open = function _open(callback) {
  var self = this;
  this.getIP(function(err, ip) {
    if (err)
      self.logger.error(err);

    if (ip) {
      self.address.host = ip;
      self.logger.info('External IP found: %s.', ip);
    }

    function open(callback) {
      if (self.mempool)
        self.mempool.open(callback);
      else
        self.chain.open(callback);
    }

    open(function(err) {
      if (err)
        return callback(err);

      self.logger.info('Pool loaded (maxpeers=%d).', self.maxPeers);

      if (self.identityKey) {
        self.logger.info('Identity public key: %s',
          bcoin.ec.publicKeyCreate(self.identityKey, true).toString('hex'));
      }

      if (!self.options.listen)
        return callback();

      self.listen(callback);
    });
  });
};

/**
 * Close and destroy the pool.
 * @alias Pool#close
 * @param {Function} callback
 */

Pool.prototype._close = function close(callback) {
  var i, items, peers, hashes, hash;

  this.stopSync();

  items = this.inv.items.slice();

  for (i = 0; i < items.length; i++)
    items[i].finish();

  hashes = Object.keys(this.request.map);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    this.request.map[hash].finish(new Error('Pool closed.'));
  }

  if (this.peers.load)
    this.peers.load.destroy();

  peers = this.peers.regular.slice();

  for (i = 0; i < peers.length; i++)
    peers[i].destroy();

  peers = this.peers.pending.slice();

  for (i = 0; i < peers.length; i++)
    peers[i].destroy();

  peers = this.peers.leeches.slice();

  for (i = 0; i < peers.length; i++)
    peers[i].destroy();

  this.unlisten(callback);
};

/**
 * Connect to the network.
 */

Pool.prototype.connect = function connect() {
  var self = this;
  var i;

  assert(this.loaded, 'Pool is not loaded.');

  if (this.connected)
    return;

  if (!this.options.selfish && !this.options.spv) {
    if (this.mempool) {
      this.mempool.on('tx', function(tx) {
        self.announce(tx);
      });
    }

    // Normally we would also broadcast
    // competing chains, but we want to
    // avoid getting banned if an evil
    // miner sends us an invalid competing
    // chain that we can't connect and
    // verify yet.
    this.chain.on('block', function(block) {
      if (!self.synced)
        return;
      self.announce(block);
    });
  }

  assert(this.seeds.length !== 0, 'No seeds available.');

  this._addLoader();

  for (i = 0; i < this.maxPeers - 1; i++)
    this._addPeer();

  this.connected = true;
};

/**
 * Start listening on a server socket.
 * @param {Function} callback
 */

Pool.prototype.listen = function listen(callback) {
  var self = this;
  var net;

  callback = utils.ensure(callback);

  assert(!this.server, 'Server already listening.');

  if (this._createServer) {
    this.server = this._createServer();
  } else {
    if (utils.isBrowser)
      return utils.nextTick(callback);
    net = require('n' + 'et');
    this.server = new net.Server();
  }

  this.server.on('connection', function(socket) {
    var hostname, host;

    if (!socket.remoteAddress) {
      self.logger.debug('Ignoring disconnected leech.');
      socket.destroy();
      return;
    }

    host = IP.normalize(socket.remoteAddress);

    if (self.peers.leeches.length >= self.maxLeeches) {
      hostname = IP.hostname(host, socket.remotePort);
      self.logger.debug('Ignoring leech: too many leeches (%s).', hostname);
      socket.destroy();
      return;
    }

    if (self.isMisbehaving(host)) {
      hostname = IP.hostname(host, socket.remotePort);
      self.logger.debug('Ignoring misbehaving leech (%s).', hostname);
      socket.destroy();
      return;
    }

    if (self.isIgnored(host)) {
      hostname = IP.hostname(host, socket.remotePort);
      self.logger.debug('Ignoring leech (%s).', hostname);
      socket.destroy();
      return;
    }

    self._addLeech(socket);
  });

  this.server.on('listening', function() {
    var data = self.server.address();
    self.logger.info(
      'Pool server listening on %s (port=%d).',
      data.address, data.port);
  });

  this.server.listen(this.port, '0.0.0.0', callback);
};

/**
 * Stop listening on server socket.
 * @param {Function} callback
 */

Pool.prototype.unlisten = function unlisten(callback) {
  callback = utils.ensure(callback);

  if (utils.isBrowser)
    return utils.nextTick(callback);

  if (!this.server)
    return utils.nextTick(callback);

  this.server.close(callback);
  this.server = null;
};

/**
 * Start timer to detect stalling.
 * @private
 */

Pool.prototype._startTimer = function _startTimer() {
  var self = this;

  this._stopTimer();

  function destroy() {
    if (!self.syncing)
      return;

    // Chain is full and up-to-date
    if (self.chain.isFull())
      return;

    if (self.peers.load) {
      self.peers.load.destroy();
      self.logger.debug('Timer ran out. Finding new loader peer.');
    }
  }

  this._timer = setTimeout(destroy, this.load.timeout);
};

/**
 * Stop the stall timer (done on chain sync).
 * @private
 */

Pool.prototype._stopTimer = function _stopTimer() {
  if (this._timer == null)
    return;

  clearTimeout(this._timer);
  this._timer = null;
};

/**
 * Start the stall interval (shorter than the
 * stall timer, inteded to give warnings and
 * reset the stall *timer* if the chain is
 * busy). Stopped on chain sync.
 * @private
 */

Pool.prototype._startInterval = function _startInterval() {
  var self = this;

  this._stopInterval();

  function load() {
    if (!self.syncing)
      return;

    // Chain is full and up-to-date
    if (self.chain.isFull())
      return;

    if (self.chain.isBusy())
      return self._startTimer();

    self.logger.warning('Stalling.');
  }

  this._interval = setInterval(load, this.load.interval);
};

/**
 * Stop the stall interval.
 * @private
 */

Pool.prototype._stopInterval = function _stopInterval() {
  if (this._interval == null)
    return;

  clearInterval(this._interval);
  this._interval = null;
};

/**
 * Add a loader peer. Necessary for
 * a sync to even begin.
 * @private
 */

Pool.prototype._addLoader = function _addLoader() {
  var self = this;
  var peer;

  if (!this.loaded)
    return;

  if (this.peers.load)
    return;

  peer = this._createPeer({
    host: this.getLoaderHost(),
    type: bcoin.peer.types.LOADER
  });

  this.logger.info('Added loader peer (%s).', peer.hostname);

  this.peers.load = peer;
  this.peers.all.push(peer);
  this.peers.map[peer.host] = peer;

  utils.nextTick(function() {
    self.emit('loader', peer);
  });
};

/**
 * Start the blockchain sync.
 */

Pool.prototype.startSync = function startSync() {
  this.syncing = true;

  this._startInterval();
  this._startTimer();

  this.connect();

  if (!this.peers.load) {
    this._addLoader();
    return;
  }

  this.sync();
};

/**
 * Send a sync to each peer.
 * @private
 */

Pool.prototype.sync = function sync() {
  var i;

  if (this.peers.load)
    this.peers.load.sync();

  for (i = 0; i < this.peers.regular.length; i++)
    this.peers.regular[i].sync();
};

/**
 * Stop the blockchain sync.
 */

Pool.prototype.stopSync = function stopSync() {
  var i;

  if (!this.syncing)
    return;

  this.syncing = false;

  if (!this.loaded)
    return;

  this._stopInterval();
  this._stopTimer();

  if (this.peers.load)
    this.peers.load.syncSent = false;

  for (i = 0; i < this.peers.regular.length; i++)
    this.peers.regular[i].syncSent = false;
};

/**
 * Handle `headers` packet from a given peer.
 * @private
 * @param {Headers[]} headers
 * @param {Peer} peer
 * @param {Function} callback
 */

Pool.prototype._handleHeaders = function _handleHeaders(headers, peer, callback) {
  var self = this;
  var ret = {};
  var last;

  callback = this._lock(_handleHeaders, [headers, peer, callback]);

  if (!callback)
    return;

  if (!this.options.headers)
    return callback();

  this.logger.debug(
    'Received %s headers from peer (%s).',
    headers.length,
    peer.hostname);

  this.emit('headers', headers);

  if (peer === this.peers.load) {
    // Reset interval to avoid stall behavior.
    this._startInterval();
    // Reset timeout to avoid killing the loader.
    this._startTimer();
  }

  utils.forEachSerial(headers, function(header, next) {
    var hash = header.hash('hex');

    if (last && header.prevBlock !== last) {
      // Note: We do _not_ want to add this
      // to known rejects. This block may
      // very well be valid, but this peer
      // is being an asshole right now.
      peer.setMisbehavior(100);
      return next(new Error('Bad header chain.'));
    }

    if (!header.verify(ret)) {
      peer.reject(header, 'invalid', ret.reason, 100);
      self.rejects.add(header.hash());
      return next(new Error('Invalid header.'));
    }

    last = hash;

    self.getData(peer, self.block.type, hash, next);
  }, function(err) {
    if (err)
      return callback(err);

    // Schedule the getdata's we just added.
    self.scheduleRequests(peer);

    // Restart the getheaders process
    // Technically `last` is not indexed yet so
    // the locator hashes will not be entirely
    // accurate. However, it shouldn't matter
    // that much since FindForkInGlobalIndex
    // simply tries to find the latest block in
    // the peer's chain.
    if (last && headers.length === 2000)
      return peer.getHeaders(last, null, callback);

    callback();
  });
};

/**
 * Handle `inv` packet from peer (containing only BLOCK types).
 * @private
 * @param {Hash[]} hashes
 * @param {Peer} peer
 * @param {Function} callback
 */

Pool.prototype._handleBlocks = function _handleBlocks(hashes, peer, callback) {
  var self = this;

  assert(!this.options.headers);

  this.logger.debug(
    'Received %s block hashes from peer (%s).',
    hashes.length,
    peer.hostname);

  this.emit('blocks', hashes);

  if (peer === this.peers.load) {
    // Reset interval to avoid stall behavior.
    this._startInterval();
    // Reset timeout to avoid killing the loader.
    this._startTimer();
  }

  utils.forEachSerial(hashes, function(hash, next, i) {
    // Resolve orphan chain.
    if (self.chain.hasOrphan(hash)) {
      // There is a possible race condition here.
      // The orphan may get resolved by the time
      // we create the locator. In that case, we
      // should probably actually move to the
      // `exists` clause below if it is the last
      // hash.
      self.logger.debug('Received known orphan hash (%s).', peer.hostname);
      return peer.resolveOrphan(null, hash, next);
    }

    self.getData(peer, self.block.type, hash, function(err, exists) {
      if (err)
        return next(err);

      // Normally we request the hashContinue.
      // In the odd case where we already have
      // it, we can do one of two things: either
      // force re-downloading of the block to
      // continue the sync, or do a getblocks
      // from the last hash (this will reset
      // the hashContinue on the remote node).
      if (exists && i === hashes.length - 1) {
        // Make sure we _actually_ have this block.
        if (!self.request.map[hash]) {
          self.logger.debug('Received existing hash (%s).', peer.hostname);
          return peer.getBlocks(hash, null, next);
        }
        // Otherwise, we're still requesting it. Ignore.
        self.logger.debug('Received requested hash (%s).', peer.hostname);
      }

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    self.scheduleRequests(peer);

    callback();
  });
};

/**
 * Handle `inv` packet from peer (containing only BLOCK types).
 * Potentially request headers if headers mode is enabled.
 * @private
 * @param {Hash[]} hashes
 * @param {Peer} peer
 * @param {Function} callback
 */

Pool.prototype._handleInv = function _handleInv(hashes, peer, callback) {
  var self = this;

  callback = this._lock(_handleInv, [hashes, peer, callback]);

  if (!callback)
    return;

  // Ignore for now if we're still syncing
  if (!this.synced && peer !== this.peers.load)
    return callback();

  if (!this.options.headers)
    return this._handleBlocks(hashes, peer, callback);

  utils.forEachSerial(hashes, function(hash, next) {
    peer.getHeaders(null, hash, next);
  }, function(err) {
    if (err)
      return callback(err);

    self.scheduleRequests(peer);

    callback();
  });
};

/**
 * Handle `block` packet. Attempt to add to chain.
 * @private
 * @param {MemBlock|MerkleBlock} block
 * @param {Peer} peer
 * @param {Function} callback
 */

Pool.prototype._handleBlock = function _handleBlock(block, peer, callback) {
  var self = this;
  var requested;

  // Fulfill the load request.
  requested = this.fulfill(block);

  // Someone is sending us blocks without
  // us requesting them.
  if (!requested) {
    peer.invFilter.add(block.hash());
    this.logger.warning(
      'Received unrequested block: %s (%s).',
      block.rhash, peer.hostname);
    return utils.nextTick(callback);
  }

  this.chain.add(block, function(err) {
    if (err) {
      if (err.type !== 'VerifyError') {
        self.scheduleRequests(peer);
        return callback(err);
      }

      if (err.score !== -1)
        peer.reject(block, err.code, err.reason, err.score);

      if (err.reason === 'bad-prevblk') {
        if (self.options.headers) {
          peer.setMisbehavior(10);
          return callback(err);
        }
        self.logger.debug('Peer sent an orphan block. Resolving.');
        return peer.resolveOrphan(null, block.hash('hex'), function(e) {
          self.scheduleRequests(peer);
          return callback(e || err);
        });
      }

      self.rejects.add(block.hash());
      self.scheduleRequests(peer);
      return callback(err);
    }

    self.scheduleRequests(peer);

    self.emit('chain-progress', self.chain.getProgress(), peer);

    if (self.logger.level >= 4 && self.chain.total % 20 === 0) {
      self.logger.debug('Status:'
        + ' ts=%s height=%d highest=%d progress=%s'
        + ' blocks=%d orphans=%d active=%d'
        + ' queue=%d target=%s peers=%d'
        + ' pending=%d jobs=%d',
        utils.date(block.ts),
        self.chain.height,
        self.chain.bestHeight,
        (self.chain.getProgress() * 100).toFixed(2) + '%',
        self.chain.total,
        self.chain.orphan.count,
        self.request.activeBlocks,
        peer.queue.block.length,
        block.bits,
        self.peers.all.length,
        self.chain.locker.pending.length,
        self.chain.locker.jobs.length);
    }

    if (self.chain.total % 2000 === 0) {
      self.logger.info(
        'Received 2000 more blocks (height=%d, hash=%s).',
        self.chain.height,
        block.rhash);
    }

    callback();
  });
};

/**
 * Send `mempool` to all peers.
 */

Pool.prototype.sendMempool = function sendMempool() {
  var i;

  if (this.peers.load)
    this.peers.load.sendMempool();

  for (i = 0; i < this.peers.regular.length; i++)
    this.peers.regular[i].sendMempool();
};

/**
 * Send `alert` to all peers.
 * @param {AlertPacket} alert
 */

Pool.prototype.sendAlert = function sendAlert(alert) {
  var i;

  if (this.peers.load)
    this.peers.load.sendAlert(alert);

  for (i = 0; i < this.peers.regular.length; i++)
    this.peers.regular[i].sendAlert(alert);

  for (i = 0; i < this.peers.leeches.length; i++)
    this.peers.leeches[i].sendAlert(alert);
};

/**
 * Create a base peer with no special purpose.
 * @private
 * @param {Object} options
 * @returns {Peer}
 */

Pool.prototype._createPeer = function _createPeer(options) {
  var self = this;
  var peer = new bcoin.peer(this, options);

  peer.once('close', function() {
    self._removePeer(peer);

    if (!self.loaded)
      return;

    if (peer.type !== bcoin.peer.types.LOADER)
      return;

    self._stopInterval();
    self._stopTimer();

    if (self.peers.regular.length === 0) {
      self.logger.warning('%s %s %s',
        'Could not connect to any peers.',
        'Do you have a network connection?',
        'Retrying in 5 seconds.');
      setTimeout(function() {
        self._addLoader();
      }, 5000);
      return;
    }

    self._addLoader();
  });

  peer.on('merkleblock', function(block) {
    if (!self.options.spv)
      return;

    if (!self.syncing)
      return;

    // If the peer sent us a block that was added
    // to the chain (not orphans), reset the timeout.
    self._handleBlock(block, peer, function(err) {
      if (err)
        return self.emit('error', err);

      if (peer.type === bcoin.peer.types.LOADER) {
        self._startInterval();
        self._startTimer();
      }
    });
  });

  peer.on('block', function(block) {
    if (self.options.spv)
      return;

    if (!self.syncing)
      return;

    // If the peer sent us a block that was added
    // to the chain (not orphans), reset the timeout.
    self._handleBlock(block, peer, function(err) {
      if (err)
        return self.emit('error', err);

      if (peer.type === bcoin.peer.types.LOADER) {
        self._startInterval();
        self._startTimer();
      }
    });
  });

  peer.on('error', function(err) {
    self.emit('error', err, peer);
  });

  peer.on('reject', function(payload) {
    var data = payload.data
      ? utils.revHex(payload.data)
      : null;

    self.logger.warning(
      'Received reject (%s): msg=%s code=%s reason=%s data=%s.',
      peer.hostname,
      payload.message,
      constants.rejectByVal[payload.code] || payload.code,
      payload.reason,
      data);

    self.emit('reject', payload, peer);
  });

  peer.on('alert', function(alert) {
    self._handleAlert(alert, peer);
  });

  peer.on('notfound', function(items) {
    var i, item, req;

    for (i = 0; i < items.length; i++) {
      item = items[i];
      req = self.request.map[item.hash];
      if (req && req.peer === peer)
        req.finish(new Error('Not found.'));
    }
  });

  peer.on('tx', function(tx) {
    self._handleTX(tx, peer, function(err) {
      if (err)
        self.emit('error', err);
    });
  });

  peer.on('addr', function(hosts) {
    var i, host;

    if (self.options.ignoreDiscovery)
      return;

    for (i = 0; i < hosts.length; i++) {
      host = hosts[i];

      if (!host.hasNetwork())
        continue;

      if (self.options.spv) {
        if (!host.hasBloom())
          continue;
      }

      if (self.options.witness) {
        if (!host.hasWitness())
          continue;
      }

      if (self.addHost(host))
        self.emit('host', host, peer);
    }

    self.emit('addr', hosts, peer);
  });

  peer.on('txs', function(txs) {
    var i, hash;

    self.emit('txs', txs, peer);

    if (self.syncing && !self.synced)
      return;

    for (i = 0; i < txs.length; i++) {
      hash = txs[i];
      self.getData(peer, self.tx.type, hash);
    }
  });

  peer.on('version', function(version) {
    if (version.height > self.block.versionHeight)
      self.block.versionHeight = version.height;

    self.logger.info(
      'Received version (%s): version=%d height=%d services=%s agent=%s',
      peer.hostname,
      version.version,
      version.height,
      version.services.toString(2),
      version.agent);

    bcoin.time.add(peer.host, version.ts);

    self.emit('version', version, peer);
  });

  peer.on('headers', function(headers) {
    if (!self.syncing)
      return;

    self._handleHeaders(headers, peer, function(err) {
      if (err)
        self.emit('error', err);
    });
  });

  peer.on('blocks', function(hashes) {
    if (!self.syncing)
      return;

    self._handleInv(hashes, peer, function(err) {
      if (err)
        self.emit('error', err);
    });
  });

  return peer;
};

/**
 * Handle an alert packet.
 * @private
 * @param {AlertPacket} alert
 * @param {Peer} peer
 */

Pool.prototype._handleAlert = function _handleAlert(alert, peer) {
  var now = bcoin.now();

  if (!this.rejects.added(alert.hash()))
    return;

  if (!alert.verify(this.network.alertKey)) {
    this.logger.warning('Peer sent a phony alert packet (%s).', peer.hostname);
    // Let's look at it because why not?
    this.logger.debug(alert);
    peer.setMisbehavior(100);
    return;
  }

  if (now >= alert.relayUntil || now >= alert.expiration) {
    this.logger.warning('Peer sent an expired alert packet (%s).', peer.hostname);
    this.logger.debug(alert);
    return;
  }

  this.logger.warning('Received alert from peer (%s).', peer.hostname);
  this.logger.warning(alert);

  this.sendAlert(alert);

  this.emit('alert', alert, peer);
};

/**
 * Handle a transaction. Attempt to add to mempool.
 * @private
 * @param {TX} tx
 * @param {Peer} peer
 * @param {Function} callback
 */

Pool.prototype._handleTX = function _handleTX(tx, peer, callback) {
  var self = this;
  var requested;

  callback = utils.ensure(callback);

  // Fulfill the load request.
  requested = this.fulfill(tx);

  if (!requested) {
    peer.invFilter.add(tx.hash());

    if (!this.mempool)
      this.tx.filter.add(tx.hash());

    this.logger.warning('Peer sent unrequested tx: %s (%s).',
      tx.rhash, peer.hostname);

    if (this.rejects.test(tx.hash())) {
      return callback(new VerifyError(tx,
        'alreadyknown',
        'txn-already-known',
        0));
    }
  }

  if (!this.mempool) {
    this.emit('tx', tx, peer);
    return callback();
  }

  this.mempool.addTX(tx, function(err) {
    if (err) {
      if (err.type === 'VerifyError') {
        if (err.score !== -1)
          peer.reject(tx, err.code, err.reason, err.score);
        self.rejects.add(tx.hash());
        return callback(err);
      }
      return callback(err);
    }

    self.emit('tx', tx, peer);

    callback();
  });
};

/**
 * Create a leech peer from an existing socket.
 * @private
 * @param {net.Socket} socket
 */

Pool.prototype._addLeech = function _addLeech(socket) {
  var self = this;
  var peer;

  if (!this.loaded)
    return socket.destroy();

  peer = this._createPeer({
    socket: socket,
    type: bcoin.peer.types.LEECH
  });

  this.logger.info('Added leech peer (%s).', peer.hostname);

  this.peers.leeches.push(peer);
  this.peers.all.push(peer);
  this.peers.map[peer.host] = peer;

  utils.nextTick(function() {
    self.emit('leech', peer);
  });
};

/**
 * Create a regular non-loader peer. These primarily
 * exist for transaction relaying.
 * @private
 */

Pool.prototype._addPeer = function _addPeer() {
  var self = this;
  var peer, host;

  if (!this.loaded)
    return;

  if (this.peers.regular.length + this.peers.pending.length >= this.maxPeers - 1)
    return;

  host = this.getHost();

  if (!host) {
    setTimeout(this._addPeer.bind(this), 5000);
    return;
  }

  peer = this._createPeer({
    host: host,
    type: bcoin.peer.types.REGULAR
  });

  this.peers.pending.push(peer);
  this.peers.all.push(peer);
  this.peers.map[peer.host] = peer;

  peer.once('ack', function() {
    if (utils.binaryRemove(self.peers.pending, peer, compare))
      utils.binaryInsert(self.peers.regular, peer, compare);
  });

  peer.once('close', function() {
    self._addPeer();
  });

  utils.nextTick(function() {
    self.emit('peer', peer);
  });
};

/**
 * Remove a peer from any list. Drop all load requests.
 * @private
 * @param {Peer} peer
 */

Pool.prototype._removePeer = function _removePeer(peer) {
  var i, hashes, hash, item;

  utils.binaryRemove(this.peers.pending, peer, compare);
  utils.binaryRemove(this.peers.regular, peer, compare);
  utils.binaryRemove(this.peers.leeches, peer, compare);
  utils.binaryRemove(this.peers.all, peer, compare);

  delete this.peers.map[peer.host];

  if (this.peers.load === peer) {
    this.logger.info('Removed loader peer (%s).', peer.hostname);
    this.peers.load = null;
  }

  hashes = Object.keys(this.request.map);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    item = this.request.map[hash];
    if (item.peer === peer)
      item.finish(new Error('Peer closed.'));
  }
};

/**
 * Watch a an address hash (filterload, SPV-only).
 * @param {Buffer|Hash} data
 * @param {String?} enc
 */

Pool.prototype.watch = function watch(data, enc) {
  if (!this.options.spv)
    return;
  this.spvFilter.add(data, enc);
  this.updateWatch();
};

/**
 * Reset the spv filter (filterload, SPV-only).
 */

Pool.prototype.unwatch = function unwatch() {
  if (!this.options.spv)
    return;
  this.spvFilter.reset();
  this.updateWatch();
};

/**
 * Resend the bloom filter to peers.
 */

Pool.prototype.updateWatch = function updateWatch() {
  var self = this;
  var i;

  if (this._pendingWatch != null)
    return;

  this._pendingWatch = setTimeout(function() {
    self._pendingWatch = null;

    if (self.peers.load)
      self.peers.load.updateWatch();

    for (i = 0; i < self.peers.regular.length; i++)
      self.peers.regular[i].updateWatch();
  }, 50);
};

/**
 * Add an address to the bloom filter (SPV-only).
 * @param {Address|Base58Address} address
 */

Pool.prototype.watchAddress = function watchAddress(address) {
  this.watch(bcoin.address.getHash(address));
};

/**
 * Queue a `getdata` request to be sent. Checks existence
 * in the chain before requesting.
 * @param {Peer} peer
 * @param {Number} type - `getdata` type (see {@link constants.inv}).
 * @param {Hash} hash - {@link Block} or {@link TX} hash.
 * @param {Object?} options
 * @param {Function} callback
 */

Pool.prototype.getData = function getData(peer, type, hash, options, callback) {
  var self = this;
  var item;

  if (typeof options === 'function') {
    callback = options;
    options = null;
  }

  callback = utils.ensure(callback);

  if (!this.loaded)
    return callback();

  if (options == null)
    options = {};

  if (typeof options === 'boolean')
    options = { force: options };

  this.has(type, hash, options.force, function(err, exists) {
    if (err)
      return callback(err);

    if (exists)
      return callback(null, true);

    item = new LoadRequest(self, peer, type, hash);

    if (options.noQueue)
      return callback(null, false);

    if (type === self.tx.type) {
      if (peer.queue.tx.length === 0) {
        utils.nextTick(function() {
          self.logger.debug(
            'Requesting %d/%d txs from peer with getdata (%s).',
            peer.queue.tx.length,
            self.request.activeTX,
            peer.hostname);

          peer.getData(peer.queue.tx);
          peer.queue.tx.length = 0;
        });
      }

      peer.queue.tx.push(item.start());

      return callback(null, false);
    }

    peer.queue.block.push(item);

    callback(null, false);
  });
};

/**
 * Test whether the pool has or has seen an item.
 * @param {InvType} type
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

Pool.prototype.has = function has(type, hash, force, callback) {
  var self = this;

  if (!callback) {
    callback = force;
    force = false;
  }

  function check(err, exists) {
    if (err)
      return callback(err);

    if (exists)
      return callback(null, true);

    // Check the pending requests.
    if (self.request.map[hash])
      return callback(null, true);

    // We need to reset the rejects filter periodically.
    // There may be a locktime in a TX that is now valid.
    if (self.rejects.tip !== self.chain.tip.hash) {
      self.rejects.tip = self.chain.tip.hash;
      self.rejects.reset();
    } else {
      // If we recently rejected this item. Ignore.
      if (self.rejects.test(hash, 'hex')) {
        self.logger.spam('Peer sent a known reject: %s.', utils.revHex(hash));
        return callback(null, true);
      }
    }

    return callback(null, false);
  }

  if (force) {
    check = utils.asyncify(check);
    return check(null, false);
  }

  if (type === this.tx.type) {
    // Check the TX filter if
    // we don't have a mempool.
    if (!this.mempool) {
      check = utils.asyncify(check);
      if (this.tx.filter.added(hash, 'hex'))
        return check(null, false);
      return check(null, true);
    }

    // Check the mempool.
    return check(null, this.mempool.has(hash));
  }

  // Check the chain.
  return this.chain.has(hash, check);
};

/**
 * Schedule next batch of `getdata` requests for peer.
 * @param {Peer} peer
 */

Pool.prototype.scheduleRequests = function scheduleRequests(peer) {
  var self = this;

  if (this._scheduled)
    return;

  this._scheduled = true;

  this.chain.onDrain(function() {
    utils.nextTick(function() {
      self._sendRequests(peer);
      self._scheduled = false;
    });
  });
};

/**
 * Send scheduled requests in the request queues.
 * @private
 * @param {Peer} peer
 */

Pool.prototype._sendRequests = function _sendRequests(peer) {
  var i, size, items;

  if (this.chain.isBusy())
    return;

  if (peer.queue.block.length === 0)
    return;

  if (this.options.spv) {
    if (this.request.activeBlocks >= 500)
      return;
    items = peer.queue.block.slice();
    peer.queue.block.length = 0;
  } else {
    size = this.network.getBatchSize(this.chain.height);

    if (this.request.activeBlocks >= size)
      return;

    items = peer.queue.block.slice(0, size);
    peer.queue.block = peer.queue.block.slice(size);
  }

  for (i = 0; i < items.length; i++)
    items[i] = items[i].start();

  this.logger.debug(
    'Requesting %d/%d blocks from peer with getdata (%s).',
    items.length,
    this.request.activeBlocks,
    peer.hostname);

  peer.getData(items);
};

/**
 * Fulfill a requested block.
 * @param {Hash}
 * @returns {LoadRequest|null}
 */

Pool.prototype.fulfill = function fulfill(hash) {
  var item;

  if (hash.hash)
    hash = hash.hash('hex');

  item = this.request.map[hash];
  if (!item)
    return false;

  item.finish();

  return item;
};

/**
 * Broadcast a transaction or block.
 * @param {TX|Block|InvItem} msg
 * @param {Function} callback - Returns [Error]. Executes on request, reject,
 * or timeout.
 * @returns {BroadcastItem}
 */

Pool.prototype.broadcast = function broadcast(msg, callback) {
  var hash = msg.hash;
  var item;

  if (msg.toInv)
    hash = msg.toInv().hash;

  item = this.inv.map[hash];

  if (item) {
    item.refresh();
    item.announce();
    item.addCallback(callback);
    return item;
  }

  item = new BroadcastItem(this, msg, callback);

  item.start();
  item.announce();

  return item;
};

/**
 * Announce an item by sending an inv to all
 * peers. This does not add it to the broadcast
 * queue.
 * @param {TX|Block} tx
 */

Pool.prototype.announce = function announce(msg) {
  var i;

  if (this.peers.load)
    this.peers.load.announce(msg);

  for (i = 0; i < this.peers.regular.length; i++)
    this.peers.regular[i].announce(msg);
};

/**
 * Set a fee rate filter for all peers.
 * @param {Rate} rate
 */

Pool.prototype.setFeeRate = function setFeeRate(rate) {
  var i;

  this.feeRate = rate;

  if (this.peers.load)
    this.peers.load.sendFeeRate(rate);

  for (i = 0; i < this.peers.regular.length; i++)
    this.peers.regular[i].sendFeeRate(rate);
};

/**
 * Get peer by host.
 * @param {String} addr
 * @returns {Peer?}
 */

Pool.prototype.getPeer = function getPeer(host) {
  return this.peers.map[host];
};

/**
 * Request UTXOs from peer.
 * @param {Outpoint[]} outpoints
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Pool.prototype.getUTXOs = function getUTXOs(outpoints, callback) {
  var i, peer;

  for (i = 0; i < this.peers.all.length; i++) {
    peer = this.peers.all[i];

    if (!peer.version)
      continue;

    if (peer.version.services & constants.services.GETUXO)
      break;
  }

  if (i === this.peers.regular.length)
    return utils.asyncify(callback)(new Error('No peer available.'));

  peer.getUTXOs(outpoints, callback);
};

/**
 * Attempt to fill transaction using getutxos (note: unreliable).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Pool.prototype.fillCoins = function fillCoins(tx, callback) {
  var outpoints = [];
  var i, input;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (!input.coin)
      outpoints.push(input.prevout);
  }

  if (outpoints.length === 0)
    return utils.asyncify(callback)(null, tx);

  this.getUTXOs(outpoints, function(err, coins) {
    if (err)
      return callback(err);

    tx.fillCoins(coins);

    callback(null, tx);
  });
};

/**
 * Allocate a new loader host.
 * @returns {NetworkAddress}
 */

Pool.prototype.getLoaderHost = function getLoaderHost() {
  var host;

  if (!this.connected && this.options.preferredSeed)
    return this.seeds[0];

  host = this.getRandom(this.seeds);

  if (host)
    return host;

  host = this.getRandom(this.hosts);

  if (host)
    return host;

  this.logger.warning('All seeds banned or ignored. Clearing...');
  this.peers.ignored = {};
  this.peers.misbehaving = {};

  return this.getRandom(this.seeds);
};

/**
 * Allocate a new host which is not currently being used.
 * @returns {NetworkAddress}
 */

Pool.prototype.getHost = function getHost() {
  var host;

  // Hang back if we don't have a loader peer yet.
  if (!this.peers.load)
    return;

  host = this.getRandom(this.seeds, true);

  if (host)
    return host;

  return this.getRandom(this.hosts, true);
};

/**
 * Get a random host from collection of hosts.
 * @param {NetworkAddress[]} hosts
 * @param {Boolean} unique
 * @returns {NetworkAddress}
 */

Pool.prototype.getRandom = function getRandom(hosts, unique) {
  var index = Math.random() * hosts.length | 0;
  var last = -1;
  var i, host;

  for (i = 0; i < hosts.length; i++) {
    host = hosts[i];

    if (this.isMisbehaving(host.host))
      continue;

    if (this.isIgnored(host.host))
      continue;

    if (unique && this.getPeer(host.host))
      continue;

    if (i >= index)
      return host;

    last = i;
  }

  if (last === -1)
    return;

  return hosts[last];
};

/**
 * Add host to host list.
 * @param {String|NetworkAddress} host
 * @returns {Boolean}
 */

Pool.prototype.addHost = function addHost(host) {
  if (typeof host === 'string')
    host = NetworkAddress.fromHostname(host, this.network);

  if (this.hosts.length > 500)
    return;

  if (this.hostMap[host.host])
    return;

  utils.binaryInsert(this.hosts, host, compare);

  this.hostMap[host.host] = host;

  return host;
};

/**
 * Remove host from host list.
 * @param {String|NetworkAddress} host
 * @returns {Boolean}
 */

Pool.prototype.removeHost = function removeHost(host) {
  if (host.host)
    host = host.host;

  host = this.hostMap[host];

  if (!host)
    return;

  utils.binaryRemove(this.hosts, host, compare);

  delete this.hostMap[host];

  return host;
};

/**
 * Increase peer's ban score.
 * @param {Peer} peer
 * @param {Number} score
 * @returns {Boolean} Whether the peer was banned.
 */

Pool.prototype.setMisbehavior = function setMisbehavior(peer, score) {
  peer.banScore += score;

  if (peer.banScore >= constants.BAN_SCORE) {
    this.peers.misbehaving[peer.host] = utils.now();
    this.removeHost(peer.host);
    this.logger.debug('Ban threshold exceeded (%s).', peer.host);
    peer.destroy();
    return true;
  }

  return false;
};

/**
 * Test whether the host/peer is banned.
 * @param {String} host
 * @returns {Boolean}
 */

Pool.prototype.isMisbehaving = function isMisbehaving(host) {
  var peer, time;

  if (host.host)
    host = host.host;

  time = this.peers.misbehaving[host];

  if (time != null) {
    if (utils.now() > time + constants.BAN_TIME) {
      delete this.peers.misbehaving[host];
      peer = this.getPeer(host);
      if (peer)
        peer.banScore = 0;
      return false;
    }
    return true;
  }

  return false;
};

/**
 * Ignore peer.
 * @param {Peer} peer
 */

Pool.prototype.ignore = function ignore(peer) {
  this.logger.debug('Ignoring peer (%s).', peer.hostname);
  if (!this.removeHost(peer.host))
    this.peers.ignored[peer.host] = true;
  peer.destroy();
};

/**
 * Test whether the host/peer is ignored.
 * @param {String} host
 * @returns {Boolean}
 */

Pool.prototype.isIgnored = function isIgnored(host) {
  if (host.host)
    host = host.host;

  return this.peers.ignored[host] === true;
};

/**
 * Attempt to retrieve external IP from icanhazip.com.
 * @param {Function} callback
 */

Pool.prototype.getIP = function getIP(callback) {
  var self = this;
  var request = require('./http/request');
  var ip;

  if (utils.isBrowser)
    return callback(new Error('Could not find IP.'));

  request({
    method: 'GET',
    uri: 'http://icanhazip.com',
    expect: 'text',
    timeout: 3000
  }, function(err, res, body) {
    if (err)
      return self.getIP2(callback);

    ip = body.trim();

    if (IP.version(ip) === -1)
      return self.getIP2(callback);

    callback(null, IP.normalize(ip));
  });
};

/**
 * Attempt to retrieve external IP from dyndns.org.
 * @param {Function} callback
 */

Pool.prototype.getIP2 = function getIP2(callback) {
  var request = require('./http/request');
  var ip;

  if (utils.isBrowser)
    return callback(new Error('Could not find IP.'));

  request({
    method: 'GET',
    uri: 'http://checkip.dyndns.org',
    expect: 'html',
    timeout: 3000
  }, function(err, res, body) {
    if (err)
      return callback(err);

    ip = /IP Address:\s*([0-9a-f.:]+)/i.exec(body);

    if (!ip || IP.version(ip[1]) === -1)
      return callback(new Error('Could not find IP.'));

    callback(null, IP.normalize(ip[1]));
  });
};

/**
 * Represents an in-flight block or transaction.
 * @exports LoadRequest
 * @constructor
 * @private
 * @param {Pool} pool
 * @param {Peer} peer
 * @param {Number} type - `getdata` type (see {@link constants.inv}).
 * @param {Hash} hash
 * @param {Function} callback
 */

function LoadRequest(pool, peer, type, hash, callback) {
  if (!(this instanceof LoadRequest))
    return new LoadRequest(pool, peer, type, hash, callback);

  this.pool = pool;
  this.peer = peer;
  this.type = type;
  this.hash = hash;
  this.callback = [];
  this.active = false;
  this.id = this.pool.uid++;
  this.timeout = null;
  this.onTimeout = this._onTimeout.bind(this);

  this.addCallback(callback);

  assert(!this.pool.request.map[this.hash]);
  this.pool.request.map[this.hash] = this;
}

/**
 * Destroy load request with an error.
 */

LoadRequest.prototype.destroy = function destroy() {
  return this.finish(new Error('Destroyed.'));
};

/**
 * Handle timeout. Potentially kill loader.
 * @private
 */

LoadRequest.prototype._onTimeout = function _onTimeout() {
  if (this.type !== this.pool.tx.type
      && this.peer === this.pool.peers.load) {
    this.pool.logger.debug(
      'Loader took too long serving a block. Finding a new one.');
    this.peer.destroy();
  }
  return this.finish(new Error('Timed out.'));
};

/**
 * Add a callback to be executed when item is received.
 * @param {Function} callback
 */

LoadRequest.prototype.addCallback = function addCallback(callback) {
  if (callback)
    this.callback.push(callback);
};

/**
 * Mark the request as in-flight. Start timeout timer.
 */

LoadRequest.prototype.start = function start() {
  this.timeout = setTimeout(this.onTimeout, this.pool.requestTimeout);

  this.active = true;
  this.pool.request.active++;

  if (this.type === this.pool.tx.type)
    this.pool.request.activeTX++;
  else
    this.pool.request.activeBlocks++;

  return this;
};

/**
 * Mark the request as completed.
 * Remove from queue and map. Clear timeout.
 * @param {Error?} err
 */

LoadRequest.prototype.finish = function finish(err) {
  var i;

  if (this.pool.request.map[this.hash]) {
    delete this.pool.request.map[this.hash];
    if (this.active) {
      this.active = false;
      this.pool.request.active--;
      if (this.type === this.pool.tx.type)
        this.pool.request.activeTX--;
      else
        this.pool.request.activeBlocks--;
    }
  }

  if (this.type === this.pool.tx.type)
    utils.binaryRemove(this.peer.queue.tx, this, compare);
  else
    utils.binaryRemove(this.peer.queue.block, this, compare);

  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }

  for (i = 0; i < this.callback.length; i++)
    this.callback[i](err);
};

/**
 * Inspect the load request.
 * @returns {String}
 */

LoadRequest.prototype.inspect = function inspect() {
  return '<LoadRequest:'
    + ' id=' + this.id
    + ' type=' + (this.type === this.pool.tx.type ? 'tx' : 'block')
    + ' active=' + this.active
    + ' hash=' + utils.revHex(this.hash)
    + '>';
};

/**
 * Convert load request to an inv item.
 * @returns {InvItem}
 */

LoadRequest.prototype.toInv = function toInv() {
  return new InvItem(this.type, this.hash);
};

/**
 * Represents an item that is broadcasted via an inv/getdata cycle.
 * @exports BroadcastItem
 * @constructor
 * @private
 * @param {Pool} pool
 * @param {TX|Block|InvItem} item
 * @param {Function?} callback
 * @emits BroadcastItem#ack
 * @emits BroadcastItem#reject
 * @emits BroadcastItem#timeout
 */

function BroadcastItem(pool, item, callback) {
  if (!(this instanceof BroadcastItem))
    return new BroadcastItem(pool, item);

  this.pool = pool;
  this.callback = [];

  this.id = this.pool.uid++;
  this.msg = null;

  if (item instanceof bcoin.tx)
    assert(!item.mutable, 'Cannot broadcast mutable TX.');

  if (item.toInv) {
    this.msg = item;
    item = item.toInv();
  }

  this.hash = item.hash;
  this.type = item.type;

  if (typeof this.type === 'string')
    this.type = constants.inv[this.type.toUpperCase()];

  assert(this.type != null);
  assert(typeof this.hash === 'string');

  // INV does not set the witness
  // mask (only GETDATA does this).
  assert((this.type & constants.WITNESS_MASK) === 0);

  this.addCallback(callback);
}

utils.inherits(BroadcastItem, EventEmitter);

/**
 * Add a callback to be executed on ack, timeout, or reject.
 * @param {Function} callback
 */

BroadcastItem.prototype.addCallback = function addCallback(callback) {
  if (callback)
    this.callback.push(callback);
};

/**
 * Start the broadcast.
 */

BroadcastItem.prototype.start = function start() {
  assert(!this.timeout, 'Already started.');
  assert(!this.pool.inv.map[this.hash], 'Already started.');

  this.pool.inv.map[this.hash] = this;
  utils.binaryInsert(this.pool.inv.items, this, compare);

  this.refresh();

  return this;
};

/**
 * Refresh the timeout on the broadcast.
 */

BroadcastItem.prototype.refresh = function refresh() {
  var self = this;

  if (this.timeout) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }

  this.timeout = setTimeout(function() {
    self.emit('timeout');
    self.finish(new Error('Timed out.'));
  }, this.pool.inv.timeout);
};

/**
 * Announce the item.
 */

BroadcastItem.prototype.announce = function announce() {
  this.pool.announce(this);
};

/**
 * Finish the broadcast, potentially with an error.
 * @param {Error?} err
 */

BroadcastItem.prototype.finish = function finish(err) {
  var i;

  assert(this.timeout, 'Already finished.');
  assert(this.pool.inv.map[this.hash], 'Already finished.');

  clearTimeout(this.timeout);
  this.timeout = null;

  delete this.pool.inv.map[this.hash];
  utils.binaryRemove(this.pool.inv.items, this, compare);

  for (i = 0; i < this.callback.length; i++)
    this.callback[i](err);

  this.callback.length = 0;
};

/**
 * Handle an ack from a peer.
 * @param {Peer} peer
 */

BroadcastItem.prototype.ack = function ack(peer) {
  var self = this;
  var i;

  setTimeout(function() {
    self.emit('ack', peer);

    for (i = 0; i < self.callback.length; i++)
      self.callback[i]();

    self.callback.length = 0;
  }, 1000);
};

/**
 * Handle a reject from a peer.
 * @param {Peer} peer
 */

BroadcastItem.prototype.reject = function reject(peer) {
  var i, err;

  this.emit('reject', peer);

  err = new Error('Rejected by ' + peer.hostname);

  for (i = 0; i < this.callback.length; i++)
    this.callback[i](err);

  this.callback.length = 0;
};

/**
 * Inspect the broadcast item.
 * @returns {String}
 */

BroadcastItem.prototype.inspect = function inspect() {
  return '<BroadcastItem:'
    + ' id=' + this.id
    + ' type=' + (this.type === constants.inv.TX ? 'tx' : 'block')
    + ' hash=' + utils.revHex(this.hash)
    + '>';
};

/**
 * Convert broadcast item to an inv item.
 * @returns {InvItem}
 */

BroadcastItem.prototype.toInv = function toInv() {
  return new InvItem(this.type, this.hash);
};

/*
 * Helpers
 */

function compare(a, b) {
  return a.id - b.id;
}

/*
 * Expose
 */

module.exports = Pool;
