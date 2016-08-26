/*!
 * pool.js - peer management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var AsyncObject = require('../utils/async');
var EventEmitter = require('events').EventEmitter;
var utils = require('../utils/utils');
var IP = require('../utils/ip');
var assert = utils.assert;
var constants = bcoin.constants;
var VerifyError = bcoin.errors.VerifyError;
var NetworkAddress = bcoin.packets.NetworkAddress;
var InvItem = bcoin.invitem;

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
  if (!(this instanceof Pool))
    return new Pool(options);

  AsyncObject.call(this);

  assert(options && options.chain, 'Pool requires a blockchain.');

  this.options = options;
  this.chain = options.chain;
  this.logger = options.logger || this.chain.logger;
  this.mempool = options.mempool;
  this.network = this.chain.network;

  this.services = constants.LOCAL_SERVICES;
  this.port = this.network.port;

  this.server = null;
  this.maxPeers = 8;
  this.maxLeeches = 8;
  this.connected = false;
  this.uid = 0;
  this.createServer = null;
  this.locker = new bcoin.locker(this);
  this.proxyServer = null;
  this.auth = null;
  this.identityKey = null;

  this.syncing = false;
  this.synced = false;

  this.loadTimeout = 120000;

  this.feeRate = -1;

  this.address = new NetworkAddress();

  this.peers = new PeerList(this);
  this.hosts = new HostList(this);

  this.blockType = constants.inv.BLOCK;
  this.txType = constants.inv.TX;

  this.localNonce = utils.nonce();

  this.spvFilter = null;
  this.txFilter = null;
  this.rejectsFilter = new bcoin.bloom.rolling(120000, 0.000001);
  this.rejectsTip = null;

  // Requested objects.
  this.requestMap = {};
  this.requestTimeout = 20 * 60000;
  this.activeRequest = 0;
  this.activeBlocks = 0;
  this.activeTX = 0;

  // Currently broadcasted objects.
  this.invMap = {};
  this.invItems = [];
  this.invTimeout = 60000;

  this.scheduled = false;
  this.pendingWatch = null;
  this.timer = null;
  this.interval = null;

  this._initOptions();
  this._init();
};

utils.inherits(Pool, AsyncObject);

/**
 * Initialize options.
 * @private
 */

Pool.prototype._initOptions = function _initOptions() {
  if (this.options.relay == null)
    this.options.relay = !this.options.spv;

  if (this.options.headers == null)
    this.options.headers = this.options.spv;

  if (!this.options.witness)
    this.services &= ~constants.services.WITNESS;

  if (this.options.port != null)
    this.port = this.options.port;

  this.address.ts = utils.now();
  this.address.services = this.services;
  this.address.setPort(this.port);

  if (this.options.maxPeers != null)
    this.maxPeers = this.options.maxPeers;

  if (this.options.maxLeeches != null)
    this.maxLeeches = this.options.maxLeeches;

  this.createServer = this.options.createServer;
  this.proxyServer = this.options.proxyServer;

  if (this.options.bip150) {
    this.options.bip151 = true;
    this.auth = new bcoin.bip150.AuthDB();

    if (this.options.authPeers)
      this.auth.setAuthorized(this.options.authPeers);

    if (this.options.knownPeers)
      this.auth.setKnown(this.options.knownPeers);

    this.identityKey = this.options.identityKey || bcoin.ec.generatePrivateKey();

    assert(Buffer.isBuffer(this.identityKey), 'Identity key must be a buffer.');
    assert(bcoin.ec.privateKeyVerify(this.identityKey),
      'Invalid identity key.');
  }

  if (this.options.loadTimeout != null)
    this.loadTimeout = this.options.loadTimeout;

  if (this.options.feeRate != null)
    this.feeRate = this.options.feeRate;

  if (this.options.seeds)
    this.hosts.setSeeds(this.options.seeds);

  if (this.options.preferredSeed)
    this.hosts.addSeed(this.options.preferredSeed);

  if (this.options.spv)
    this.blockType = constants.inv.FILTERED_BLOCK;

  if (this.options.witness) {
    this.blockType |= constants.WITNESS_MASK;
    this.txType |= constants.WITNESS_MASK;
    if (this.options.compact) {
      this.logger.warning('Disabling compact blocks due to segwit.');
      this.options.compact = false;
    }
  }

  if (this.options.spv)
    this.spvFilter = bcoin.bloom.fromRate(10000, 0.001, constants.bloom.NONE);

  if (!this.options.mempool)
    this.txFilter = new bcoin.bloom.rolling(50000, 0.000001);

  if (this.options.requestTimeout != null)
    this.requestTimeout = this.options.requestTimeout;

  if (this.options.invTimeout != null)
    this.invTimeout = this.options.invTimeout;
};

/**
 * Initialize the pool.
 * @private
 */

Pool.prototype._init = function _init() {
  var self = this;

  if (this.mempool) {
    this.mempool.on('bad orphan', function(tx) {
      self.rejectsFilter.add(tx.hash());
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
    self.stopTimer();
    self.stopInterval();

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
  var key;

  this.getIP(function(err, ip) {
    if (err)
      self.logger.error(err);

    if (ip) {
      self.address.setHost(ip);
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
        key = bcoin.ec.publicKeyCreate(self.identityKey, true);
        self.logger.info('Identity public key: %s.', key.toString('hex'));
        self.logger.info('Identity address: %s.', bcoin.bip150.address(key));
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
  var i, items, hashes, hash;

  this.stopSync();

  items = this.invItems.slice();

  for (i = 0; i < items.length; i++)
    items[i].finish();

  hashes = Object.keys(this.requestMap);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    this.requestMap[hash].finish(new Error('Pool closed.'));
  }

  this.peers.destroy();

  this.stopInterval();
  this.stopTimer();

  this.unlisten(callback);
};

/**
 * Connect to the network.
 */

Pool.prototype.connect = function connect() {
  var self = this;

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

  assert(this.hosts.seeds.length !== 0, 'No seeds available.');

  this.addLoader();

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

  if (this.createServer) {
    this.server = this.createServer();
  } else {
    if (utils.isBrowser)
      return utils.nextTick(callback);
    net = require('net');
    this.server = new net.Server();
  }

  this.server.on('connection', function(socket) {
    self._handleLeech(socket);
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
 * Handle incoming connection.
 * @private
 * @param {net.Socket} socket
 */

Pool.prototype._handleLeech = function _handleLeech(socket) {
  var hostname, addr;

  if (!socket.remoteAddress) {
    this.logger.debug('Ignoring disconnected leech.');
    socket.destroy();
    return;
  }

  hostname = IP.hostname(socket.remoteAddress, socket.remotePort);
  addr = NetworkAddress.fromHostname(hostname, this.network);

  if (this.peers.leeches.length >= this.maxLeeches) {
    this.logger.debug('Ignoring leech: too many leeches (%s).', hostname);
    socket.destroy();
    return;
  }

  if (this.hosts.isMisbehaving(addr)) {
    this.logger.debug('Ignoring misbehaving leech (%s).', hostname);
    socket.destroy();
    return;
  }

  if (this.hosts.isIgnored(addr)) {
    this.logger.debug('Ignoring leech (%s).', hostname);
    socket.destroy();
    return;
  }

  this.addLeech(socket);
};

/**
 * Start timer to detect stalling.
 * @private
 */

Pool.prototype.startTimer = function startTimer() {
  var self = this;

  this.stopTimer();

  function destroy() {
    if (!self.syncing)
      return;

    if (self.chain.isFull())
      return;

    if (self.peers.load) {
      self.peers.load.destroy();
      self.logger.debug('Timer ran out. Finding new loader peer.');
    }
  }

  this.timer = setTimeout(destroy, this.loadTimeout);
};

/**
 * Stop the stall timer (done on chain sync).
 * @private
 */

Pool.prototype.stopTimer = function stopTimer() {
  if (this.timer != null) {
    clearTimeout(this.timer);
    this.timer = null;
  }
};

/**
 * Start the stall interval (shorter than the
 * stall timer, inteded to give warnings and
 * reset the stall *timer* if the chain is
 * busy). Stopped on chain sync.
 * @private
 */

Pool.prototype.startInterval = function startInterval() {
  var self = this;

  this.stopInterval();

  function load() {
    if (!self.syncing)
      return;

    if (self.chain.isFull())
      return self.stopInterval();

    if (self.chain.isBusy())
      return self.startTimer();

    self.logger.warning('Stalling.');
  }

  this.interval = setInterval(load, this.loadTimeout / 6 | 0);
};

/**
 * Stop the stall interval.
 * @private
 */

Pool.prototype.stopInterval = function stopInterval() {
  if (this.interval != null) {
    clearInterval(this.interval);
    this.interval = null;
  }
};

/**
 * Add a loader peer. Necessary for
 * a sync to even begin.
 * @private
 */

Pool.prototype.addLoader = function addLoader() {
  var self = this;
  var peer, addr;

  if (!this.loaded)
    return;

  if (this.peers.load) {
    this.fillPeers();
    return;
  }

  addr = this.getLoaderHost();
  peer = this.peers.get(addr);

  if (peer) {
    this.peers.repurpose(peer);
    this.logger.info('Repurposed loader peer (%s).', peer.hostname);
    utils.nextTick(function() {
      self.emit('loader', peer);
    });
    return;
  }

  peer = this.createPeer({
    host: addr,
    type: bcoin.peer.types.LOADER
  });

  this.logger.info('Added loader peer (%s).', peer.hostname);

  this.peers.addLoader(peer);
  this.fillPeers();

  utils.nextTick(function() {
    self.emit('loader', peer);
  });
};

/**
 * Start the blockchain sync.
 */

Pool.prototype.startSync = function startSync() {
  this.syncing = true;

  this.startInterval();
  this.startTimer();

  this.connect();

  if (!this.peers.load) {
    this.addLoader();
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

  this.stopInterval();
  this.stopTimer();

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
    this.startInterval();
    // Reset timeout to avoid killing the loader.
    this.startTimer();
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
      self.rejectsFilter.add(header.hash());
      return next(new Error('Invalid header.'));
    }

    last = hash;

    self.getData(peer, self.blockType, hash, next);
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
    this.startInterval();
    // Reset timeout to avoid killing the loader.
    this.startTimer();
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

    self.getData(peer, self.blockType, hash, function(err, exists) {
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
        if (!self.requestMap[hash]) {
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

      self.rejectsFilter.add(block.hash());
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
        self.activeBlocks,
        peer.queueBlock.length,
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

Pool.prototype.createPeer = function createPeer(options) {
  var self = this;
  var peer = new bcoin.peer(this, options);

  peer.once('close', function() {
    self.removePeer(peer);

    if (!self.loaded)
      return;

    if (peer.type !== bcoin.peer.types.LOADER) {
      self.fillPeers();
      return;
    }

    self.stopInterval();
    self.stopTimer();

    if (self.peers.regular.length === 0) {
      self.logger.warning('%s %s %s',
        'Could not connect to any peers.',
        'Do you have a network connection?',
        'Retrying in 5 seconds.');
      setTimeout(function() {
        self.addLoader();
      }, 5000);
      return;
    }

    self.addLoader();
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
        self.startInterval();
        self.startTimer();
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
        self.startInterval();
        self.startTimer();
      }
    });
  });

  peer.on('error', function(err) {
    self.emit('error', err, peer);
  });

  peer.on('reject', function(payload) {
    var data, code;

    if (payload.data)
      data = utils.revHex(payload.data);

    code = constants.rejectByVal[payload.code];

    if (code)
      code = code.toLowerCase();

    self.logger.warning(
      'Received reject (%s): msg=%s code=%s reason=%s data=%s.',
      peer.hostname,
      payload.message,
      code || payload.code,
      payload.reason,
      data || null);

    self.emit('reject', payload, peer);
  });

  peer.on('alert', function(alert) {
    self._handleAlert(alert, peer);
  });

  peer.on('notfound', function(items) {
    var i, item, req;

    for (i = 0; i < items.length; i++) {
      item = items[i];
      req = self.requestMap[item.hash];
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

      if (self.hosts.add(host))
        self.emit('host', host, peer);
    }

    self.emit('addr', hosts, peer);
    self.fillPeers();
  });

  peer.on('txs', function(txs) {
    var i, hash;

    self.emit('txs', txs, peer);

    if (self.syncing && !self.synced)
      return;

    for (i = 0; i < txs.length; i++) {
      hash = txs[i];
      self.getData(peer, self.txType, hash);
    }
  });

  peer.on('version', function(version) {
    self.logger.info(
      'Received version (%s): version=%d height=%d services=%s agent=%s',
      peer.hostname,
      version.version,
      version.height,
      version.services.toString(2),
      version.agent);

    bcoin.time.add(peer.hostname, version.ts);

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

  if (!this.rejectsFilter.added(alert.hash()))
    return;

  if (!alert.verify(this.network.alertKey)) {
    this.logger.warning('Peer sent a phony alert packet (%s).', peer.hostname);
    // Let's look at it because why not?
    this.logger.debug(alert);
    peer.setMisbehavior(100);
    return;
  }

  if (now >= alert.expiration) {
    this.logger.warning(
      'Peer sent an expired alert packet (%s).',
      peer.hostname);
    this.logger.debug(alert);
    return;
  }

  if (alert.id === 0x7fffffff) {
    if (!(alert.expiration === 0x7fffffff
        && alert.cancel === 0x7fffffff - 1
        && alert.minVer === 0
        && alert.maxVer === 0x7fffffff
        && alert.subVers.length === 0
        && alert.priority === 0x7fffffff
        && alert.statusBar === 'URGENT: Alert key compromised, upgrade required')) {
      return;
    }
  }

  // Keep alert disabled on main.
  if (this.network.type === 'main') {
    // https://github.com/bitcoin/bitcoin/pull/7692#issuecomment-197967429
    this.logger.warning('The Japanese government sent an alert packet.');
    this.logger.warning('Here is their IP: %s.', peer.hostname);
    this.logger.info(alert);
    peer.setMisbehavior(100);
    return;
  }

  this.logger.warning('Received alert from peer (%s).', peer.hostname);
  this.logger.warning(alert);

  if (now < alert.relayUntil)
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
      this.txFilter.add(tx.hash());

    this.logger.warning('Peer sent unrequested tx: %s (%s).',
      tx.rhash, peer.hostname);

    if (this.rejectsFilter.test(tx.hash())) {
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
        self.rejectsFilter.add(tx.hash());
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

Pool.prototype.addLeech = function addLeech(socket) {
  var self = this;
  var peer;

  if (!this.loaded)
    return socket.destroy();

  peer = this.createPeer({
    socket: socket,
    type: bcoin.peer.types.LEECH
  });

  this.logger.info('Added leech peer (%s).', peer.hostname);

  this.peers.addLeech(peer);

  utils.nextTick(function() {
    self.emit('leech', peer);
  });
};

/**
 * Create a regular non-loader peer. These primarily
 * exist for transaction relaying.
 * @private
 */

Pool.prototype.addPeer = function addPeer() {
  var self = this;
  var peer, addr;

  if (!this.loaded)
    return;

  if (this.peers.isFull())
    return;

  // Hang back if we don't have a loader peer yet.
  if (!this.peers.load)
    return;

  addr = this.hosts.getHost();

  if (!addr)
    return;

  peer = this.createPeer({
    host: addr,
    type: bcoin.peer.types.REGULAR
  });

  this.peers.addPending(peer);

  peer.once('ack', function() {
    self.peers.promote(peer);
  });

  utils.nextTick(function() {
    self.emit('peer', peer);
  });
};

/**
 * Attempt to refill the pool with peers.
 * @private
 */

Pool.prototype.fillPeers = function fillPeers() {
  for (var i = 0; i < this.maxPeers - 1; i++)
    this.addPeer();
};

/**
 * Remove a peer from any list. Drop all load requests.
 * @private
 * @param {Peer} peer
 */

Pool.prototype.removePeer = function removePeer(peer) {
  var i, hashes, hash, item;

  this.peers.remove(peer);

  hashes = Object.keys(this.requestMap);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    item = this.requestMap[hash];
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

  if (this.pendingWatch != null)
    return;

  this.pendingWatch = setTimeout(function() {
    self.pendingWatch = null;

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

Pool.prototype.getData = function getData(peer, type, hash, callback) {
  var self = this;
  var item;

  callback = utils.ensure(callback);

  if (!this.loaded)
    return callback();

  this.has(type, hash, function(err, exists) {
    if (err)
      return callback(err);

    if (exists)
      return callback(null, true);

    item = new LoadRequest(self, peer, type, hash);

    if (type === self.txType) {
      if (peer.queueTX.length === 0) {
        utils.nextTick(function() {
          self.logger.debug(
            'Requesting %d/%d txs from peer with getdata (%s).',
            peer.queueTX.length,
            self.activeTX,
            peer.hostname);

          peer.getData(peer.queueTX);
          peer.queueTX.length = 0;
        });
      }

      peer.queueTX.push(item.start());

      return callback(null, false);
    }

    peer.queueBlock.push(item);

    callback(null, false);
  });
};

/**
 * Test whether the pool has or has seen an item.
 * @param {InvType} type
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

Pool.prototype.has = function has(type, hash, callback) {
  var self = this;

  this.exists(type, hash, function(err, exists) {
    if (err)
      return callback(err);

    if (exists)
      return callback(null, true);

    // Check the pending requests.
    if (self.requestMap[hash])
      return callback(null, true);

    // We need to reset the rejects filter periodically.
    // There may be a locktime in a TX that is now valid.
    if (self.rejectsTip !== self.chain.tip.hash) {
      self.rejectsTip = self.chain.tip.hash;
      self.rejectsFilter.reset();
    } else {
      // If we recently rejected this item. Ignore.
      if (self.rejectsFilter.test(hash, 'hex')) {
        self.logger.spam('Peer sent a known reject: %s.', utils.revHex(hash));
        return callback(null, true);
      }
    }

    return callback(null, false);
  });
};

/**
 * Test whether the chain or mempool has seen an item.
 * @param {InvType} type
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

Pool.prototype.exists = function exists(type, hash, callback) {
  if (type === this.txType) {
    // Check the TX filter if
    // we don't have a mempool.
    if (!this.mempool) {
      callback = utils.asyncify(callback);
      if (this.txFilter.added(hash, 'hex'))
        return callback(null, false);
      return callback(null, true);
    }

    // Check the mempool.
    return callback(null, this.mempool.has(hash));
  }

  // Check the chain.
  this.chain.has(hash, callback);
};

/**
 * Schedule next batch of `getdata` requests for peer.
 * @param {Peer} peer
 */

Pool.prototype.scheduleRequests = function scheduleRequests(peer) {
  var self = this;

  if (this.scheduled)
    return;

  this.scheduled = true;

  this.chain.onDrain(function() {
    utils.nextTick(function() {
      self.sendRequests(peer);
      self.scheduled = false;
    });
  });
};

/**
 * Send scheduled requests in the request queues.
 * @private
 * @param {Peer} peer
 */

Pool.prototype.sendRequests = function sendRequests(peer) {
  var i, size, items;

  if (this.chain.isBusy())
    return;

  if (peer.queueBlock.length === 0)
    return;

  if (this.options.spv) {
    if (this.activeBlocks >= 500)
      return;
    items = peer.queueBlock.slice();
    peer.queueBlock.length = 0;
  } else {
    size = this.network.getBatchSize(this.chain.height);

    if (this.activeBlocks >= size)
      return;

    items = peer.queueBlock.slice(0, size);
    peer.queueBlock = peer.queueBlock.slice(size);
  }

  for (i = 0; i < items.length; i++)
    items[i] = items[i].start();

  this.logger.debug(
    'Requesting %d/%d blocks from peer with getdata (%s).',
    items.length,
    this.activeBlocks,
    peer.hostname);

  peer.getData(items);
};

/**
 * Fulfill a requested block.
 * @param {Hash}
 * @returns {LoadRequest|null}
 */

Pool.prototype.fulfill = function fulfill(data) {
  var hash = data.hash('hex');
  var item = this.requestMap[hash];

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

  item = this.invMap[hash];

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
 * Allocate a new loader host.
 * @returns {NetworkAddress}
 */

Pool.prototype.getLoaderHost = function getLoaderHost() {
  if (!this.connected && this.options.preferredSeed)
    return this.hosts.seeds[0];

  return this.hosts.getLoaderHost();
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
    this.ban(peer);
    this.logger.debug('Ban threshold exceeded (%s).', peer.host);
    return true;
  }

  return false;
};

/**
 * Ban a peer.
 * @param {NetworkAddress} host
 */

Pool.prototype.ban = function ban(addr) {
  var peer = this.peers.get(addr);

  this.logger.debug('Banning peer (%s).', addr.hostname);
  this.hosts.ban(addr);

  if (peer)
    peer.destroy();
};

/**
 * Unban a peer.
 * @param {String|NetworkAddress} addr
 */

Pool.prototype.unban = function unban(addr) {
  this.hosts.unban(addr);
};

/**
 * Test whether the host/peer is banned.
 * @param {NetworkAddress} addr
 * @returns {Boolean}
 */

Pool.prototype.isMisbehaving = function isMisbehaving(addr) {
  return this.hosts.isMisbehaving(addr);
};

/**
 * Ignore peer.
 * @param {Peer} peer
 */

Pool.prototype.ignore = function ignore(addr) {
  var peer = this.peers.get(addr);

  this.logger.debug('Ignoring peer (%s).', addr.hostname);
  this.hosts.ignore(addr);

  if (peer)
    peer.destroy();
};

/**
 * Test whether the host/peer is ignored.
 * @param {NetworkAddress} addr
 * @returns {Boolean}
 */

Pool.prototype.isIgnored = function isIgnored(addr) {
  return this.hosts.isIgnored(addr);
};

/**
 * Attempt to retrieve external IP from icanhazip.com.
 * @param {Function} callback
 */

Pool.prototype.getIP = function getIP(callback) {
  var self = this;
  var request, ip;

  if (utils.isBrowser)
    return callback(new Error('Could not find IP.'));

  request = require('../http/request');

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
  var request, ip;

  if (utils.isBrowser)
    return callback(new Error('Could not find IP.'));

  request = require('../http/request');

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
 * Peer List
 * @constructor
 */

function PeerList(pool) {
  this.pool = pool;
  // Peers that are loading blocks themselves
  this.regular = [];
  // Peers that are still connecting
  this.pending = [];
  // Peers that connected to us
  this.leeches = [];
  // Peers that are loading block ids
  this.load = null;
  // All peers
  this.all = [];
  // Map of hostnames
  this.map = {};
}

PeerList.prototype.addPending = function addPending(peer) {
  this.pending.push(peer);
  this.all.push(peer);
  assert(!this.map[peer.hostname]);
  this.map[peer.hostname] = peer;
};

PeerList.prototype.promote = function promote(peer) {
  if (utils.binaryRemove(this.pending, peer, compare))
    utils.binaryInsert(this.regular, peer, compare);
};

PeerList.prototype.remove = function remove(peer) {
  utils.binaryRemove(this.pending, peer, compare);
  utils.binaryRemove(this.regular, peer, compare);
  utils.binaryRemove(this.leeches, peer, compare);
  utils.binaryRemove(this.all, peer, compare);

  assert(this.map[peer.hostname]);
  delete this.map[peer.hostname];

  if (this.load === peer) {
    this.pool.logger.info('Removed loader peer (%s).', peer.hostname);
    this.load = null;
  }
};

PeerList.prototype.repurpose = function repurpose(peer) {
  assert(peer.type === bcoin.peer.types.REGULAR);
  utils.binaryRemove(this.pending, peer, compare);
  utils.binaryRemove(this.regular, peer, compare);
  peer.type = bcoin.peer.types.LOADER;
  assert(!this.load);
  this.load = peer;
};

PeerList.prototype.isFull = function isFull() {
  return this.regular.length + this.pending.length >= this.pool.maxPeers - 1;
};

PeerList.prototype.addLeech = function addLeech(peer) {
  this.leeches.push(peer);
  this.all.push(peer);
  this.map[peer.hostname] = peer;
};

PeerList.prototype.addLoader = function addLoader(peer) {
  this.load = peer;
  this.all.push(peer);
  this.map[peer.hostname] = peer;
};

PeerList.prototype.get = function get(addr) {
  return this.map[addr.hostname];
};

PeerList.prototype.destroy = function destroy() {
  var i, peers;

  if (this.load)
    this.load.destroy();

  peers = this.regular.slice();

  for (i = 0; i < peers.length; i++)
    peers[i].destroy();

  peers = this.pending.slice();

  for (i = 0; i < peers.length; i++)
    peers[i].destroy();

  peers = this.leeches.slice();

  for (i = 0; i < peers.length; i++)
    peers[i].destroy();
};

/**
 * Host List
 * @constructor
 */

function HostList(pool) {
  this.pool = pool;
  this.seeds = [];
  this.items = [];
  this.map = {};

  // Ignored hosts
  this.ignored = {};

  // Misbehaving hosts
  this.misbehaving = {};

  this.setSeeds(this.pool.network.seeds);
}

/**
 * Clear misbehaving and ignored.
 */

HostList.prototype.clear = function clear() {
  this.ignored = {};
  this.misbehaving = {};
};

/**
 * Allocate a new loader host.
 * @returns {NetworkAddress}
 */

HostList.prototype.getLoaderHost = function getLoaderHost() {
  var addr = this.getRandom(this.seeds);

  if (addr)
    return addr;

  addr = this.getRandom(this.items);

  if (addr)
    return addr;

  this.pool.logger.warning('All seeds banned or ignored. Clearing...');
  this.clear();

  return this.getRandom(this.seeds);
};

/**
 * Allocate a new host which is not currently being used.
 * @returns {NetworkAddress}
 */

HostList.prototype.getHost = function getHost() {
  var addr = this.getRandom(this.seeds, true);

  if (addr)
    return addr;

  return this.getRandom(this.items, true);
};

/**
 * Get a random host from collection of hosts.
 * @param {NetworkAddress[]} hosts
 * @param {Boolean} unique
 * @returns {NetworkAddress}
 */

HostList.prototype.getRandom = function getRandom(hosts, unique) {
  var index = Math.random() * hosts.length | 0;
  var last = -1;
  var i, addr;

  for (i = 0; i < hosts.length; i++) {
    addr = hosts[i];

    if (this.isMisbehaving(addr))
      continue;

    if (this.isIgnored(addr))
      continue;

    if (unique && this.pool.peers.get(addr))
      continue;

    if (i >= index)
      return addr;

    last = i;
  }

  if (last === -1)
    return;

  return hosts[last];
};

/**
 * Add host to host list.
 * @param {NetworkAddress} addr
 * @returns {Boolean}
 */

HostList.prototype.add = function add(addr) {
  if (this.items.length > 500)
    return;

  if (this.map[addr.hostname])
    return;

  utils.binaryInsert(this.items, addr, compare);

  this.map[addr.hostname] = addr;

  return addr;
};

/**
 * Remove host from host list.
 * @param {NetworkAddress} addr
 * @returns {Boolean}
 */

HostList.prototype.remove = function remove(addr) {
  addr = this.map[addr.hostname];

  if (!addr)
    return;

  utils.binaryRemove(this.items, addr, compare);

  delete this.map[addr.hostname];

  return addr;
};

/**
 * Increase peer's ban score.
 * @param {NetworkAddress} addr
 */

HostList.prototype.ban = function ban(addr) {
  this.misbehaving[addr.host] = utils.now();
  this.remove(addr);
};

/**
 * Unban host.
 * @param {NetworkAddress} addr
 */

HostList.prototype.unban = function unban(addr) {
  delete this.misbehaving[addr.host];
  delete this.ignored[addr.host];
};

/**
 * Test whether the host/peer is banned.
 * @param {NetworkAddress} addr
 * @returns {Boolean}
 */

HostList.prototype.isMisbehaving = function isMisbehaving(addr) {
  var time = this.misbehaving[addr.host];

  if (time != null) {
    if (utils.now() > time + constants.BAN_TIME) {
      delete this.misbehaving[addr.host];
      return false;
    }
    return true;
  }

  return false;
};

/**
 * Ignore peer.
 * @param {NetworkAddress} addr
 */

HostList.prototype.ignore = function ignore(addr) {
  if (!this.remove(addr))
    this.ignored[addr.host] = true;
};

/**
 * Test whether the host/peer is ignored.
 * @param {NetworkAddress} addr
 * @returns {Boolean}
 */

HostList.prototype.isIgnored = function isIgnored(addr) {
  return this.ignored[addr.host] === true;
};

/**
 * Set initial seeds.
 * @param {String[]} seeds
 */

HostList.prototype.setSeeds = function setSeeds(seeds) {
  var i, hostname, seed;

  this.seeds.length = 0;

  for (i = 0; i < seeds.length; i++) {
    hostname = seeds[i];
    seed = NetworkAddress.fromHostname(hostname, this.pool.network);
    this.seeds.push(seed);
  }
};

/**
 * Add a preferred seed.
 * @param {String} hostname
 */

HostList.prototype.addSeed = function addSeed(hostname) {
  var seed = NetworkAddress.fromHostname(hostname, this.pool.network);
  this.seeds.unshift(seed);
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

  assert(!this.pool.requestMap[this.hash]);
  this.pool.requestMap[this.hash] = this;
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
  if (this.type !== this.pool.txType
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
  this.pool.activeRequest++;

  if (this.type === this.pool.txType)
    this.pool.activeTX++;
  else
    this.pool.activeBlocks++;

  return this;
};

/**
 * Mark the request as completed.
 * Remove from queue and map. Clear timeout.
 * @param {Error?} err
 */

LoadRequest.prototype.finish = function finish(err) {
  var i;

  if (this.pool.requestMap[this.hash]) {
    delete this.pool.requestMap[this.hash];
    if (this.active) {
      this.active = false;
      this.pool.activeRequest--;
      if (this.type === this.pool.txType)
        this.pool.activeTX--;
      else
        this.pool.activeBlocks--;
    }
  }

  if (this.type === this.pool.txType)
    utils.binaryRemove(this.peer.queueTX, this, compare);
  else
    utils.binaryRemove(this.peer.queueBlock, this, compare);

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
    + ' type=' + (this.type === this.pool.txType ? 'tx' : 'block')
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
  assert(!this.pool.invMap[this.hash], 'Already started.');

  this.pool.invMap[this.hash] = this;
  utils.binaryInsert(this.pool.invItems, this, compare);

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
  }, this.pool.invTimeout);
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
  assert(this.pool.invMap[this.hash], 'Already finished.');

  clearTimeout(this.timeout);
  this.timeout = null;

  delete this.pool.invMap[this.hash];
  utils.binaryRemove(this.pool.invItems, this, compare);

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
