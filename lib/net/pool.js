/*!
 * pool.js - peer management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const AsyncObject = require('../utils/asyncobject');
const util = require('../utils/util');
const IP = require('../utils/ip');
const co = require('../utils/co');
const common = require('./common');
const chainCommon = require('../blockchain/common');
const Address = require('../primitives/address');
const BIP150 = require('./bip150');
const BIP151 = require('./bip151');
const BIP152 = require('./bip152');
const Bloom = require('../utils/bloom');
const RollingFilter = require('../utils/rollingfilter');
const secp256k1 = require('../crypto/secp256k1');
const Lock = require('../utils/lock');
const Network = require('../protocol/network');
const Peer = require('./peer');
const external = require('./external');
const List = require('../utils/list');
const tcp = require('./tcp');
const dns = require('./dns');
const HostList = require('./hostlist');
const UPNP = require('./upnp');
const InvItem = require('../primitives/invitem');
const packets = require('./packets');
const services = common.services;
const invTypes = InvItem.types;
const packetTypes = packets.types;
const scores = HostList.scores;

/**
 * A pool of peers for handling all network activity.
 * @alias module:net.Pool
 * @constructor
 * @param {Object} options
 * @param {Chain} options.chain
 * @param {Mempool?} options.mempool
 * @param {Number?} [options.maxOutbound=8] - Maximum number of peers.
 * @param {Boolean?} options.spv - Do an SPV sync.
 * @param {Boolean?} options.noRelay - Whether to ask
 * for relayed transactions.
 * @param {Number?} [options.feeRate] - Fee filter rate.
 * @param {Number?} [options.invTimeout=60000] - Timeout for broadcasted
 * objects.
 * @param {Boolean?} options.listen - Whether to spin up a server socket
 * and listen for peers.
 * @param {Boolean?} options.selfish - A selfish pool. Will not serve blocks,
 * headers, hashes, utxos, or transactions to peers.
 * @param {Boolean?} options.broadcast - Whether to automatically broadcast
 * transactions accepted to our mempool.
 * @param {String[]} options.seeds
 * @param {Function?} options.createSocket - Custom function to create a socket.
 * Must accept (port, host) and return a node-like socket.
 * @param {Function?} options.createServer - Custom function to create a server.
 * Must return a node-like server.
 * @emits Pool#block
 * @emits Pool#tx
 * @emits Pool#peer
 * @emits Pool#open
 * @emits Pool#close
 * @emits Pool#error
 * @emits Pool#reject
 */

function Pool(options) {
  if (!(this instanceof Pool))
    return new Pool(options);

  AsyncObject.call(this);

  this.options = new PoolOptions(options);

  this.network = this.options.network;
  this.logger = this.options.logger.context('net');
  this.chain = this.options.chain;
  this.mempool = this.options.mempool;
  this.server = this.options.createServer();
  this.nonces = this.options.nonces;

  this.locker = new Lock(true);
  this.connected = false;
  this.disconnecting = false;
  this.syncing = false;
  this.spvFilter = null;
  this.txFilter = null;
  this.blockMap = new Set();
  this.txMap = new Set();
  this.compactBlocks = new Set();
  this.invMap = new Map();
  this.pendingFilter = null;
  this.pendingRefill = null;

  this.checkpoints = false;
  this.headerChain = new List();
  this.headerNext = null;
  this.headerTip = null;
  this.headerFails = 0;

  this.peers = new PeerList();
  this.authdb = new BIP150.AuthDB(this.options);
  this.hosts = new HostList(this.options);
  this.id = 0;

  if (this.options.spv)
    this.spvFilter = Bloom.fromRate(20000, 0.001, Bloom.flags.ALL);

  if (!this.options.mempool)
    this.txFilter = new RollingFilter(50000, 0.000001);

  this._init();
};

util.inherits(Pool, AsyncObject);

/**
 * Max number of header chain failures
 * before disabling checkpoints.
 * @const {Number}
 * @default
 */

Pool.MAX_HEADER_FAILS = 1000;

/**
 * Discovery interval for UPNP and DNS seeds.
 * @const {Number}
 * @default
 */

Pool.DISCOVERY_INTERVAL = 120000;

/**
 * Initialize the pool.
 * @private
 */

Pool.prototype._init = function _init() {
  this.server.on('error', (err) => {
    this.emit('error', err);
  });

  this.server.on('connection', (socket) => {
    this.handleSocket(socket);
    this.emit('connection', socket);
  });

  this.server.on('listening', () => {
    let data = this.server.address();
    this.logger.info(
      'Pool server listening on %s (port=%d).',
      data.address, data.port);
    this.emit('listening', data);
  });

  this.chain.on('block', (block, entry) => {
    this.emit('block', block, entry);
  });

  this.chain.on('reset', () => {
    if (this.checkpoints)
      this.resetChain();
    this.forceSync();
  });

  this.chain.on('full', () => {
    this.sync();
    this.emit('full');
    this.logger.info('Chain is fully synced (height=%d).', this.chain.height);
  });

  this.chain.on('bad orphan', (err, id) => {
    this.handleBadOrphan('block', err, id);
  });

  if (this.mempool) {
    this.mempool.on('tx', (tx) => {
      this.emit('tx', tx);
    });

    this.mempool.on('bad orphan', (err, id) => {
      this.handleBadOrphan('tx', err, id);
    });
  }

  if (!this.options.selfish && !this.options.spv) {
    if (this.mempool) {
      this.mempool.on('tx', (tx) => {
        this.announceTX(tx);
      });
    }

    // Normally we would also broadcast
    // competing chains, but we want to
    // avoid getting banned if an evil
    // miner sends us an invalid competing
    // chain that we can't connect and
    // verify yet.
    this.chain.on('block', (block) => {
      if (!this.chain.synced)
        return;
      this.announceBlock(block);
    });
  }
};

/**
 * Open the pool, wait for the chain to load.
 * @method
 * @alias Pool#open
 * @returns {Promise}
 */

Pool.prototype._open = async function _open() {
  if (this.mempool)
    await this.mempool.open();
  else
    await this.chain.open();

  this.logger.info('Pool loaded (maxpeers=%d).', this.options.maxOutbound);

  if (this.options.bip150) {
    let key = secp256k1.publicKeyCreate(this.options.identityKey, true);
    this.logger.info('Identity public key: %s.', key.toString('hex'));
    this.logger.info('Identity address: %s.', BIP150.address(key));
  }

  this.resetChain();
};

/**
 * Reset header chain.
 */

Pool.prototype.resetChain = function resetChain() {
  let tip = this.chain.tip;

  if (!this.options.checkpoints)
    return;

  this.checkpoints = false;
  this.chain.checkpoints = false;
  this.headerTip = null;
  this.headerChain.reset();
  this.headerNext = null;

  if (tip.height < this.network.lastCheckpoint) {
    this.checkpoints = true;
    this.chain.checkpoints = true;
    this.headerTip = this.getNextTip(tip.height);
    this.headerChain.push(new HeaderEntry(tip.hash, tip.height));
    this.logger.info(
      'Initialized header chain to height %d (checkpoint=%s).',
      tip.height, util.revHex(this.headerTip.hash));
  }
};

/**
 * Close and destroy the pool.
 * @method
 * @alias Pool#close
 * @returns {Promise}
 */

Pool.prototype._close = async function close() {
  await this.disconnect();
};

/**
 * Connect to the network.
 * @method
 * @returns {Promise}
 */

Pool.prototype.connect = async function connect() {
  let unlock = await this.locker.lock();
  try {
    return await this._connect();
  } finally {
    unlock();
  }
};

/**
 * Connect to the network (no lock).
 * @method
 * @returns {Promise}
 */

Pool.prototype._connect = async function connect() {
  assert(this.loaded, 'Pool is not loaded.');

  if (this.connected)
    return;

  await this.hosts.open();
  await this.authdb.open();

  await this.discoverGateway();
  await this.discoverExternal();
  await this.discoverSeeds();

  this.fillOutbound();

  await this.listen();

  this.startTimer();

  this.connected = true;
};

/**
 * Disconnect from the network.
 * @method
 * @returns {Promise}
 */

Pool.prototype.disconnect = async function disconnect() {
  let unlock = await this.locker.lock();
  try {
    return await this._disconnect();
  } finally {
    unlock();
  }
};

/**
 * Disconnect from the network.
 * @method
 * @returns {Promise}
 */

Pool.prototype._disconnect = async function disconnect() {
  assert(this.loaded, 'Pool is not loaded.');

  if (!this.connected)
    return;

  this.disconnecting = true;

  for (let item of this.invMap.values())
    item.resolve();

  this.peers.destroy();

  this.blockMap.clear();
  this.txMap.clear();

  if (this.pendingFilter != null) {
    clearTimeout(this.pendingFilter);
    this.pendingFilter = null;
  }

  if (this.pendingRefill != null) {
    clearTimeout(this.pendingRefill);
    this.pendingRefill = null;
  }

  this.checkpoints = false;
  this.chain.checkpoints = false;
  this.headerTip = null;
  this.headerChain.reset();
  this.headerNext = null;

  this.stopTimer();

  await this.authdb.close();
  await this.hosts.close();

  await this.unlisten();

  this.disconnecting = false;
  this.syncing = false;
  this.connected = false;
};

/**
 * Start listening on a server socket.
 * @method
 * @private
 * @returns {Promise}
 */

Pool.prototype.listen = async function listen() {
  assert(this.server);
  assert(!this.connected, 'Already listening.');

  if (!this.options.listen)
    return;

  this.server.maxConnections = this.options.maxInbound;

  await this.server.listen(this.options.port, this.options.host);
};

/**
 * Stop listening on server socket.
 * @method
 * @private
 * @returns {Promise}
 */

Pool.prototype.unlisten = async function unlisten() {
  assert(this.server);
  assert(this.connected, 'Not listening.');

  if (!this.options.listen)
    return;

  await this.server.close();
};

/**
 * Start discovery timer.
 * @private
 */

Pool.prototype.startTimer = function startTimer() {
  assert(this.timer == null, 'Timer already started.');
  this.timer = co.setInterval(this.discover, Pool.DISCOVERY_INTERVAL, this);
};

/**
 * Stop discovery timer.
 * @private
 */

Pool.prototype.stopTimer = function stopTimer() {
  assert(this.timer != null, 'Timer already stopped.');
  co.clearInterval(this.timer);
  this.timer = null;
};

/**
 * Rediscover seeds and internet gateway.
 * Attempt to add port mapping once again.
 * @returns {Promise}
 */

Pool.prototype.discover = async function discover() {
  await this.discoverGateway();
  await this.discoverSeeds(true);
};

/**
 * Attempt to add port mapping (i.e.
 * remote:8333->local:8333) via UPNP.
 * @returns {Promise}
 */

Pool.prototype.discoverGateway = async function discoverGateway() {
  let src = this.options.publicPort;
  let dest = this.options.port;
  let wan, host;

  // Pointless if we're not listening.
  if (!this.options.listen)
    return;

  // UPNP is always optional, since
  // it's likely to not work anyway.
  if (!this.options.upnp)
    return;

  try {
    this.logger.debug('Discovering internet gateway (upnp).');
    wan = await UPNP.discover();
  } catch (e) {
    this.logger.debug('Could not discover internet gateway (upnp).');
    this.logger.debug(e);
    return false;
  }

  try {
    host = await wan.getExternalIP();
  } catch (e) {
    this.logger.debug('Could not find external IP (upnp).');
    this.logger.debug(e);
    return false;
  }

  if (this.hosts.addLocal(host, src, scores.UPNP))
    this.logger.info('External IP found (upnp): %s.', host);

  this.logger.debug(
    'Adding port mapping %d->%d.',
    src, dest);

  try {
    await wan.addPortMapping(host, src, dest);
  } catch (e) {
    this.logger.debug('Could not add port mapping (upnp).');
    this.logger.debug(e);
    return false;
  }

  return true;
};

/**
 * Attempt to resolve DNS seeds if necessary.
 * @param {Boolean} checkPeers
 * @returns {Promise}
 */

Pool.prototype.discoverSeeds = async function discoverSeeds(checkPeers) {
  let max = Math.min(2, this.options.maxOutbound);
  let size = this.hosts.size();
  let total = 0;

  if (this.hosts.dnsSeeds.length === 0)
    return;

  for (let peer = this.peers.head(); peer; peer = peer.next) {
    if (!peer.outbound)
      continue;

    if (peer.connected) {
      if (++total > max)
        break;
    }
  }

  if (size === 0 || (checkPeers && total < max)) {
    this.logger.warning('Could not find enough peers.');
    this.logger.warning('Hitting DNS seeds...');

    await this.hosts.discoverSeeds();

    this.logger.info(
      'Resolved %d hosts from DNS seeds.',
      this.hosts.size() - size);

    this.refill();
  }
};

/**
 * Attempt to discover external IP via HTTP.
 * @returns {Promise}
 */

Pool.prototype.discoverExternal = async function discoverExternal() {
  let port = this.options.publicPort;
  let host4, host6;

  // Pointless if we're not listening.
  if (!this.options.listen)
    return;

  // Never hit an HTTP server if
  // we're using an outbound proxy.
  if (this.options.proxy)
    return;

  // Try not to hit this if we can avoid it.
  if (this.hosts.local.size > 0)
    return;

  try {
    host4 = await external.getIPv4();
  } catch (e) {
    this.logger.debug('Could not find external IPv4 (http).');
    this.logger.debug(e);
  }

  if (host4 && this.hosts.addLocal(host4, port, scores.HTTP))
    this.logger.info('External IPv4 found (http): %s.', host4);

  try {
    host6 = await external.getIPv6();
  } catch (e) {
    this.logger.debug('Could not find external IPv6 (http).');
    this.logger.debug(e);
  }

  if (host6 && this.hosts.addLocal(host6, port, scores.HTTP))
    this.logger.info('External IPv6 found (http): %s.', host6);
};

/**
 * Handle incoming connection.
 * @private
 * @param {net.Socket} socket
 */

Pool.prototype.handleSocket = function handleSocket(socket) {
  let host;

  if (!socket.remoteAddress) {
    this.logger.debug('Ignoring disconnected peer.');
    socket.destroy();
    return;
  }

  host = IP.normalize(socket.remoteAddress);

  if (this.peers.inbound >= this.options.maxInbound) {
    this.logger.debug('Ignoring peer: too many inbound (%s).', host);
    socket.destroy();
    return;
  }

  if (this.hosts.isBanned(host)) {
    this.logger.debug('Ignoring banned peer (%s).', host);
    socket.destroy();
    return;
  }

  host = IP.toHostname(host, socket.remotePort);

  assert(!this.peers.map[host], 'Port collision.');

  this.addInbound(socket);
};

/**
 * Add a loader peer. Necessary for
 * a sync to even begin.
 * @private
 */

Pool.prototype.addLoader = function addLoader() {
  let peer, addr;

  if (!this.loaded)
    return;

  assert(!this.peers.load);

  for (let peer = this.peers.head(); peer; peer = peer.next) {
    if (!peer.outbound)
      continue;

    this.logger.info(
      'Repurposing peer for loader (%s).',
      peer.hostname());

    this.setLoader(peer);

    return;
  }

  addr = this.getHost();

  if (!addr)
    return;

  peer = this.createOutbound(addr);

  this.logger.info('Adding loader peer (%s).', peer.hostname());

  this.peers.add(peer);

  this.setLoader(peer);
};

/**
 * Add a loader peer. Necessary for
 * a sync to even begin.
 * @private
 */

Pool.prototype.setLoader = function setLoader(peer) {
  if (!this.loaded)
    return;

  assert(peer.outbound);
  assert(!this.peers.load);
  assert(!peer.loader);

  peer.loader = true;
  this.peers.load = peer;

  this.sendSync(peer);

  this.emit('loader', peer);
};

/**
 * Start the blockchain sync.
 */

Pool.prototype.startSync = function startSync() {
  if (!this.loaded)
    return;

  assert(this.connected, 'Pool is not connected!');

  this.syncing = true;
  this.resync(false);
};

/**
 * Force sending of a sync to each peer.
 */

Pool.prototype.forceSync = function forceSync() {
  if (!this.loaded)
    return;

  assert(this.connected, 'Pool is not connected!');

  this.resync(true);
};

/**
 * Send a sync to each peer.
 */

Pool.prototype.sync = function sync(force) {
  this.resync(false);
};

/**
 * Stop the sync.
 * @private
 */

Pool.prototype.stopSync = function stopSync() {
  if (!this.syncing)
    return;

  this.syncing = false;

  for (let peer = this.peers.head(); peer; peer = peer.next) {
    if (!peer.outbound)
      continue;

    if (!peer.syncing)
      continue;

    peer.syncing = false;
    peer.merkleBlock = null;
    peer.merkleTime = -1;
    peer.merkleMatches = 0;
    peer.merkleMap = null;
    peer.blockTime = -1;
    peer.blockMap.reset();
    peer.compactBlocks.clear();
  }

  this.blockMap.clear();
  this.compactBlocks.clear();
};

/**
 * Send a sync to each peer.
 * @private
 * @param {Boolean?} force
 * @returns {Promise}
 */

Pool.prototype.resync = async function resync(force) {
  let locator;

  if (!this.syncing)
    return;

  try {
    locator = await this.chain.getLocator();
  } catch (e) {
    this.emit('error', e);
    return;
  }

  for (let peer = this.peers.head(); peer; peer = peer.next) {
    if (!peer.outbound)
      continue;

    if (!force && peer.syncing)
      continue;

    this.sendLocator(locator, peer);
  }
};

/**
 * Test whether a peer is sync-worthy.
 * @param {Peer} peer
 * @returns {Boolean}
 */

Pool.prototype.isSyncable = function isSyncable(peer) {
  if (!this.syncing)
    return false;

  if (peer.destroyed)
    return false;

  if (!peer.handshake)
    return false;

  if (!(peer.services & services.NETWORK))
    return false;

  if (this.options.hasWitness() && !peer.hasWitness())
    return false;

  if (!peer.loader) {
    if (!this.chain.synced)
      return false;
  }

  return true;
};

/**
 * Start syncing from peer.
 * @method
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype.sendSync = async function sendSync(peer) {
  let locator;

  if (peer.syncing)
    return false;

  if (!this.isSyncable(peer))
    return false;

  peer.syncing = true;
  peer.blockTime = util.ms();

  try {
    locator = await this.chain.getLocator();
  } catch (e) {
    peer.syncing = false;
    peer.blockTime = -1;
    this.emit('error', e);
    return false;
  }

  return this.sendLocator(locator, peer);
};

/**
 * Send a chain locator and start syncing from peer.
 * @method
 * @param {Hash[]} locator
 * @param {Peer} peer
 * @returns {Boolean}
 */

Pool.prototype.sendLocator = function sendLocator(locator, peer) {
  if (!this.isSyncable(peer))
    return false;

  // Ask for the mempool if we're synced.
  if (this.network.requestMempool) {
    if (peer.loader && this.chain.synced)
      peer.sendMempool();
  }

  peer.syncing = true;
  peer.blockTime = util.ms();

  if (this.checkpoints) {
    peer.sendGetHeaders(locator, this.headerTip.hash);
    return true;
  }

  peer.sendGetBlocks(locator);

  return true;
};

/**
 * Send `mempool` to all peers.
 */

Pool.prototype.sendMempool = function sendMempool() {
  for (let peer = this.peers.head(); peer; peer = peer.next)
    peer.sendMempool();
};

/**
 * Send `getaddr` to all peers.
 */

Pool.prototype.sendGetAddr = function sendGetAddr() {
  for (let peer = this.peers.head(); peer; peer = peer.next)
    peer.sendGetAddr();
};

/**
 * Request current header chain blocks.
 * @private
 * @param {Peer} peer
 */

Pool.prototype.resolveHeaders = function resolveHeaders(peer) {
  let items = [];

  for (let node = this.headerNext; node; node = node.next) {
    this.headerNext = node.next;

    items.push(node.hash);

    if (items.length === 50000)
      break;
  }

  this.getBlock(peer, items);
};

/**
 * Update all peer heights by their best hash.
 * @param {Hash} hash
 * @param {Number} height
 */

Pool.prototype.resolveHeight = function resolveHeight(hash, height) {
  let total = 0;

  for (let peer = this.peers.head(); peer; peer = peer.next) {
    if (peer.bestHash !== hash)
      continue;

    if (peer.bestHeight !== height) {
      peer.bestHeight = height;
      total++;
    }
  }

  if (total > 0)
    this.logger.debug('Resolved height for %d peers.', total);
};

/**
 * Find the next checkpoint.
 * @private
 * @param {Number} height
 * @returns {Object}
 */

Pool.prototype.getNextTip = function getNextTip(height) {
  for (let next of this.network.checkpoints) {
    if (next.height > height)
      return new HeaderEntry(next.hash, next.height);
  }

  throw new Error('Next checkpoint not found.');
};

/**
 * Announce broadcast list to peer.
 * @param {Peer} peer
 */

Pool.prototype.announceList = function announceList(peer) {
  let blocks = [];
  let txs = [];

  for (let item of this.invMap.values()) {
    switch (item.type) {
      case invTypes.BLOCK:
        blocks.push(item.msg);
        break;
      case invTypes.TX:
        txs.push(item.msg);
        break;
      default:
        assert(false, 'Bad item type.');
        break;
    }
  }

  if (blocks.length > 0)
    peer.announceBlock(blocks);

  if (txs.length > 0)
    peer.announceTX(txs);
};

/**
 * Get a block/tx from the broadcast map.
 * @private
 * @param {Peer} peer
 * @param {InvItem} item
 * @returns {Promise}
 */

Pool.prototype.getBroadcasted = function getBroadcasted(peer, item) {
  let type = item.isTX() ? invTypes.TX : invTypes.BLOCK;
  let entry = this.invMap.get(item.hash);

  if (!entry)
    return;

  if (type !== entry.type) {
    this.logger.debug(
      'Peer requested item with the wrong type (%s).',
      peer.hostname());
    return;
  }

  this.logger.debug(
    'Peer requested %s %s as a %s packet (%s).',
    item.isTX() ? 'tx' : 'block',
    item.rhash(),
    item.hasWitness() ? 'witness' : 'normal',
    peer.hostname());

  entry.handleAck(peer);

  return entry.msg;
};

/**
 * Get a block/tx either from the broadcast map, mempool, or blockchain.
 * @method
 * @private
 * @param {Peer} peer
 * @param {InvItem} item
 * @returns {Promise}
 */

Pool.prototype.getItem = async function getItem(peer, item) {
  let entry = this.getBroadcasted(peer, item);

  if (entry)
    return entry;

  if (this.options.selfish)
    return;

  if (item.isTX()) {
    if (!this.mempool)
      return;
    return this.mempool.getTX(item.hash);
  }

  if (this.chain.options.spv)
    return;

  if (this.chain.options.prune)
    return;

  return await this.chain.db.getBlock(item.hash);
};

/**
 * Send a block from the broadcast list or chain.
 * @method
 * @private
 * @param {Peer} peer
 * @param {InvItem} item
 * @returns {Boolean}
 */

Pool.prototype.sendBlock = async function sendBlock(peer, item, witness) {
  let block = this.getBroadcasted(peer, item);

  // Check for a broadcasted item first.
  if (block) {
    peer.send(new packets.BlockPacket(block, witness));
    return true;
  }

  if (this.options.selfish
      || this.chain.options.spv
      || this.chain.options.prune) {
    return false;
  }

  // If we have the same serialization, we
  // can write the raw binary to the socket.
  if (witness || !this.options.hasWitness()) {
    block = await this.chain.db.getRawBlock(item.hash);

    if (block) {
      peer.sendRaw('block', block);
      return true;
    }

    return false;
  }

  block = await this.chain.db.getBlock(item.hash);

  if (block) {
    peer.send(new packets.BlockPacket(block, witness));
    return true;
  }

  return false;
};

/**
 * Create an outbound peer with no special purpose.
 * @private
 * @param {NetAddress} addr
 * @returns {Peer}
 */

Pool.prototype.createOutbound = function createOutbound(addr) {
  let cipher = BIP151.ciphers.CHACHAPOLY;
  let identity = this.options.identityKey;
  let peer = Peer.fromOutbound(this.options, addr);

  this.hosts.markAttempt(addr.hostname);

  if (this.options.bip151)
    peer.setCipher(cipher);

  if (this.options.bip150)
    peer.setAuth(this.authdb, identity);

  this.bindPeer(peer);

  this.logger.debug('Connecting to %s.', peer.hostname());

  peer.tryOpen();

  return peer;
};

/**
 * Accept an inbound socket.
 * @private
 * @param {net.Socket} socket
 * @returns {Peer}
 */

Pool.prototype.createInbound = function createInbound(socket) {
  let cipher = BIP151.ciphers.CHACHAPOLY;
  let identity = this.options.identityKey;
  let peer = Peer.fromInbound(this.options, socket);

  if (this.options.bip151)
    peer.setCipher(cipher);

  if (this.options.bip150)
    peer.setAuth(this.authdb, identity);

  this.bindPeer(peer);

  peer.tryOpen();

  return peer;
};

/**
 * Allocate new peer id.
 * @returns {Number}
 */

Pool.prototype.uid = function uid() {
  let MAX = Number.MAX_SAFE_INTEGER;

  if (this.id >= MAX - this.peers.size() - 1)
    this.id = 0;

  // Once we overflow, there's a chance
  // of collisions. Unlikely to happen
  // unless we have tried to connect 9
  // quadrillion times, but still
  // account for it.
  do {
    this.id += 1;
  } while (this.peers.find(this.id));

  return this.id;
};

/**
 * Bind to peer events.
 * @private
 * @param {Peer} peer
 */

Pool.prototype.bindPeer = function bindPeer(peer) {
  peer.id = this.uid();

  peer.onPacket = (packet) => {
    return this.handlePacket(peer, packet);
  };

  peer.on('error', (err) => {
    this.logger.debug(err);
  });

  peer.once('connect', () => {
    this.handleConnect(peer);
  });

  peer.once('open', () => {
    this.handleOpen(peer);
  });

  peer.once('close', (connected) => {
    this.handleClose(peer, connected);
  });

  peer.once('ban', () => {
    this.handleBan(peer);
  });
};

/**
 * Handle peer packet event.
 * @method
 * @private
 * @param {Peer} peer
 * @param {Packet} packet
 * @returns {Promise}
 */

Pool.prototype.handlePacket = async function handlePacket(peer, packet) {
  switch (packet.type) {
    case packetTypes.VERSION:
      await this.handleVersion(peer, packet);
      break;
    case packetTypes.VERACK:
      await this.handleVerack(peer, packet);
      break;
    case packetTypes.PING:
      await this.handlePing(peer, packet);
      break;
    case packetTypes.PONG:
      await this.handlePong(peer, packet);
      break;
    case packetTypes.GETADDR:
      await this.handleGetAddr(peer, packet);
      break;
    case packetTypes.ADDR:
      await this.handleAddr(peer, packet);
      break;
    case packetTypes.INV:
      await this.handleInv(peer, packet);
      break;
    case packetTypes.GETDATA:
      await this.handleGetData(peer, packet);
      break;
    case packetTypes.NOTFOUND:
      await this.handleNotFound(peer, packet);
      break;
    case packetTypes.GETBLOCKS:
      await this.handleGetBlocks(peer, packet);
      break;
    case packetTypes.GETHEADERS:
      await this.handleGetHeaders(peer, packet);
      break;
    case packetTypes.HEADERS:
      await this.handleHeaders(peer, packet);
      break;
    case packetTypes.SENDHEADERS:
      await this.handleSendHeaders(peer, packet);
      break;
    case packetTypes.BLOCK:
      await this.handleBlock(peer, packet);
      break;
    case packetTypes.TX:
      await this.handleTX(peer, packet);
      break;
    case packetTypes.REJECT:
      await this.handleReject(peer, packet);
      break;
    case packetTypes.MEMPOOL:
      await this.handleMempool(peer, packet);
      break;
    case packetTypes.FILTERLOAD:
      await this.handleFilterLoad(peer, packet);
      break;
    case packetTypes.FILTERADD:
      await this.handleFilterAdd(peer, packet);
      break;
    case packetTypes.FILTERCLEAR:
      await this.handleFilterClear(peer, packet);
      break;
    case packetTypes.MERKLEBLOCK:
      await this.handleMerkleBlock(peer, packet);
      break;
    case packetTypes.FEEFILTER:
      await this.handleFeeFilter(peer, packet);
      break;
    case packetTypes.SENDCMPCT:
      await this.handleSendCmpct(peer, packet);
      break;
    case packetTypes.CMPCTBLOCK:
      await this.handleCmpctBlock(peer, packet);
      break;
    case packetTypes.GETBLOCKTXN:
      await this.handleGetBlockTxn(peer, packet);
      break;
    case packetTypes.BLOCKTXN:
      await this.handleBlockTxn(peer, packet);
      break;
    case packetTypes.ENCINIT:
      await this.handleEncinit(peer, packet);
      break;
    case packetTypes.ENCACK:
      await this.handleEncack(peer, packet);
      break;
    case packetTypes.AUTHCHALLENGE:
      await this.handleAuthChallenge(peer, packet);
      break;
    case packetTypes.AUTHREPLY:
      await this.handleAuthReply(peer, packet);
      break;
    case packetTypes.AUTHPROPOSE:
      await this.handleAuthPropose(peer, packet);
      break;
    case packetTypes.UNKNOWN:
      await this.handleUnknown(peer, packet);
      break;
    default:
      assert(false, 'Bad packet type.');
      break;
  }

  this.emit('packet', packet, peer);
};

/**
 * Handle peer connect event.
 * @method
 * @private
 * @param {Peer} peer
 */

Pool.prototype.handleConnect = async function handleConnect(peer) {
  this.logger.info('Connected to %s.', peer.hostname());

  if (peer.outbound)
    this.hosts.markSuccess(peer.hostname());

  this.emit('peer connect', peer);
};

/**
 * Handle peer open event.
 * @method
 * @private
 * @param {Peer} peer
 */

Pool.prototype.handleOpen = async function handleOpen(peer) {
  // Advertise our address.
  if (!this.options.selfish && this.options.listen) {
    let addr = this.hosts.getLocal(peer.address);
    if (addr)
      peer.send(new packets.AddrPacket([addr]));
  }

  // We want compact blocks!
  if (this.options.compact)
    peer.sendCompact(this.options.blockMode);

  // Find some more peers.
  if (!this.hosts.isFull())
    peer.sendGetAddr();

  // Relay our spv filter if we have one.
  if (this.spvFilter)
    peer.sendFilterLoad(this.spvFilter);

  // Announce our currently broadcasted items.
  this.announceList(peer);

  // Set a fee rate filter.
  if (this.options.feeRate !== -1)
    peer.sendFeeRate(this.options.feeRate);

  // Start syncing the chain.
  if (peer.outbound)
    this.sendSync(peer);

  if (peer.outbound) {
    this.hosts.markAck(peer.hostname(), peer.services);

    // If we don't have an ack'd
    // loader yet consider it dead.
    if (!peer.loader) {
      if (this.peers.load && !this.peers.load.handshake) {
        assert(this.peers.load.loader);
        this.peers.load.loader = false;
        this.peers.load = null;
      }
    }

    // If we do not have a loader,
    // use this peer.
    if (!this.peers.load)
      this.setLoader(peer);
  }

  this.emit('peer open', peer);
};

/**
 * Handle peer close event.
 * @method
 * @private
 * @param {Peer} peer
 * @param {Boolean} connected
 */

Pool.prototype.handleClose = async function handleClose(peer, connected) {
  let outbound = peer.outbound;
  let loader = peer.loader;
  let size = peer.blockMap.size;

  this.removePeer(peer);

  if (loader) {
    this.logger.info('Removed loader peer (%s).', peer.hostname());
    if (this.checkpoints)
      this.resetChain();
  }

  this.nonces.remove(peer.hostname());

  this.emit('peer close', peer, connected);

  if (!this.loaded)
    return;

  if (this.disconnecting)
    return;

  if (this.chain.synced && size > 0) {
    this.logger.warning('Peer disconnected with requested blocks.');
    this.logger.warning('Resending sync...');
    this.forceSync();
  }

  if (!outbound)
    return;

  this.refill();
};

/**
 * Handle ban event.
 * @method
 * @private
 * @param {Peer} peer
 */

Pool.prototype.handleBan = async function handleBan(peer) {
  this.ban(peer.address);
  this.emit('ban', peer);
};

/**
 * Handle peer version event.
 * @method
 * @private
 * @param {Peer} peer
 * @param {VersionPacket} packet
 */

Pool.prototype.handleVersion = async function handleVersion(peer, packet) {
  this.logger.info(
    'Received version (%s): version=%d height=%d services=%s agent=%s',
    peer.hostname(),
    packet.version,
    packet.height,
    packet.services.toString(2),
    packet.agent);

  this.network.time.add(peer.hostname(), packet.ts);
  this.nonces.remove(peer.hostname());

  if (!peer.outbound && packet.remote.isRoutable())
    this.hosts.markLocal(packet.remote);
};

/**
 * Handle `verack` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {VerackPacket} packet
 */

Pool.prototype.handleVerack = async function handleVerack(peer, packet) {
  ;
};

/**
 * Handle `ping` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {PingPacket} packet
 */

Pool.prototype.handlePing = async function handlePing(peer, packet) {
  ;
};

/**
 * Handle `pong` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {PongPacket} packet
 */

Pool.prototype.handlePong = async function handlePong(peer, packet) {
  ;
};

/**
 * Handle `getaddr` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {GetAddrPacket} packet
 */

Pool.prototype.handleGetAddr = async function handleGetAddr(peer, packet) {
  let items = [];
  let addrs;

  if (this.options.selfish)
    return;

  if (peer.sentAddr) {
    this.logger.debug(
      'Ignoring repeated getaddr (%s).',
      peer.hostname());
    return;
  }

  peer.sentAddr = true;

  addrs = this.hosts.toArray();

  for (let addr of addrs) {
    if (!peer.addrFilter.added(addr.hostname, 'ascii'))
      continue;

    items.push(addr);

    if (items.length === 1000)
      break;
  }

  if (items.length === 0)
    return;

  this.logger.debug(
    'Sending %d addrs to peer (%s)',
    items.length,
    peer.hostname());

  peer.send(new packets.AddrPacket(items));
};

/**
 * Handle peer addr event.
 * @method
 * @private
 * @param {Peer} peer
 * @param {AddrPacket} packet
 */

Pool.prototype.handleAddr = async function handleAddr(peer, packet) {
  let addrs = packet.items;
  let now = this.network.now();
  let services = this.options.getRequiredServices();

  for (let addr of addrs) {
    peer.addrFilter.add(addr.hostname, 'ascii');

    if (!addr.isRoutable())
      continue;

    if (!addr.hasServices(services))
      continue;

    if (addr.ts <= 100000000 || addr.ts > now + 10 * 60)
      addr.ts = now - 5 * 24 * 60 * 60;

    if (addr.port === 0)
      continue;

    this.hosts.add(addr, peer.address);
  }

  this.logger.info(
    'Received %d addrs (hosts=%d, peers=%d) (%s).',
    addrs.length,
    this.hosts.size(),
    this.peers.size(),
    peer.hostname());

  this.fillOutbound();
};

/**
 * Handle `inv` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {InvPacket} packet
 */

Pool.prototype.handleInv = async function handleInv(peer, packet) {
  let unlock = await this.locker.lock();
  try {
    return await this._handleInv(peer, packet);
  } finally {
    unlock();
  }
};

/**
 * Handle `inv` packet (without a lock).
 * @method
 * @private
 * @param {Peer} peer
 * @param {InvPacket} packet
 */

Pool.prototype._handleInv = async function handleInv(peer, packet) {
  let items = packet.items;
  let blocks = [];
  let txs = [];
  let unknown = -1;

  if (items.length > 50000) {
    peer.increaseBan(100);
    return;
  }

  for (let item of items) {
    switch (item.type) {
      case invTypes.BLOCK:
        blocks.push(item.hash);
        break;
      case invTypes.TX:
        txs.push(item.hash);
        break;
      default:
        unknown = item.type;
        continue;
    }
    peer.invFilter.add(item.hash, 'hex');
  }

  this.logger.spam(
    'Received inv packet with %d items: blocks=%d txs=%d (%s).',
    items.length, blocks.length, txs.length, peer.hostname());

  if (unknown !== -1) {
    this.logger.warning(
      'Peer sent an unknown inv type: %d (%s).',
      unknown, peer.hostname());
  }

  if (blocks.length > 0)
    await this.handleBlockInv(peer, blocks);

  if (txs.length > 0)
    await this.handleTXInv(peer, txs);
};

/**
 * Handle `inv` packet from peer (containing only BLOCK types).
 * @method
 * @private
 * @param {Peer} peer
 * @param {Hash[]} hashes
 * @returns {Promise}
 */

Pool.prototype.handleBlockInv = async function handleBlockInv(peer, hashes) {
  let items = [];
  let hash, exists;

  assert(hashes.length > 0);

  if (!this.syncing)
    return;

  // Always keep track of the peer's best hash.
  if (!peer.loader || this.chain.synced) {
    hash = hashes[hashes.length - 1];
    peer.bestHash = hash;
  }

  // Ignore for now if we're still syncing
  if (!this.chain.synced && !peer.loader)
    return;

  if (this.options.hasWitness() && !peer.hasWitness())
    return;

  // Request headers instead.
  if (this.checkpoints)
    return;

  this.logger.debug(
    'Received %s block hashes from peer (%s).',
    hashes.length,
    peer.hostname());

  for (let i = 0; i < hashes.length; i++) {
    let hash = hashes[i];

    // Resolve orphan chain.
    if (this.chain.hasOrphan(hash)) {
      this.logger.debug('Received known orphan hash (%s).', peer.hostname());
      await this.resolveOrphan(peer, hash);
      continue;
    }

    // Request the block if we don't have it.
    if (!(await this.hasBlock(hash))) {
      items.push(hash);
      continue;
    }

    exists = hash;

    // Normally we request the hashContinue.
    // In the odd case where we already have
    // it, we can do one of two things: either
    // force re-downloading of the block to
    // continue the sync, or do a getblocks
    // from the last hash (this will reset
    // the hashContinue on the remote node).
    if (i === hashes.length - 1) {
      this.logger.debug('Received existing hash (%s).', peer.hostname());
      await this.getBlocks(peer, hash);
    }
  }

  // Attempt to update the peer's best height
  // with the last existing hash we know of.
  if (exists && this.chain.synced) {
    let height = await this.chain.db.getHeight(exists);
    if (height !== -1)
      peer.bestHeight = height;
  }

  this.getBlock(peer, items);
};

/**
 * Handle peer inv packet (txs).
 * @method
 * @private
 * @param {Peer} peer
 * @param {Hash[]} hashes
 */

Pool.prototype.handleTXInv = async function handleTXInv(peer, hashes) {
  assert(hashes.length > 0);

  if (this.syncing && !this.chain.synced)
    return;

  this.ensureTX(peer, hashes);
};

/**
 * Handle `getdata` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {GetDataPacket} packet
 */

Pool.prototype.handleGetData = async function handleGetData(peer, packet) {
  let items = packet.items;
  let notFound = [];
  let txs = 0;
  let blocks = 0;
  let compact = 0;
  let unknown = -1;

  if (items.length > 50000) {
    this.logger.warning('Peer sent inv with >50k items (%s).', peer.hostname());
    peer.increaseBan(100);
    peer.destroy();
    return;
  }

  for (let item of items) {
    if (item.isTX()) {
      let tx = await this.getItem(peer, item);

      if (!tx) {
        notFound.push(item);
        continue;
      }

      // Coinbases are an insta-ban from any node.
      // This should technically never happen, but
      // it's worth keeping here just in case. A
      // 24-hour ban from any node is rough.
      if (tx.isCoinbase()) {
        notFound.push(item);
        this.logger.warning('Failsafe: tried to relay a coinbase.');
        continue;
      }

      peer.send(new packets.TXPacket(tx, item.hasWitness()));

      txs++;

      continue;
    }

    switch (item.type) {
      case invTypes.BLOCK:
      case invTypes.WITNESS_BLOCK: {
        let result = await this.sendBlock(peer, item, item.hasWitness());
        if (!result) {
          notFound.push(item);
          continue;
        }
        blocks++;
        break;
      }
      case invTypes.FILTERED_BLOCK:
      case invTypes.WITNESS_FILTERED_BLOCK: {
        let block;

        if (!this.options.bip37) {
          this.logger.debug(
            'Peer requested a merkleblock without bip37 enabled (%s).',
            peer.hostname());
          peer.destroy();
          return;
        }

        if (!peer.spvFilter) {
          notFound.push(item);
          continue;
        }

        block = await this.getItem(peer, item);

        if (!block) {
          notFound.push(item);
          continue;
        }

        block = block.toMerkle(peer.spvFilter);

        peer.send(new packets.MerkleBlockPacket(block));

        for (let tx of block.txs) {
          peer.send(new packets.TXPacket(tx, item.hasWitness()));
          txs++;
        }

        blocks++;

        break;
      }
      case invTypes.CMPCT_BLOCK: {
        let height = await this.chain.db.getHeight(item.hash);
        let block;

        // Fallback to full block.
        if (height < this.chain.tip.height - 10) {
          let result = await this.sendBlock(peer, item, peer.compactWitness);
          if (!result) {
            notFound.push(item);
            continue;
          }
          blocks++;
          break;
        }

        block = await this.getItem(peer, item);

        if (!block) {
          notFound.push(item);
          continue;
        }

        peer.sendCompactBlock(block);

        blocks++;
        compact++;

        break;
      }
      default: {
        unknown = item.type;
        notFound.push(item);
        continue;
      }
    }

    if (item.hash === peer.hashContinue) {
      peer.sendInv([new InvItem(invTypes.BLOCK, this.chain.tip.hash)]);
      peer.hashContinue = null;
    }

    // Wait for the peer to read
    // before we pull more data
    // out of the database.
    await peer.drain();
  }

  if (notFound.length > 0)
    peer.send(new packets.NotFoundPacket(notFound));

  if (txs > 0) {
    this.logger.debug(
      'Served %d txs with getdata (notfound=%d) (%s).',
      txs, notFound.length, peer.hostname());
  }

  if (blocks > 0) {
    this.logger.debug(
      'Served %d blocks with getdata (notfound=%d, cmpct=%d) (%s).',
      blocks, notFound.length, compact, peer.hostname());
  }

  if (unknown !== -1) {
    this.logger.warning(
      'Peer sent an unknown getdata type: %s (%d).',
      unknown, peer.hostname());
  }
};

/**
 * Handle peer notfound packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {NotFoundPacket} packet
 */

Pool.prototype.handleNotFound = async function handleNotFound(peer, packet) {
  let items = packet.items;

  for (let item of items) {
    if (!this.resolveItem(peer, item)) {
      this.logger.warning(
        'Peer sent notfound for unrequested item: %s (%s).',
        item.hash, peer.hostname());
      peer.destroy();
      return;
    }
  }
};

/**
 * Handle `getblocks` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {GetBlocksPacket} packet
 */

Pool.prototype.handleGetBlocks = async function handleGetBlocks(peer, packet) {
  let blocks = [];
  let hash;

  if (!this.chain.synced)
    return;

  if (this.options.selfish)
    return;

  if (this.chain.options.spv)
    return;

  if (this.chain.options.prune)
    return;

  hash = await this.chain.findLocator(packet.locator);

  if (hash)
    hash = await this.chain.db.getNextHash(hash);

  while (hash) {
    blocks.push(new InvItem(invTypes.BLOCK, hash));

    if (hash === packet.stop)
      break;

    if (blocks.length === 500) {
      peer.hashContinue = hash;
      break;
    }

    hash = await this.chain.db.getNextHash(hash);
  }

  peer.sendInv(blocks);
};

/**
 * Handle `getheaders` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {GetHeadersPacket} packet
 */

Pool.prototype.handleGetHeaders = async function handleGetHeaders(peer, packet) {
  let headers = [];
  let hash, entry;

  if (!this.chain.synced)
    return;

  if (this.options.selfish)
    return;

  if (this.chain.options.spv)
    return;

  if (this.chain.options.prune)
    return;

  if (packet.locator.length > 0) {
    hash = await this.chain.findLocator(packet.locator);
    if (hash)
      hash = await this.chain.db.getNextHash(hash);
  } else {
    hash = packet.stop;
  }

  if (hash)
    entry = await this.chain.db.getEntry(hash);

  while (entry) {
    headers.push(entry.toHeaders());

    if (entry.hash === packet.stop)
      break;

    if (headers.length === 2000)
      break;

    entry = await entry.getNext();
  }

  peer.sendHeaders(headers);
};

/**
 * Handle `headers` packet from a given peer.
 * @method
 * @private
 * @param {Peer} peer
 * @param {HeadersPacket} packet
 * @returns {Promise}
 */

Pool.prototype.handleHeaders = async function handleHeaders(peer, packet) {
  let unlock = await this.locker.lock();
  try {
    return await this._handleHeaders(peer, packet);
  } finally {
    unlock();
  }
};

/**
 * Handle `headers` packet from
 * a given peer without a lock.
 * @method
 * @private
 * @param {Peer} peer
 * @param {HeadersPacket} packet
 * @returns {Promise}
 */

Pool.prototype._handleHeaders = async function handleHeaders(peer, packet) {
  let headers = packet.items;
  let checkpoint = false;
  let node;

  if (!this.checkpoints)
    return;

  if (!this.syncing)
    return;

  if (!peer.loader)
    return;

  if (headers.length === 0)
    return;

  if (headers.length > 2000) {
    peer.increaseBan(100);
    return;
  }

  assert(this.headerChain.size > 0);

  for (let header of headers) {
    let last = this.headerChain.tail;
    let hash = header.hash('hex');
    let height = last.height + 1;

    if (!header.verify()) {
      this.logger.warning(
        'Peer sent an invalid header (%s).',
        peer.hostname());
      peer.increaseBan(100);
      peer.destroy();
      return;
    }

    if (header.prevBlock !== last.hash) {
      this.logger.warning(
        'Peer sent a bad header chain (%s).',
        peer.hostname());

      if (++this.headerFails < Pool.MAX_HEADER_FAILS) {
        peer.destroy();
        return;
      }

      this.logger.warning(
        'Switching to getblocks (%s).',
        peer.hostname());

      await this.switchSync(peer);
      return;
    }

    node = new HeaderEntry(hash, height);

    if (node.height === this.headerTip.height) {
      if (node.hash !== this.headerTip.hash) {
        this.logger.warning(
          'Peer sent an invalid checkpoint (%s).',
          peer.hostname());

        if (++this.headerFails < Pool.MAX_HEADER_FAILS) {
          peer.destroy();
          return;
        }

        this.logger.warning(
          'Switching to getblocks (%s).',
          peer.hostname());

        await this.switchSync(peer);
        return;
      }
      checkpoint = true;
    }

    if (!this.headerNext)
      this.headerNext = node;

    this.headerChain.push(node);
  }

  this.logger.debug(
    'Received %s headers from peer (%s).',
    headers.length,
    peer.hostname());

  // If we received a valid header
  // chain, consider this a "block".
  peer.blockTime = util.ms();

  // Request the blocks we just added.
  if (checkpoint) {
    this.headerChain.shift();
    this.resolveHeaders(peer);
    return;
  }

  // Request more headers.
  peer.sendGetHeaders([node.hash], this.headerTip.hash);
};

/**
 * Handle `sendheaders` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {SendHeadersPacket} packet
 * @returns {Promise}
 */

Pool.prototype.handleSendHeaders = async function handleSendHeaders(peer, packet) {
  ;
};

/**
 * Handle `block` packet. Attempt to add to chain.
 * @method
 * @private
 * @param {Peer} peer
 * @param {BlockPacket} packet
 * @returns {Promise}
 */

Pool.prototype.handleBlock = async function handleBlock(peer, packet) {
  let flags = chainCommon.flags.DEFAULT_FLAGS;

  if (this.options.spv) {
    this.logger.warning(
      'Peer sent unsolicited block (%s).',
      peer.hostname());
    return;
  }

  return await this.addBlock(peer, packet.block, flags);
};

/**
 * Attempt to add block to chain.
 * @method
 * @private
 * @param {Peer} peer
 * @param {Block} block
 * @returns {Promise}
 */

Pool.prototype.addBlock = async function addBlock(peer, block, flags) {
  let hash = block.hash('hex');
  let unlock = await this.locker.lock(hash);
  try {
    return await this._addBlock(peer, block, flags);
  } finally {
    unlock();
  }
};

/**
 * Attempt to add block to chain (without a lock).
 * @method
 * @private
 * @param {Peer} peer
 * @param {Block} block
 * @returns {Promise}
 */

Pool.prototype._addBlock = async function addBlock(peer, block, flags) {
  let hash = block.hash('hex');
  let entry;

  if (!this.syncing)
    return;

  if (!this.resolveBlock(peer, hash)) {
    this.logger.warning(
      'Received unrequested block: %s (%s).',
      block.rhash(), peer.hostname());
    peer.destroy();
    return;
  }

  peer.blockTime = util.ms();

  try {
    entry = await this.chain.add(block, flags, peer.id);
  } catch (err) {
    if (err.type === 'VerifyError') {
      peer.reject('block', err);
      this.logger.warning(err);
      return;
    }
    throw err;
  }

  // Block was orphaned.
  if (!entry) {
    let height;

    if (this.checkpoints) {
      this.logger.warning(
        'Peer sent orphan block with getheaders (%s).',
        peer.hostname());
      return;
    }

    // During a getblocks sync, peers send
    // their best tip frequently. We can grab
    // the height commitment from the coinbase.
    height = block.getCoinbaseHeight();

    if (height !== -1) {
      peer.bestHash = hash;
      peer.bestHeight = height;
      this.resolveHeight(hash, height);
    }

    this.logger.debug('Peer sent an orphan block. Resolving.');

    await this.resolveOrphan(peer, hash);

    return;
  }

  if (this.chain.synced) {
    peer.bestHash = entry.hash;
    peer.bestHeight = entry.height;
    this.resolveHeight(entry.hash, entry.height);
  }

  this.logStatus(block);

  await this.resolveChain(peer, hash);
};

/**
 * Resolve header chain.
 * @method
 * @private
 * @param {Peer} peer
 * @param {Hash} hash
 * @returns {Promise}
 */

Pool.prototype.resolveChain = async function resolveChain(peer, hash) {
  let node = this.headerChain.head;

  if (!this.checkpoints)
    return;

  if (!peer.loader)
    return;

  if (peer.destroyed)
    throw new Error('Peer was destroyed (header chain resolution).');

  assert(node);

  if (hash !== node.hash) {
    this.logger.warning(
      'Header hash mismatch %s != %s (%s).',
      util.revHex(hash),
      util.revHex(node.hash),
      peer.hostname());

    peer.destroy();

    return;
  }

  if (node.height < this.network.lastCheckpoint) {
    if (node.height === this.headerTip.height) {
      this.logger.info(
        'Received checkpoint %s (%d).',
        util.revHex(node.hash), node.height);

      this.headerTip = this.getNextTip(node.height);

      peer.sendGetHeaders([hash], this.headerTip.hash);

      return;
    }

    this.headerChain.shift();
    this.resolveHeaders(peer);

    return;
  }

  this.logger.info(
    'Switching to getblocks (%s).',
    peer.hostname());

  await this.switchSync(peer, hash);
};

/**
 * Switch to getblocks.
 * @method
 * @private
 * @param {Peer} peer
 * @param {Hash} hash
 * @returns {Promise}
 */

Pool.prototype.switchSync = async function switchSync(peer, hash) {
  assert(this.checkpoints);

  this.checkpoints = false;
  this.chain.checkpoints = false;
  this.headerTip = null;
  this.headerChain.reset();
  this.headerNext = null;

  await this.getBlocks(peer, hash);
};

/**
 * Handle bad orphan.
 * @method
 * @private
 * @param {String} msg
 * @param {VerifyError} err
 * @param {Number} id
 */

Pool.prototype.handleBadOrphan = function handleBadOrphan(msg, err, id) {
  let peer = this.peers.find(id);

  if (!peer) {
    this.logger.warning(
      'Could not find offending peer for orphan: %s (%d).',
      util.revHex(err.hash), id);
    return;
  }

  this.logger.debug(
    'Punishing peer for sending a bad orphan (%s).',
    peer.hostname());

  // Punish the original peer who sent this.
  peer.reject(msg, err);
};

/**
 * Log sync status.
 * @private
 * @param {Block} block
 */

Pool.prototype.logStatus = function logStatus(block) {
  if (this.chain.height % 20 === 0) {
    this.logger.debug('Status:'
      + ' ts=%s height=%d progress=%s'
      + ' orphans=%d active=%d'
      + ' target=%s peers=%d',
      util.date(block.ts),
      this.chain.height,
      (this.chain.getProgress() * 100).toFixed(2) + '%',
      this.chain.orphanMap.size,
      this.blockMap.size,
      block.bits,
      this.peers.size());
  }

  if (this.chain.height % 2000 === 0) {
    this.logger.info(
      'Received 2000 more blocks (height=%d, hash=%s).',
      this.chain.height,
      block.rhash());
  }
};

/**
 * Handle a transaction. Attempt to add to mempool.
 * @method
 * @private
 * @param {Peer} peer
 * @param {TXPacket} packet
 * @returns {Promise}
 */

Pool.prototype.handleTX = async function handleTX(peer, packet) {
  let hash = packet.tx.hash('hex');
  let unlock = await this.locker.lock(hash);
  try {
    return await this._handleTX(peer, packet);
  } finally {
    unlock();
  }
};

/**
 * Handle a transaction. Attempt to add to mempool (without a lock).
 * @method
 * @private
 * @param {Peer} peer
 * @param {TXPacket} packet
 * @returns {Promise}
 */

Pool.prototype._handleTX = async function handleTX(peer, packet) {
  let tx = packet.tx;
  let hash = tx.hash('hex');
  let flags = chainCommon.flags.VERIFY_NONE;
  let block = peer.merkleBlock;
  let missing;

  if (block) {
    assert(peer.merkleMatches > 0);
    assert(peer.merkleMap);

    if (block.hasTX(hash)) {
      if (peer.merkleMap.has(hash)) {
        this.logger.warning(
          'Peer sent duplicate merkle tx: %s (%s).',
          tx.txid(), peer.hostname());
        peer.increaseBan(100);
        return;
      }

      peer.merkleMap.add(hash);

      block.addTX(tx);

      if (--peer.merkleMatches === 0) {
        peer.merkleBlock = null;
        peer.merkleTime = -1;
        peer.merkleMatches = 0;
        peer.merkleMap = null;
        await this._addBlock(peer, block, flags);
      }

      return;
    }
  }

  if (!this.resolveTX(peer, hash)) {
    this.logger.warning(
      'Peer sent unrequested tx: %s (%s).',
      tx.txid(), peer.hostname());
    peer.destroy();
    return;
  }

  if (!this.mempool) {
    this.emit('tx', tx);
    return;
  }

  try {
    missing = await this.mempool.addTX(tx, peer.id);
  } catch (err) {
    if (err.type === 'VerifyError') {
      peer.reject('tx', err);
      this.logger.info(err);
      return;
    }
    throw err;
  }

  if (missing && missing.length > 0) {
    this.logger.debug(
      'Requesting %d missing transactions (%s).',
      missing.length, peer.hostname());

    this.ensureTX(peer, missing);
  }
};

/**
 * Handle peer reject event.
 * @method
 * @private
 * @param {Peer} peer
 * @param {RejectPacket} packet
 */

Pool.prototype.handleReject = async function handleReject(peer, packet) {
  let entry;

  this.logger.warning(
    'Received reject (%s): msg=%s code=%s reason=%s hash=%s.',
    peer.hostname(),
    packet.message,
    packet.getCode(),
    packet.reason,
    packet.rhash());

  if (!packet.hash)
    return;

  entry = this.invMap.get(packet.hash);

  if (!entry)
    return;

  entry.handleReject(peer);
};

/**
 * Handle `mempool` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {MempoolPacket} packet
 */

Pool.prototype.handleMempool = async function handleMempool(peer, packet) {
  let items = [];

  if (!this.mempool)
    return;

  if (!this.chain.synced)
    return;

  if (this.options.selfish)
    return;

  if (!this.options.bip37) {
    this.logger.debug(
      'Peer requested mempool without bip37 enabled (%s).',
      peer.hostname());
    peer.destroy();
    return;
  }

  for (let hash of this.mempool.map.keys())
    items.push(new InvItem(invTypes.TX, hash));

  this.logger.debug(
    'Sending mempool snapshot (%s).',
    peer.hostname());

  peer.queueInv(items);
};

/**
 * Handle `filterload` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {FilterLoadPacket} packet
 */

Pool.prototype.handleFilterLoad = async function handleFilterLoad(peer, packet) {
  ;
};

/**
 * Handle `filteradd` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {FilterAddPacket} packet
 */

Pool.prototype.handleFilterAdd = async function handleFilterAdd(peer, packet) {
  ;
};

/**
 * Handle `filterclear` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {FilterClearPacket} packet
 */

Pool.prototype.handleFilterClear = async function handleFilterClear(peer, packet) {
  ;
};

/**
 * Handle `merkleblock` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {MerkleBlockPacket} block
 */

Pool.prototype.handleMerkleBlock = async function handleMerkleBlock(peer, packet) {
  let hash = packet.block.hash('hex');
  let unlock = await this.locker.lock(hash);
  try {
    return await this._handleMerkleBlock(peer, packet);
  } finally {
    unlock();
  }
};

/**
 * Handle `merkleblock` packet (without a lock).
 * @method
 * @private
 * @param {Peer} peer
 * @param {MerkleBlockPacket} block
 */

Pool.prototype._handleMerkleBlock = async function handleMerkleBlock(peer, packet) {
  let block = packet.block;
  let hash = block.hash('hex');
  let flags = chainCommon.flags.VERIFY_NONE;

  if (!this.syncing)
    return;

  // Potential DoS.
  if (!this.options.spv) {
    this.logger.warning(
      'Peer sent unsolicited merkleblock (%s).',
      peer.hostname());
    peer.increaseBan(100);
    return;
  }

  if (!peer.blockMap.has(hash)) {
    this.logger.warning(
      'Peer sent an unrequested merkleblock (%s).',
      peer.hostname());
    peer.destroy();
    return;
  }

  if (peer.merkleBlock) {
    this.logger.warning(
      'Peer sent a merkleblock prematurely (%s).',
      peer.hostname());
    peer.increaseBan(100);
    return;
  }

  if (!block.verify()) {
    this.logger.warning(
      'Peer sent an invalid merkleblock (%s).',
      peer.hostname());
    peer.increaseBan(100);
    return;
  }

  if (block.tree.matches.length === 0) {
    await this._addBlock(peer, block, flags);
    return;
  }

  peer.merkleBlock = block;
  peer.merkleTime = util.ms();
  peer.merkleMatches = block.tree.matches.length;
  peer.merkleMap = new Set();
};

/**
 * Handle `sendcmpct` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {FeeFilterPacket} packet
 */

Pool.prototype.handleFeeFilter = async function handleFeeFilter(peer, packet) {
  ;
};

/**
 * Handle `sendcmpct` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {SendCmpctPacket} packet
 */

Pool.prototype.handleSendCmpct = async function handleSendCmpct(peer, packet) {
  ;
};

/**
 * Handle `cmpctblock` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {CompactBlockPacket} packet
 */

Pool.prototype.handleCmpctBlock = async function handleCmpctBlock(peer, packet) {
  let block = packet.block;
  let hash = block.hash('hex');
  let witness = peer.compactWitness;
  let flags = chainCommon.flags.VERIFY_BODY;
  let result;

  if (!this.syncing)
    return;

  if (!this.options.compact) {
    this.logger.info(
      'Peer sent unsolicited cmpctblock (%s).',
      peer.hostname());
    this.destroy();
    return;
  }

  if (!peer.hasCompactSupport() || !peer.hasCompact()) {
    this.logger.info(
      'Peer sent unsolicited cmpctblock (%s).',
      peer.hostname());
    this.destroy();
    return;
  }

  if (peer.compactBlocks.has(hash)) {
    this.logger.debug(
      'Peer sent us a duplicate compact block (%s).',
      peer.hostname());
    return;
  }

  if (this.compactBlocks.has(hash)) {
    this.logger.debug(
      'Already waiting for compact block %s (%s).',
      hash, peer.hostname());
    return;
  }

  if (!peer.blockMap.has(hash)) {
    if (this.options.blockMode !== 1) {
      this.logger.warning(
        'Peer sent us an unrequested compact block (%s).',
        peer.hostname());
      peer.destroy();
      return;
    }
    peer.blockMap.set(hash, util.ms());
    assert(!this.blockMap.has(hash));
    this.blockMap.add(hash);
  }

  if (!this.mempool) {
    this.logger.warning('Requesting compact blocks without a mempool!');
    return;
  }

  if (!block.verify()) {
    this.logger.debug(
      'Peer sent an invalid compact block (%s).',
      peer.hostname());
    peer.increaseBan(100);
    return;
  }

  try {
    result = block.init();
  } catch (e) {
    this.logger.debug(
      'Peer sent an invalid compact block (%s).',
      peer.hostname());
    peer.increaseBan(100);
    return;
  }

  if (!result) {
    this.logger.warning(
      'Siphash collision for %s. Requesting full block (%s).',
      block.rhash(), peer.hostname());
    peer.getFullBlock(hash);
    peer.increaseBan(10);
    return;
  }

  result = block.fillMempool(witness, this.mempool);

  if (result) {
    this.logger.debug(
      'Received full compact block %s (%s).',
      block.rhash(), peer.hostname());
    await this.addBlock(peer, block.toBlock(), flags);
    return;
  }

  if (this.options.blockMode === 1) {
    if (peer.compactBlocks.size >= 15) {
      this.logger.warning('Compact block DoS attempt (%s).', peer.hostname());
      peer.destroy();
      return;
    }
  }

  block.now = util.ms();

  assert(!peer.compactBlocks.has(hash));
  peer.compactBlocks.set(hash, block);

  this.compactBlocks.add(hash);

  this.logger.debug(
    'Received non-full compact block %s tx=%d/%d (%s).',
    block.rhash(), block.count, block.totalTX, peer.hostname());

  peer.send(new packets.GetBlockTxnPacket(block.toRequest()));
};

/**
 * Handle `getblocktxn` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {GetBlockTxnPacket} packet
 */

Pool.prototype.handleGetBlockTxn = async function handleGetBlockTxn(peer, packet) {
  let req = packet.request;
  let res, item, block, height;

  if (this.chain.options.spv)
    return;

  if (this.chain.options.prune)
    return;

  if (this.options.selfish)
    return;

  item = new InvItem(invTypes.BLOCK, req.hash);

  block = await this.getItem(peer, item);

  if (!block) {
    this.logger.debug(
      'Peer sent getblocktxn for non-existent block (%s).',
      peer.hostname());
    peer.increaseBan(100);
    return;
  }

  height = await this.chain.db.getHeight(req.hash);

  if (height < this.chain.tip.height - 15) {
    this.logger.debug(
      'Peer sent a getblocktxn for a block > 15 deep (%s)',
      peer.hostname());
    return;
  }

  this.logger.debug(
    'Sending blocktxn for %s to peer (%s).',
    block.rhash(),
    peer.hostname());

  res = BIP152.TXResponse.fromBlock(block, req);

  peer.send(new packets.BlockTxnPacket(res, peer.compactWitness));
};

/**
 * Handle `blocktxn` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {BlockTxnPacket} packet
 */

Pool.prototype.handleBlockTxn = async function handleBlockTxn(peer, packet) {
  let res = packet.response;
  let block = peer.compactBlocks.get(res.hash);
  let flags = chainCommon.flags.VERIFY_BODY;

  if (!block) {
    this.logger.debug(
      'Peer sent unsolicited blocktxn (%s).',
      peer.hostname());
    return;
  }

  peer.compactBlocks.delete(res.hash);

  assert(this.compactBlocks.has(res.hash));
  this.compactBlocks.delete(res.hash);

  if (!block.fillMissing(res)) {
    this.logger.warning(
      'Peer sent non-full blocktxn for %s. Requesting full block (%s).',
      block.rhash(),
      peer.hostname());
    peer.getFullBlock(res.hash);
    peer.increaseBan(10);
    return;
  }

  this.logger.debug(
    'Filled compact block %s (%s).',
    block.rhash(), peer.hostname());

  await this.addBlock(peer, block.toBlock(), flags);
};

/**
 * Handle `encinit` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {EncinitPacket} packet
 */

Pool.prototype.handleEncinit = async function handleEncinit(peer, packet) {
  ;
};

/**
 * Handle `encack` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {EncackPacket} packet
 */

Pool.prototype.handleEncack = async function handleEncack(peer, packet) {
  ;
};

/**
 * Handle `authchallenge` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {AuthChallengePacket} packet
 */

Pool.prototype.handleAuthChallenge = async function handleAuthChallenge(peer, packet) {
  ;
};

/**
 * Handle `authreply` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {AuthReplyPacket} packet
 */

Pool.prototype.handleAuthReply = async function handleAuthReply(peer, packet) {
  ;
};

/**
 * Handle `authpropose` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {AuthProposePacket} packet
 */

Pool.prototype.handleAuthPropose = async function handleAuthPropose(peer, packet) {
  ;
};

/**
 * Handle `unknown` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {UnknownPacket} packet
 */

Pool.prototype.handleUnknown = async function handleUnknown(peer, packet) {
  this.logger.warning(
    'Unknown packet: %s (%s).',
    packet.cmd, peer.hostname());
};

/**
 * Create an inbound peer from an existing socket.
 * @private
 * @param {net.Socket} socket
 */

Pool.prototype.addInbound = function addInbound(socket) {
  let peer;

  if (!this.loaded) {
    socket.destroy();
    return;
  }

  peer = this.createInbound(socket);

  this.logger.info('Added inbound peer (%s).', peer.hostname());

  this.peers.add(peer);
};

/**
 * Allocate a host from the host list.
 * @returns {NetAddress}
 */

Pool.prototype.getHost = function getHost() {
  let services = this.options.getRequiredServices();
  let now = this.network.now();

  for (let addr of this.hosts.nodes) {
    if (this.peers.has(addr.hostname))
      continue;

    return addr;
  }

  for (let i = 0; i < 100; i++) {
    let entry = this.hosts.getHost();
    let addr;

    if (!entry)
      break;

    addr = entry.addr;

    if (this.peers.has(addr.hostname))
      continue;

    if (!addr.isValid())
      continue;

    if (!addr.hasServices(services))
      continue;

    if (!this.options.onion && addr.isOnion())
      continue;

    if (i < 30 && now - entry.lastAttempt < 600)
      continue;

    if (i < 50 && addr.port !== this.network.port)
      continue;

    if (i < 95 && this.hosts.isBanned(addr.host))
      continue;

    return entry.addr;
  }
};

/**
 * Create an outbound non-loader peer. These primarily
 * exist for transaction relaying.
 * @private
 */

Pool.prototype.addOutbound = function addOutbound() {
  let peer, addr;

  if (!this.loaded)
    return;

  if (this.peers.outbound >= this.options.maxOutbound)
    return;

  // Hang back if we don't
  // have a loader peer yet.
  if (!this.peers.load)
    return;

  addr = this.getHost();

  if (!addr)
    return;

  peer = this.createOutbound(addr);

  this.peers.add(peer);

  this.emit('peer', peer);
};

/**
 * Attempt to refill the pool with peers (no lock).
 * @private
 */

Pool.prototype.fillOutbound = function fillOutbound() {
  let need = this.options.maxOutbound - this.peers.outbound;

  if (!this.peers.load)
    this.addLoader();

  if (need <= 0)
    return;

  this.logger.debug('Refilling peers (%d/%d).',
    this.peers.outbound,
    this.options.maxOutbound);

  for (let i = 0; i < need; i++)
    this.addOutbound();
};

/**
 * Attempt to refill the pool with peers (no lock).
 * @private
 */

Pool.prototype.refill = function refill() {
  if (this.pendingRefill != null)
    return;

  this.pendingRefill = setTimeout(() => {
    this.pendingRefill = null;
    this.fillOutbound();
  }, 3000);
};

/**
 * Remove a peer from any list. Drop all load requests.
 * @private
 * @param {Peer} peer
 */

Pool.prototype.removePeer = function removePeer(peer) {
  this.peers.remove(peer);

  for (let hash of peer.blockMap.keys())
    this.resolveBlock(peer, hash);

  for (let hash of peer.txMap.keys())
    this.resolveTX(peer, hash);

  for (let hash of peer.compactBlocks.keys()) {
    assert(this.compactBlocks.has(hash));
    this.compactBlocks.delete(hash);
  }

  peer.compactBlocks.clear();
};

/**
 * Ban peer.
 * @param {NetAddress} addr
 */

Pool.prototype.ban = function ban(addr) {
  let peer = this.peers.get(addr.hostname);

  this.logger.debug('Banning peer (%s).', addr.hostname);

  this.hosts.ban(addr.host);
  this.hosts.remove(addr.hostname);

  if (peer)
    peer.destroy();
};

/**
 * Unban peer.
 * @param {NetAddress} addr
 */

Pool.prototype.unban = function unban(addr) {
  this.hosts.unban(addr.host);
};

/**
 * Set the spv filter.
 * @param {Bloom} filter
 * @param {String?} enc
 */

Pool.prototype.setFilter = function setFilter(filter) {
  if (!this.options.spv)
    return;

  this.spvFilter = filter;
  this.queueFilterLoad();
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
  this.queueFilterLoad();
};

/**
 * Reset the spv filter (filterload, SPV-only).
 */

Pool.prototype.unwatch = function unwatch() {
  if (!this.options.spv)
    return;

  this.spvFilter.reset();
  this.queueFilterLoad();
};

/**
 * Queue a resend of the bloom filter.
 */

Pool.prototype.queueFilterLoad = function queueFilterLoad() {
  if (!this.options.spv)
    return;

  if (this.pendingFilter != null)
    return;

  this.pendingFilter = setTimeout(() => {
    this.pendingFilter = null;
    this.sendFilterLoad();
  }, 100);
};

/**
 * Resend the bloom filter to peers.
 */

Pool.prototype.sendFilterLoad = function sendFilterLoad() {
  if (!this.options.spv)
    return;

  assert(this.spvFilter);

  for (let peer = this.peers.head(); peer; peer = peer.next)
    peer.sendFilterLoad(this.spvFilter);
};

/**
 * Add an address to the bloom filter (SPV-only).
 * @param {Address|Base58Address} address
 */

Pool.prototype.watchAddress = function watchAddress(address) {
  let hash = Address.getHash(address);
  this.watch(hash);
};

/**
 * Add an outpoint to the bloom filter (SPV-only).
 * @param {Outpoint} outpoint
 */

Pool.prototype.watchOutpoint = function watchOutpoint(outpoint) {
  this.watch(outpoint.toRaw());
};

/**
 * Send `getblocks` to peer after building
 * locator and resolving orphan root.
 * @method
 * @param {Peer} peer
 * @param {Hash} orphan - Orphan hash to resolve.
 * @returns {Promise}
 */

Pool.prototype.resolveOrphan = async function resolveOrphan(peer, orphan) {
  let locator = await this.chain.getLocator();
  let root = this.chain.getOrphanRoot(orphan);

  assert(root);

  peer.sendGetBlocks(locator, root);
};

/**
 * Send `getheaders` to peer after building locator.
 * @method
 * @param {Peer} peer
 * @param {Hash} tip - Tip to build chain locator from.
 * @param {Hash?} stop
 * @returns {Promise}
 */

Pool.prototype.getHeaders = async function getHeaders(peer, tip, stop) {
  let locator = await this.chain.getLocator(tip);
  peer.sendGetHeaders(locator, stop);
};

/**
 * Send `getblocks` to peer after building locator.
 * @method
 * @param {Peer} peer
 * @param {Hash} tip - Tip hash to build chain locator from.
 * @param {Hash?} stop
 * @returns {Promise}
 */

Pool.prototype.getBlocks = async function getBlocks(peer, tip, stop) {
  let locator = await this.chain.getLocator(tip);
  peer.sendGetBlocks(locator, stop);
};

/**
 * Queue a `getdata` request to be sent.
 * @param {Peer} peer
 * @param {Hash[]} hashes
 */

Pool.prototype.getBlock = function getBlock(peer, hashes) {
  let now = util.ms();
  let items = [];

  if (!this.loaded)
    return;

  if (!peer.handshake)
    throw new Error('Peer handshake not complete (getdata).');

  if (peer.destroyed)
    throw new Error('Peer is destroyed (getdata).');

  for (let hash of hashes) {
    if (this.blockMap.has(hash))
      continue;

    this.blockMap.add(hash);
    peer.blockMap.set(hash, now);

    if (this.chain.synced)
      now += 100;

    items.push(hash);
  }

  if (items.length === 0)
    return;

  this.logger.debug(
    'Requesting %d/%d blocks from peer with getdata (%s).',
    items.length,
    this.blockMap.size,
    peer.hostname());

  peer.getBlock(items);
};

/**
 * Queue a `getdata` request to be sent.
 * @param {Peer} peer
 * @param {Hash[]} hashes
 */

Pool.prototype.getTX = function getTX(peer, hashes) {
  let now = util.ms();
  let items = [];

  if (!this.loaded)
    return;

  if (!peer.handshake)
    throw new Error('Peer handshake not complete (getdata).');

  if (peer.destroyed)
    throw new Error('Peer is destroyed (getdata).');

  for (let hash of hashes) {
    if (this.txMap.has(hash))
      continue;

    this.txMap.add(hash);
    peer.txMap.set(hash, now);

    now += 50;

    items.push(hash);
  }

  if (items.length === 0)
    return;

  this.logger.debug(
    'Requesting %d/%d txs from peer with getdata (%s).',
    items.length,
    this.txMap.size,
    peer.hostname());

  peer.getTX(items);
};

/**
 * Test whether the chain has or has seen an item.
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

Pool.prototype.hasBlock = async function hasBlock(hash) {
  // Check the lock.
  if (this.locker.has(hash))
    return true;

  // Check the chain.
  if (await this.chain.has(hash))
    return true;

  return false;
};

/**
 * Test whether the mempool has or has seen an item.
 * @param {Hash} hash
 * @returns {Boolean}
 */

Pool.prototype.hasTX = function hasTX(hash) {
  // Check the lock queue.
  if (this.locker.has(hash))
    return true;

  if (!this.mempool) {
    // Check the TX filter if
    // we don't have a mempool.
    if (!this.txFilter.added(hash, 'hex'))
      return true;
  } else {
    // Check the mempool.
    if (this.mempool.has(hash))
      return true;

    // If we recently rejected this item. Ignore.
    if (this.mempool.hasReject(hash)) {
      this.logger.spam('Saw known reject of %s.', util.revHex(hash));
      return true;
    }
  }

  return false;
};

/**
 * Queue a `getdata` request to be sent.
 * Check tx existence before requesting.
 * @param {Peer} peer
 * @param {Hash[]} hashes
 */

Pool.prototype.ensureTX = function ensureTX(peer, hashes) {
  let items = [];

  for (let hash of hashes) {
    if (this.hasTX(hash))
      continue;

    items.push(hash);
  }

  this.getTX(peer, items);
};

/**
 * Fulfill a requested tx.
 * @param {Peer} peer
 * @param {Hash} hash
 * @returns {Boolean}
 */

Pool.prototype.resolveTX = function resolveTX(peer, hash) {
  if (!peer.txMap.has(hash))
    return false;

  peer.txMap.delete(hash);

  assert(this.txMap.has(hash));
  this.txMap.delete(hash);

  return true;
};

/**
 * Fulfill a requested block.
 * @param {Peer} peer
 * @param {Hash} hash
 * @returns {Boolean}
 */

Pool.prototype.resolveBlock = function resolveBlock(peer, hash) {
  if (!peer.blockMap.has(hash))
    return false;

  peer.blockMap.delete(hash);

  assert(this.blockMap.has(hash));
  this.blockMap.delete(hash);

  return true;
};

/**
 * Fulfill a requested item.
 * @param {Peer} peer
 * @param {InvItem} item
 * @returns {Boolean}
 */

Pool.prototype.resolveItem = function resolveItem(peer, item) {
  if (item.isBlock())
    return this.resolveBlock(peer, item.hash);

  if (item.isTX())
    return this.resolveTX(peer, item.hash);

  return false;
};

/**
 * Broadcast a transaction or block.
 * @param {TX|Block} msg
 * @returns {Promise}
 */

Pool.prototype.broadcast = function broadcast(msg) {
  let hash = msg.hash('hex');
  let item = this.invMap.get(hash);

  if (item) {
    item.refresh();
    item.announce();
  } else {
    item = new BroadcastItem(this, msg);
    item.start();
    item.announce();
  }

  return new Promise((resolve, reject) => {
    item.addJob(resolve, reject);
  });
};

/**
 * Announce a block to all peers.
 * @param {Block} tx
 */

Pool.prototype.announceBlock = function announceBlock(msg) {
  for (let peer = this.peers.head(); peer; peer = peer.next)
    peer.announceBlock(msg);
};

/**
 * Announce a transaction to all peers.
 * @param {TX} tx
 */

Pool.prototype.announceTX = function announceTX(msg) {
  for (let peer = this.peers.head(); peer; peer = peer.next)
    peer.announceTX(msg);
};

/**
 * PoolOptions
 * @alias module:net.PoolOptions
 * @constructor
 */

function PoolOptions(options) {
  if (!(this instanceof PoolOptions))
    return new PoolOptions(options);

  this.network = Network.primary;
  this.logger = null;
  this.chain = null;
  this.mempool = null;

  this.nonces = new NonceList();

  this.prefix = null;
  this.checkpoints = true;
  this.spv = false;
  this.bip37 = false;
  this.listen = false;
  this.compact = true;
  this.noRelay = false;
  this.host = '0.0.0.0';
  this.port = this.network.port;
  this.publicHost = '0.0.0.0';
  this.publicPort = this.network.port;
  this.maxOutbound = 8;
  this.maxInbound = 8;
  this.createSocket = this._createSocket.bind(this);
  this.createServer = tcp.createServer;
  this.resolve = this._resolve.bind(this);
  this.proxy = null;
  this.onion = false;
  this.upnp = false;
  this.selfish = false;
  this.version = common.PROTOCOL_VERSION;
  this.agent = common.USER_AGENT;
  this.bip151 = false;
  this.bip150 = false;
  this.authPeers = [];
  this.knownPeers = {};
  this.identityKey = secp256k1.generatePrivateKey();
  this.banScore = common.BAN_SCORE;
  this.banTime = common.BAN_TIME;
  this.feeRate = -1;
  this.seeds = this.network.seeds;
  this.nodes = [];
  this.invTimeout = 60000;
  this.blockMode = 0;
  this.services = common.LOCAL_SERVICES;
  this.requiredServices = common.REQUIRED_SERVICES;
  this.persistent = false;

  this.fromOptions(options);
}

/**
 * Inject properties from object.
 * @private
 * @param {Object} options
 * @returns {PoolOptions}
 */

PoolOptions.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'Pool requires options.');
  assert(options.chain && typeof options.chain === 'object',
    'Pool options require a blockchain.');

  this.chain = options.chain;
  this.network = options.chain.network;
  this.logger = options.chain.logger;

  this.port = this.network.port;
  this.seeds = this.network.seeds;
  this.port = this.network.port;
  this.publicPort = this.network.port;

  if (options.logger != null) {
    assert(typeof options.logger === 'object');
    this.logger = options.logger;
  }

  if (options.mempool != null) {
    assert(typeof options.mempool === 'object');
    this.mempool = options.mempool;
  }

  if (options.prefix != null) {
    assert(typeof options.prefix === 'string');
    this.prefix = options.prefix;
  }

  if (options.checkpoints != null) {
    assert(typeof options.checkpoints === 'boolean');
    assert(options.checkpoints === this.chain.options.checkpoints);
    this.checkpoints = options.checkpoints;
  } else {
    this.checkpoints = this.chain.options.checkpoints;
  }

  if (options.spv != null) {
    assert(typeof options.spv === 'boolean');
    assert(options.spv === this.chain.options.spv);
    this.spv = options.spv;
  } else {
    this.spv = this.chain.options.spv;
  }

  if (options.bip37 != null) {
    assert(typeof options.bip37 === 'boolean');
    this.bip37 = options.bip37;
  }

  if (options.listen != null) {
    assert(typeof options.listen === 'boolean');
    this.listen = options.listen;
  }

  if (options.compact != null) {
    assert(typeof options.compact === 'boolean');
    this.compact = options.compact;
  }

  if (options.noRelay != null) {
    assert(typeof options.noRelay === 'boolean');
    this.noRelay = options.noRelay;
  }

  if (options.host != null) {
    assert(typeof options.host === 'string');
    let raw = IP.toBuffer(options.host);
    this.host = IP.toString(raw);
    if (IP.isRoutable(raw))
      this.publicHost = this.host;
  }

  if (options.port != null) {
    assert(typeof options.port === 'number');
    assert(options.port > 0 && options.port <= 0xffff);
    this.port = options.port;
    this.publicPort = options.port;
  }

  if (options.publicHost != null) {
    assert(typeof options.publicHost === 'string');
    this.publicHost = IP.normalize(options.publicHost);
  }

  if (options.publicPort != null) {
    assert(typeof options.publicPort === 'number');
    assert(options.publicPort > 0 && options.publicPort <= 0xffff);
    this.publicPort = options.publicPort;
  }

  if (options.maxOutbound != null) {
    assert(typeof options.maxOutbound === 'number');
    assert(options.maxOutbound > 0);
    this.maxOutbound = options.maxOutbound;
  }

  if (options.maxInbound != null) {
    assert(typeof options.maxInbound === 'number');
    this.maxInbound = options.maxInbound;
  }

  if (options.createSocket) {
    assert(typeof options.createSocket === 'function');
    this.createSocket = options.createSocket;
  }

  if (options.createServer) {
    assert(typeof options.createServer === 'function');
    this.createServer = options.createServer;
  }

  if (options.resolve) {
    assert(typeof options.resolve === 'function');
    this.resolve = options.resolve;
  }

  if (options.proxy) {
    assert(typeof options.proxy === 'string');
    this.proxy = options.proxy;
  }

  if (options.onion != null) {
    assert(typeof options.onion === 'boolean');
    this.onion = options.onion;
  }

  if (options.upnp != null) {
    assert(typeof options.upnp === 'boolean');
    this.upnp = options.upnp;
  }

  if (options.selfish) {
    assert(typeof options.selfish === 'boolean');
    this.selfish = options.selfish;
  }

  if (options.version) {
    assert(typeof options.version === 'number');
    this.version = options.version;
  }

  if (options.agent) {
    assert(typeof options.agent === 'string');
    assert(options.agent.length <= 255);
    this.agent = options.agent;
  }

  if (options.bip151 != null) {
    assert(typeof options.bip151 === 'boolean');
    this.bip151 = options.bip151;
  }

  if (options.bip150 != null) {
    assert(typeof options.bip150 === 'boolean');
    assert(!options.bip150 || this.bip151,
      'Cannot enable bip150 without bip151.');

    if (options.knownPeers) {
      assert(typeof options.knownPeers === 'object');
      assert(!Array.isArray(options.knownPeers));
      this.knownPeers = options.knownPeers;
    }

    if (options.authPeers) {
      assert(Array.isArray(options.authPeers));
      this.authPeers = options.authPeers;
    }

    if (options.identityKey) {
      assert(Buffer.isBuffer(options.identityKey),
        'Identity key must be a buffer.');
      assert(secp256k1.privateKeyVerify(options.identityKey),
        'Invalid identity key.');
      this.identityKey = options.identityKey;
    }
  }

  if (options.banScore != null) {
    assert(typeof this.options.banScore === 'number');
    this.banScore = this.options.banScore;
  }

  if (options.banTime != null) {
    assert(typeof this.options.banTime === 'number');
    this.banTime = this.options.banTime;
  }

  if (options.feeRate != null) {
    assert(typeof this.options.feeRate === 'number');
    this.feeRate = this.options.feeRate;
  }

  if (options.seeds) {
    assert(Array.isArray(options.seeds));
    this.seeds = options.seeds;
  }

  if (options.nodes) {
    assert(Array.isArray(options.nodes));
    this.nodes = options.nodes;
  }

  if (options.only != null) {
    assert(Array.isArray(options.only));
    if (options.only.length > 0) {
      this.nodes = options.only;
      this.maxOutbound = options.only.length;
    }
  }

  if (options.invTimeout != null) {
    assert(typeof options.invTimeout === 'number');
    this.invTimeout = options.invTimeout;
  }

  if (options.blockMode != null) {
    assert(typeof options.blockMode === 'number');
    this.blockMode = options.blockMode;
  }

  if (options.persistent != null) {
    assert(typeof options.persistent === 'boolean');
    this.persistent = options.persistent;
  }

  if (this.spv) {
    this.requiredServices |= common.services.BLOOM;
    this.services &= ~common.services.NETWORK;
    this.noRelay = true;
    this.checkpoints = true;
    this.compact = false;
    this.bip37 = false;
    this.listen = false;
  }

  if (this.selfish) {
    this.services &= ~common.services.NETWORK;
    this.bip37 = false;
  }

  if (this.bip37)
    this.services |= common.services.BLOOM;

  if (this.proxy)
    this.listen = false;

  if (options.services != null) {
    assert(util.isUInt32(options.services));
    this.services = options.services;
  }

  if (options.requiredServices != null) {
    assert(util.isUInt32(options.requiredServices));
    this.requiredServices = options.requiredServices;
  }

  return this;
};

/**
 * Instantiate options from object.
 * @param {Object} options
 * @returns {PoolOptions}
 */

PoolOptions.fromOptions = function fromOptions(options) {
  return new PoolOptions().fromOptions(options);
};

/**
 * Get the chain height.
 * @private
 * @returns {Number}
 */

PoolOptions.prototype.getHeight = function getHeight() {
  return this.chain.height;
};

/**
 * Test whether the chain is synced.
 * @private
 * @returns {Boolean}
 */

PoolOptions.prototype.isFull = function isFull() {
  return this.chain.synced;
};

/**
 * Get required services for outbound peers.
 * @private
 * @returns {Number}
 */

PoolOptions.prototype.getRequiredServices = function getRequiredServices() {
  let services = this.requiredServices;
  if (this.hasWitness())
    services |= common.services.WITNESS;
  return services;
};

/**
 * Whether segwit is enabled.
 * @private
 * @returns {Boolean}
 */

PoolOptions.prototype.hasWitness = function hasWitness() {
  return this.chain.state.hasWitness();
};

/**
 * Create a version packet nonce.
 * @private
 * @param {String} hostname
 * @returns {Buffer}
 */

PoolOptions.prototype.createNonce = function createNonce(hostname) {
  return this.nonces.alloc(hostname);
};

/**
 * Test whether version nonce is ours.
 * @private
 * @param {Buffer} nonce
 * @returns {Boolean}
 */

PoolOptions.prototype.hasNonce = function hasNonce(nonce) {
  return this.nonces.has(nonce);
};

/**
 * Get fee rate for txid.
 * @private
 * @param {Hash} hash
 * @returns {Rate}
 */

PoolOptions.prototype.getRate = function getRate(hash) {
  let entry;

  if (!this.mempool)
    return -1;

  entry = this.mempool.getEntry(hash);

  if (!entry)
    return -1;

  return entry.getRate();
};

/**
 * Default createSocket call.
 * @private
 * @param {Number} port
 * @param {String} host
 * @returns {net.Socket}
 */

PoolOptions.prototype._createSocket = function createSocket(port, host) {
  return tcp.createSocket(port, host, this.proxy);
};

/**
 * Default resolve call.
 * @private
 * @param {String} name
 * @returns {String[]}
 */

PoolOptions.prototype._resolve = function resolve(name) {
  if (this.onion)
    return dns.lookup(name, this.proxy);

  return dns.lookup(name);
};

/**
 * Peer List
 * @alias module:net.PeerList
 * @constructor
 * @param {Object} options
 */

function PeerList() {
  this.map = new Map();
  this.ids = new Map();
  this.list = new List();
  this.load = null;
  this.inbound = 0;
  this.outbound = 0;
}

/**
 * Get the list head.
 * @returns {Peer}
 */

PeerList.prototype.head = function head() {
  return this.list.head;
};

/**
 * Get the list tail.
 * @returns {Peer}
 */

PeerList.prototype.tail = function tail() {
  return this.list.tail;
};

/**
 * Get list size.
 * @returns {Number}
 */

PeerList.prototype.size = function size() {
  return this.list.size;
};

/**
 * Add peer to list.
 * @param {Peer} peer
 */

PeerList.prototype.add = function add(peer) {
  assert(this.list.push(peer));

  assert(!this.map.has(peer.hostname()));
  this.map.set(peer.hostname(), peer);

  assert(!this.ids.has(peer.id));
  this.ids.set(peer.id, peer);

  if (peer.outbound)
    this.outbound++;
  else
    this.inbound++;
};

/**
 * Remove peer from list.
 * @param {Peer} peer
 */

PeerList.prototype.remove = function remove(peer) {
  assert(this.list.remove(peer));

  assert(this.ids.has(peer.id));
  this.ids.delete(peer.id);

  assert(this.map.has(peer.hostname()));
  this.map.delete(peer.hostname());

  if (peer === this.load) {
    assert(peer.loader);
    peer.loader = false;
    this.load = null;
  }

  if (peer.outbound)
    this.outbound--;
  else
    this.inbound--;
};

/**
 * Get peer by hostname.
 * @param {String} hostname
 * @returns {Peer}
 */

PeerList.prototype.get = function get(hostname) {
  return this.map.get(hostname);
};

/**
 * Test whether a peer exists.
 * @param {String} hostname
 * @returns {Boolean}
 */

PeerList.prototype.has = function has(hostname) {
  return this.map.has(hostname);
};

/**
 * Get peer by ID.
 * @param {Number} id
 * @returns {Peer}
 */

PeerList.prototype.find = function find(id) {
  return this.ids.get(id);
};

/**
 * Destroy peer list (kills peers).
 */

PeerList.prototype.destroy = function destroy() {
  let next;

  for (let peer = this.list.head; peer; peer = next) {
    next = peer.next;
    peer.destroy();
  }
};

/**
 * Represents an item that is broadcasted via an inv/getdata cycle.
 * @alias module:net.BroadcastItem
 * @constructor
 * @private
 * @param {Pool} pool
 * @param {TX|Block} msg
 * @emits BroadcastItem#ack
 * @emits BroadcastItem#reject
 * @emits BroadcastItem#timeout
 */

function BroadcastItem(pool, msg) {
  let item;

  if (!(this instanceof BroadcastItem))
    return new BroadcastItem(pool, msg);

  assert(!msg.mutable, 'Cannot broadcast mutable item.');

  item = msg.toInv();

  this.pool = pool;
  this.hash = item.hash;
  this.type = item.type;
  this.msg = msg;
  this.jobs = [];
}

util.inherits(BroadcastItem, EventEmitter);

/**
 * Add a job to be executed on ack, timeout, or reject.
 * @returns {Promise}
 */

BroadcastItem.prototype.addJob = function addJob(resolve, reject) {
  this.jobs.push(co.job(resolve, reject));
};

/**
 * Start the broadcast.
 */

BroadcastItem.prototype.start = function start() {
  assert(!this.timeout, 'Already started.');
  assert(!this.pool.invMap.has(this.hash), 'Already started.');

  this.pool.invMap.set(this.hash, this);

  this.refresh();

  return this;
};

/**
 * Refresh the timeout on the broadcast.
 */

BroadcastItem.prototype.refresh = function refresh() {
  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }

  this.timeout = setTimeout(() => {
    this.emit('timeout');
    this.reject(new Error('Timed out.'));
  }, this.pool.options.invTimeout);
};

/**
 * Announce the item.
 */

BroadcastItem.prototype.announce = function announce() {
  switch (this.type) {
    case invTypes.TX:
      this.pool.announceTX(this.msg);
      break;
    case invTypes.BLOCK:
      this.pool.announceBlock(this.msg);
      break;
    default:
      assert(false, 'Bad type.');
      break;
  }
};

/**
 * Finish the broadcast.
 */

BroadcastItem.prototype.cleanup = function cleanup() {
  assert(this.timeout != null, 'Already finished.');
  assert(this.pool.invMap.has(this.hash), 'Already finished.');

  clearTimeout(this.timeout);
  this.timeout = null;

  this.pool.invMap.delete(this.hash);
};

/**
 * Finish the broadcast, return with an error.
 * @param {Error} err
 */

BroadcastItem.prototype.reject = function reject(err) {
  this.cleanup();

  for (let job of this.jobs)
    job.reject(err);

  this.jobs.length = 0;
};

/**
 * Finish the broadcast successfully.
 */

BroadcastItem.prototype.resolve = function resolve() {
  this.cleanup();

  for (let job of this.jobs)
    job.resolve(false);

  this.jobs.length = 0;
};

/**
 * Handle an ack from a peer.
 * @param {Peer} peer
 */

BroadcastItem.prototype.handleAck = function handleAck(peer) {
  setTimeout(() => {
    this.emit('ack', peer);

    for (let job of this.jobs)
      job.resolve(true);

    this.jobs.length = 0;
  }, 1000);
};

/**
 * Handle a reject from a peer.
 * @param {Peer} peer
 */

BroadcastItem.prototype.handleReject = function handleReject(peer) {
  this.emit('reject', peer);

  for (let job of this.jobs)
    job.resolve(false);

  this.jobs.length = 0;
};

/**
 * Inspect the broadcast item.
 * @returns {String}
 */

BroadcastItem.prototype.inspect = function inspect() {
  let type = this.type === invTypes.TX ? 'tx' : 'block';
  let hash = util.revHex(this.hash);
  return `<BroadcastItem: type=${type} hash=${hash}>`;
};

/**
 * NonceList
 * @constructor
 * @ignore
 */

function NonceList() {
  this.map = new Map();
  this.hosts = new Map();
}

NonceList.prototype.alloc = function alloc(hostname) {
  let nonce, key;

  for (;;) {
    nonce = util.nonce();
    key = nonce.toString('hex');
    if (!this.map.has(key)) {
      this.map.set(key, hostname);
      assert(!this.hosts.has(hostname));
      this.hosts.set(hostname, key);
      break;
    }
  }

  return nonce;
};

NonceList.prototype.has = function has(nonce) {
  let key = nonce.toString('hex');
  return this.map.has(key);
};

NonceList.prototype.remove = function remove(hostname) {
  let key = this.hosts.get(hostname);

  if (!key)
    return false;

  this.hosts.delete(hostname);

  assert(this.map.has(key));
  this.map.delete(key);

  return true;
};

/**
 * HeaderEntry
 * @constructor
 * @ignore
 */

function HeaderEntry(hash, height) {
  this.hash = hash;
  this.height = height;
  this.prev = null;
  this.next = null;
}

/*
 * Expose
 */

module.exports = Pool;
