/*!
 * pool.js - peer management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const {Lock} = require('bmutex');
const IP = require('binet');
const dns = require('bdns');
const tcp = require('btcp');
const UPNP = require('bupnp');
const socks = require('bsocks');
const List = require('blst');
const {BloomFilter, RollingFilter} = require('bfilter');
const secp256k1 = require('bcrypto/lib/secp256k1');
const util = require('../utils/util');
const common = require('./common');
const chainCommon = require('../blockchain/common');
const Address = require('../primitives/address');
const BIP150 = require('./bip150');
const BIP151 = require('./bip151');
const BIP152 = require('./bip152');
const Network = require('../protocol/network');
const Peer = require('./peer');
const HostList = require('./hostlist');
const InvItem = require('../primitives/invitem');
const packets = require('./packets');
const services = common.services;
const invTypes = InvItem.types;
const packetTypes = packets.types;
const scores = HostList.scores;

/**
 * Pool
 * A pool of peers for handling all network activity.
 * @alias module:net.Pool
 * @extends EventEmitter
 */

class Pool extends EventEmitter {
  /**
   * Create a pool.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();

    this.opened = false;
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
    this.discovering = false;
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

    this.peers = new PeerList();
    this.authdb = new BIP150.AuthDB(this.options);
    this.hosts = new HostList(this.options);
    this.id = 0;

    if (this.options.spv) {
      this.spvFilter = BloomFilter.fromRate(
        20000, 0.001, BloomFilter.flags.ALL);
    }

    if (!this.options.mempool)
      this.txFilter = new RollingFilter(50000, 0.000001);

    this.init();
  }

  /**
   * Initialize the pool.
   * @private
   */

  init() {
    this.server.on('error', (err) => {
      this.emit('error', err);
    });

    this.server.on('connection', (socket) => {
      this.handleSocket(socket);
      this.emit('connection', socket);
    });

    this.server.on('listening', () => {
      const data = this.server.address();
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
  }

  /**
   * Open the pool, wait for the chain to load.
   * @returns {Promise}
   */

  async open() {
    assert(!this.opened, 'Pool is already open.');
    this.opened = true;

    this.logger.info('Pool loaded (maxpeers=%d).', this.options.maxOutbound);

    if (this.options.bip150) {
      const key = secp256k1.publicKeyCreate(this.options.identityKey, true);
      this.logger.info('Identity public key: %s.', key.toString('hex'));
      this.logger.info('Identity address: %s.', BIP150.address(key));
    }

    this.resetChain();
  }

  /**
   * Close and destroy the pool.
   * @method
   * @alias Pool#close
   * @returns {Promise}
   */

  async close() {
    assert(this.opened, 'Pool is not open.');
    this.opened = false;
    return this.disconnect();
  }

  /**
   * Reset header chain.
   */

  resetChain() {
    if (!this.options.checkpoints)
      return;

    this.checkpoints = false;
    this.headerTip = null;
    this.headerChain.reset();
    this.headerNext = null;

    const tip = this.chain.tip;

    if (tip.height < this.network.lastCheckpoint) {
      this.checkpoints = true;
      this.headerTip = this.getNextTip(tip.height);
      this.headerChain.push(new HeaderEntry(tip.hash, tip.height));
      this.logger.info(
        'Initialized header chain to height %d (checkpoint=%s).',
        tip.height, util.revHex(this.headerTip.hash));
    }
  }

  /**
   * Connect to the network.
   * @method
   * @returns {Promise}
   */

  async connect() {
    const unlock = await this.locker.lock();
    try {
      return await this._connect();
    } finally {
      unlock();
    }
  }

  /**
   * Connect to the network (no lock).
   * @method
   * @returns {Promise}
   */

  async _connect() {
    assert(this.opened, 'Pool is not opened.');

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
  }

  /**
   * Disconnect from the network.
   * @method
   * @returns {Promise}
   */

  async disconnect() {
    const unlock = await this.locker.lock();
    try {
      return await this._disconnect();
    } finally {
      unlock();
    }
  }

  /**
   * Disconnect from the network.
   * @method
   * @returns {Promise}
   */

  async _disconnect() {
    if (!this.connected)
      return;

    this.disconnecting = true;

    for (const item of this.invMap.values())
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
  }

  /**
   * Start listening on a server socket.
   * @method
   * @private
   * @returns {Promise}
   */

  async listen() {
    assert(this.server);
    assert(!this.connected, 'Already listening.');

    if (!this.options.listen)
      return;

    this.server.maxConnections = this.options.maxInbound;

    await this.server.listen(this.options.port, this.options.host);
  }

  /**
   * Stop listening on server socket.
   * @method
   * @private
   * @returns {Promise}
   */

  async unlisten() {
    assert(this.server);
    assert(this.connected, 'Not listening.');

    if (!this.options.listen)
      return;

    await this.server.close();
  }

  /**
   * Start discovery timer.
   * @private
   */

  startTimer() {
    assert(this.timer == null, 'Timer already started.');
    this.timer = setInterval(() => this.discover(), Pool.DISCOVERY_INTERVAL);
  }

  /**
   * Stop discovery timer.
   * @private
   */

  stopTimer() {
    assert(this.timer != null, 'Timer already stopped.');
    clearInterval(this.timer);
    this.timer = null;
  }

  /**
   * Rediscover seeds and internet gateway.
   * Attempt to add port mapping once again.
   * @returns {Promise}
   */

  async discover() {
    if (this.discovering)
      return;

    try {
      this.discovering = true;
      await this.discoverGateway();
      await this.discoverSeeds(true);
    } finally {
      this.discovering = false;
    }
  }

  /**
   * Attempt to add port mapping (i.e.
   * remote:8333->local:8333) via UPNP.
   * @returns {Promise}
   */

  async discoverGateway() {
    const src = this.options.publicPort;
    const dest = this.options.port;

    // Pointless if we're not listening.
    if (!this.options.listen)
      return false;

    // UPNP is always optional, since
    // it's likely to not work anyway.
    if (!this.options.upnp)
      return false;

    let wan;
    try {
      this.logger.debug('Discovering internet gateway (upnp).');
      wan = await UPNP.discover();
    } catch (e) {
      this.logger.debug('Could not discover internet gateway (upnp).');
      this.logger.debug(e);
      return false;
    }

    let host;
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
  }

  /**
   * Attempt to resolve DNS seeds if necessary.
   * @param {Boolean} checkPeers
   * @returns {Promise}
   */

  async discoverSeeds(checkPeers) {
    if (this.hosts.dnsSeeds.length === 0)
      return;

    const max = Math.min(2, this.options.maxOutbound);
    const size = this.hosts.size();

    let total = 0;
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
  }

  /**
   * Attempt to discover external IP via DNS.
   * @returns {Promise}
   */

  async discoverExternal() {
    const port = this.options.publicPort;

    // Pointless if we're not listening.
    if (!this.options.listen)
      return;

    // Never hit a DNS server if
    // we're using an outbound proxy.
    if (this.options.proxy)
      return;

    // Try not to hit this if we can avoid it.
    if (this.hosts.local.size > 0)
      return;

    let host4 = null;

    try {
      host4 = await dns.getIPv4(2000);
    } catch (e) {
      this.logger.debug('Could not find external IPv4 (dns).');
      this.logger.debug(e);
    }

    if (host4 && this.hosts.addLocal(host4, port, scores.DNS))
      this.logger.info('External IPv4 found (dns): %s.', host4);

    let host6 = null;

    try {
      host6 = await dns.getIPv6(2000);
    } catch (e) {
      this.logger.debug('Could not find external IPv6 (dns).');
      this.logger.debug(e);
    }

    if (host6 && this.hosts.addLocal(host6, port, scores.DNS))
      this.logger.info('External IPv6 found (dns): %s.', host6);
  }

  /**
   * Handle incoming connection.
   * @private
   * @param {net.Socket} socket
   */

  handleSocket(socket) {
    if (!socket.remoteAddress) {
      this.logger.debug('Ignoring disconnected peer.');
      socket.destroy();
      return;
    }

    const ip = IP.normalize(socket.remoteAddress);

    if (this.peers.inbound >= this.options.maxInbound) {
      this.logger.debug('Ignoring peer: too many inbound (%s).', ip);
      socket.destroy();
      return;
    }

    if (this.hosts.isBanned(ip)) {
      this.logger.debug('Ignoring banned peer (%s).', ip);
      socket.destroy();
      return;
    }

    const host = IP.toHostname(ip, socket.remotePort);

    assert(!this.peers.map.has(host), 'Port collision.');

    this.addInbound(socket);
  }

  /**
   * Add a loader peer. Necessary for
   * a sync to even begin.
   * @private
   */

  addLoader() {
    if (!this.opened)
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

    const addr = this.getHost();

    if (!addr)
      return;

    const peer = this.createOutbound(addr);

    this.logger.info('Adding loader peer (%s).', peer.hostname());

    this.peers.add(peer);

    this.setLoader(peer);
  }

  /**
   * Add a loader peer. Necessary for
   * a sync to even begin.
   * @private
   */

  setLoader(peer) {
    if (!this.opened)
      return;

    assert(peer.outbound);
    assert(!this.peers.load);
    assert(!peer.loader);

    peer.loader = true;
    this.peers.load = peer;

    this.sendSync(peer);

    this.emit('loader', peer);
  }

  /**
   * Start the blockchain sync.
   */

  startSync() {
    if (!this.opened)
      return;

    assert(this.connected, 'Pool is not connected!');

    this.syncing = true;
    this.resync(false);
  }

  /**
   * Force sending of a sync to each peer.
   */

  forceSync() {
    if (!this.opened)
      return;

    assert(this.connected, 'Pool is not connected!');

    this.resync(true);
  }

  /**
   * Send a sync to each peer.
   */

  sync(force) {
    this.resync(false);
  }

  /**
   * Stop the sync.
   * @private
   */

  stopSync() {
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
      peer.blockMap.clear();
      peer.compactBlocks.clear();
    }

    this.blockMap.clear();
    this.compactBlocks.clear();
  }

  /**
   * Send a sync to each peer.
   * @private
   * @param {Boolean?} force
   * @returns {Promise}
   */

  async resync(force) {
    if (!this.syncing)
      return;

    let locator;
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
  }

  /**
   * Test whether a peer is sync-worthy.
   * @param {Peer} peer
   * @returns {Boolean}
   */

  isSyncable(peer) {
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
  }

  /**
   * Start syncing from peer.
   * @method
   * @param {Peer} peer
   * @returns {Promise}
   */

  async sendSync(peer) {
    if (peer.syncing)
      return false;

    if (!this.isSyncable(peer))
      return false;

    peer.syncing = true;
    peer.blockTime = Date.now();

    let locator;
    try {
      locator = await this.chain.getLocator();
    } catch (e) {
      peer.syncing = false;
      peer.blockTime = -1;
      this.emit('error', e);
      return false;
    }

    return this.sendLocator(locator, peer);
  }

  /**
   * Send a chain locator and start syncing from peer.
   * @method
   * @param {Hash[]} locator
   * @param {Peer} peer
   * @returns {Boolean}
   */

  sendLocator(locator, peer) {
    if (!this.isSyncable(peer))
      return false;

    // Ask for the mempool if we're synced.
    if (this.network.requestMempool) {
      if (peer.loader && this.chain.synced)
        peer.sendMempool();
    }

    peer.syncing = true;
    peer.blockTime = Date.now();

    if (this.checkpoints) {
      peer.sendGetHeaders(locator, this.headerTip.hash);
      return true;
    }

    peer.sendGetBlocks(locator);

    return true;
  }

  /**
   * Send `mempool` to all peers.
   */

  sendMempool() {
    for (let peer = this.peers.head(); peer; peer = peer.next)
      peer.sendMempool();
  }

  /**
   * Send `getaddr` to all peers.
   */

  sendGetAddr() {
    for (let peer = this.peers.head(); peer; peer = peer.next)
      peer.sendGetAddr();
  }

  /**
   * Request current header chain blocks.
   * @private
   * @param {Peer} peer
   */

  resolveHeaders(peer) {
    const items = [];

    for (let node = this.headerNext; node; node = node.next) {
      this.headerNext = node.next;

      items.push(node.hash);

      if (items.length === 50000)
        break;
    }

    this.getBlock(peer, items);
  }

  /**
   * Update all peer heights by their best hash.
   * @param {Hash} hash
   * @param {Number} height
   */

  resolveHeight(hash, height) {
    let total = 0;

    for (let peer = this.peers.head(); peer; peer = peer.next) {
      if (peer.bestHash !== hash)
        continue;

      if (peer.bestHeight !== height) {
        peer.bestHeight = height;
        total += 1;
      }
    }

    if (total > 0)
      this.logger.debug('Resolved height for %d peers.', total);
  }

  /**
   * Find the next checkpoint.
   * @private
   * @param {Number} height
   * @returns {Object}
   */

  getNextTip(height) {
    for (const next of this.network.checkpoints) {
      if (next.height > height)
        return new HeaderEntry(next.hash, next.height);
    }

    throw new Error('Next checkpoint not found.');
  }

  /**
   * Announce broadcast list to peer.
   * @param {Peer} peer
   */

  announceList(peer) {
    const blocks = [];
    const txs = [];

    for (const item of this.invMap.values()) {
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
  }

  /**
   * Get a block/tx from the broadcast map.
   * @private
   * @param {Peer} peer
   * @param {InvItem} item
   * @returns {Promise}
   */

  getBroadcasted(peer, item) {
    const type = item.isTX() ? invTypes.TX : invTypes.BLOCK;
    const entry = this.invMap.get(item.hash);

    if (!entry)
      return null;

    if (type !== entry.type) {
      this.logger.debug(
        'Peer requested item with the wrong type (%s).',
        peer.hostname());
      return null;
    }

    this.logger.debug(
      'Peer requested %s %s as a %s packet (%s).',
      item.isTX() ? 'tx' : 'block',
      item.rhash(),
      item.hasWitness() ? 'witness' : 'normal',
      peer.hostname());

    entry.handleAck(peer);

    return entry.msg;
  }

  /**
   * Get a block/tx either from the broadcast map, mempool, or blockchain.
   * @method
   * @private
   * @param {Peer} peer
   * @param {InvItem} item
   * @returns {Promise}
   */

  async getItem(peer, item) {
    const entry = this.getBroadcasted(peer, item);

    if (entry)
      return entry;

    if (this.options.selfish)
      return null;

    if (item.isTX()) {
      if (!this.mempool)
        return null;
      return this.mempool.getTX(item.hash);
    }

    if (this.chain.options.spv)
      return null;

    if (this.chain.options.prune)
      return null;

    return this.chain.getBlock(item.hash);
  }

  /**
   * Send a block from the broadcast list or chain.
   * @method
   * @private
   * @param {Peer} peer
   * @param {InvItem} item
   * @returns {Boolean}
   */

  async sendBlock(peer, item, witness) {
    const broadcasted = this.getBroadcasted(peer, item);

    // Check for a broadcasted item first.
    if (broadcasted) {
      peer.send(new packets.BlockPacket(broadcasted, witness));
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
      const block = await this.chain.getRawBlock(item.hash);

      if (block) {
        peer.sendRaw('block', block);
        return true;
      }

      return false;
    }

    const block = await this.chain.getBlock(item.hash);

    if (block) {
      peer.send(new packets.BlockPacket(block, witness));
      return true;
    }

    return false;
  }

  /**
   * Create an outbound peer with no special purpose.
   * @private
   * @param {NetAddress} addr
   * @returns {Peer}
   */

  createOutbound(addr) {
    const cipher = BIP151.ciphers.CHACHAPOLY;
    const identity = this.options.identityKey;
    const peer = Peer.fromOutbound(this.options, addr);

    this.hosts.markAttempt(addr.hostname);

    if (this.options.bip151)
      peer.setCipher(cipher);

    if (this.options.bip150)
      peer.setAuth(this.authdb, identity);

    this.bindPeer(peer);

    this.logger.debug('Connecting to %s.', peer.hostname());

    peer.tryOpen();

    return peer;
  }

  /**
   * Accept an inbound socket.
   * @private
   * @param {net.Socket} socket
   * @returns {Peer}
   */

  createInbound(socket) {
    const cipher = BIP151.ciphers.CHACHAPOLY;
    const identity = this.options.identityKey;
    const peer = Peer.fromInbound(this.options, socket);

    if (this.options.bip151)
      peer.setCipher(cipher);

    if (this.options.bip150)
      peer.setAuth(this.authdb, identity);

    this.bindPeer(peer);

    peer.tryOpen();

    return peer;
  }

  /**
   * Allocate new peer id.
   * @returns {Number}
   */

  uid() {
    const MAX = Number.MAX_SAFE_INTEGER;

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
  }

  /**
   * Bind to peer events.
   * @private
   * @param {Peer} peer
   */

  bindPeer(peer) {
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
  }

  /**
   * Handle peer packet event.
   * @method
   * @private
   * @param {Peer} peer
   * @param {Packet} packet
   * @returns {Promise}
   */

  async handlePacket(peer, packet) {
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
  }

  /**
   * Handle peer connect event.
   * @method
   * @private
   * @param {Peer} peer
   */

  async handleConnect(peer) {
    this.logger.info('Connected to %s.', peer.hostname());

    if (peer.outbound)
      this.hosts.markSuccess(peer.hostname());

    this.emit('peer connect', peer);
  }

  /**
   * Handle peer open event.
   * @method
   * @private
   * @param {Peer} peer
   */

  async handleOpen(peer) {
    // Advertise our address.
    if (!this.options.selfish && this.options.listen) {
      const addr = this.hosts.getLocal(peer.address);
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
  }

  /**
   * Handle peer close event.
   * @method
   * @private
   * @param {Peer} peer
   * @param {Boolean} connected
   */

  async handleClose(peer, connected) {
    const outbound = peer.outbound;
    const loader = peer.loader;
    const size = peer.blockMap.size;

    this.removePeer(peer);

    if (loader) {
      this.logger.info('Removed loader peer (%s).', peer.hostname());
      if (this.checkpoints)
        this.resetChain();
    }

    this.nonces.remove(peer.hostname());

    this.emit('peer close', peer, connected);

    if (!this.opened)
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
  }

  /**
   * Handle ban event.
   * @method
   * @private
   * @param {Peer} peer
   */

  async handleBan(peer) {
    this.ban(peer.address);
    this.emit('ban', peer);
  }

  /**
   * Handle peer version event.
   * @method
   * @private
   * @param {Peer} peer
   * @param {VersionPacket} packet
   */

  async handleVersion(peer, packet) {
    this.logger.info(
      'Received version (%s): version=%d height=%d services=%s agent=%s',
      peer.hostname(),
      packet.version,
      packet.height,
      packet.services.toString(2),
      packet.agent);

    this.network.time.add(peer.hostname(), packet.time);
    this.nonces.remove(peer.hostname());

    if (!peer.outbound && packet.remote.isRoutable())
      this.hosts.markLocal(packet.remote);
  }

  /**
   * Handle `verack` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {VerackPacket} packet
   */

  async handleVerack(peer, packet) {
    ;
  }

  /**
   * Handle `ping` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {PingPacket} packet
   */

  async handlePing(peer, packet) {
    ;
  }

  /**
   * Handle `pong` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {PongPacket} packet
   */

  async handlePong(peer, packet) {
    ;
  }

  /**
   * Handle `getaddr` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {GetAddrPacket} packet
   */

  async handleGetAddr(peer, packet) {
    if (this.options.selfish)
      return;

    if (peer.sentAddr) {
      this.logger.debug(
        'Ignoring repeated getaddr (%s).',
        peer.hostname());
      return;
    }

    peer.sentAddr = true;

    const addrs = this.hosts.toArray();
    const items = [];

    for (const addr of addrs) {
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
  }

  /**
   * Handle peer addr event.
   * @method
   * @private
   * @param {Peer} peer
   * @param {AddrPacket} packet
   */

  async handleAddr(peer, packet) {
    const addrs = packet.items;
    const now = this.network.now();
    const services = this.options.getRequiredServices();

    for (const addr of addrs) {
      peer.addrFilter.add(addr.hostname, 'ascii');

      if (!addr.isRoutable())
        continue;

      if (!addr.hasServices(services))
        continue;

      if (addr.time <= 100000000 || addr.time > now + 10 * 60)
        addr.time = now - 5 * 24 * 60 * 60;

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
  }

  /**
   * Handle `inv` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {InvPacket} packet
   */

  async handleInv(peer, packet) {
    const unlock = await this.locker.lock();
    try {
      return await this._handleInv(peer, packet);
    } finally {
      unlock();
    }
  }

  /**
   * Handle `inv` packet (without a lock).
   * @method
   * @private
   * @param {Peer} peer
   * @param {InvPacket} packet
   */

  async _handleInv(peer, packet) {
    const items = packet.items;

    if (items.length > 50000) {
      peer.increaseBan(100);
      return;
    }

    const blocks = [];
    const txs = [];
    let unknown = -1;

    for (const item of items) {
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
  }

  /**
   * Handle `inv` packet from peer (containing only BLOCK types).
   * @method
   * @private
   * @param {Peer} peer
   * @param {Hash[]} hashes
   * @returns {Promise}
   */

  async handleBlockInv(peer, hashes) {
    assert(hashes.length > 0);

    if (!this.syncing)
      return;

    // Always keep track of the peer's best hash.
    if (!peer.loader || this.chain.synced) {
      const hash = hashes[hashes.length - 1];
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

    const items = [];

    let exists = null;

    for (let i = 0; i < hashes.length; i++) {
      const hash = hashes[i];

      // Resolve orphan chain.
      if (this.chain.hasOrphan(hash)) {
        this.logger.debug('Received known orphan hash (%s).', peer.hostname());
        await this.resolveOrphan(peer, hash);
        continue;
      }

      // Request the block if we don't have it.
      if (!await this.hasBlock(hash)) {
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
      const height = await this.chain.getHeight(exists);
      if (height !== -1)
        peer.bestHeight = height;
    }

    this.getBlock(peer, items);
  }

  /**
   * Handle peer inv packet (txs).
   * @method
   * @private
   * @param {Peer} peer
   * @param {Hash[]} hashes
   */

  async handleTXInv(peer, hashes) {
    assert(hashes.length > 0);

    if (this.syncing && !this.chain.synced)
      return;

    this.ensureTX(peer, hashes);
  }

  /**
   * Handle `getdata` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {GetDataPacket} packet
   */

  async handleGetData(peer, packet) {
    const items = packet.items;

    if (items.length > 50000) {
      this.logger.warning(
        'Peer sent inv with >50k items (%s).',
        peer.hostname());
      peer.increaseBan(100);
      peer.destroy();
      return;
    }

    const notFound = [];

    let txs = 0;
    let blocks = 0;
    let compact = 0;
    let unknown = -1;

    for (const item of items) {
      if (item.isTX()) {
        const tx = await this.getItem(peer, item);

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

        txs += 1;

        continue;
      }

      switch (item.type) {
        case invTypes.BLOCK:
        case invTypes.WITNESS_BLOCK: {
          const result = await this.sendBlock(peer, item, item.hasWitness());
          if (!result) {
            notFound.push(item);
            continue;
          }
          blocks += 1;
          break;
        }
        case invTypes.FILTERED_BLOCK:
        case invTypes.WITNESS_FILTERED_BLOCK: {
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

          const block = await this.getItem(peer, item);

          if (!block) {
            notFound.push(item);
            continue;
          }

          const merkle = block.toMerkle(peer.spvFilter);

          peer.send(new packets.MerkleBlockPacket(merkle));

          for (const tx of merkle.txs) {
            peer.send(new packets.TXPacket(tx, item.hasWitness()));
            txs += 1;
          }

          blocks += 1;

          break;
        }
        case invTypes.CMPCT_BLOCK: {
          const height = await this.chain.getHeight(item.hash);

          // Fallback to full block.
          if (height < this.chain.tip.height - 10) {
            const result = await this.sendBlock(
              peer, item, peer.compactWitness);

            if (!result) {
              notFound.push(item);
              continue;
            }

            blocks += 1;

            break;
          }

          const block = await this.getItem(peer, item);

          if (!block) {
            notFound.push(item);
            continue;
          }

          peer.sendCompactBlock(block);

          blocks += 1;
          compact += 1;

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
  }

  /**
   * Handle peer notfound packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {NotFoundPacket} packet
   */

  async handleNotFound(peer, packet) {
    const items = packet.items;

    for (const item of items) {
      if (!this.resolveItem(peer, item)) {
        this.logger.warning(
          'Peer sent notfound for unrequested item: %s (%s).',
          item.hash, peer.hostname());
        peer.destroy();
        return;
      }
    }
  }

  /**
   * Handle `getblocks` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {GetBlocksPacket} packet
   */

  async handleGetBlocks(peer, packet) {
    if (!this.chain.synced)
      return;

    if (this.options.selfish)
      return;

    if (this.chain.options.spv)
      return;

    if (this.chain.options.prune)
      return;

    let hash = await this.chain.findLocator(packet.locator);

    if (hash)
      hash = await this.chain.getNextHash(hash);

    const blocks = [];

    while (hash) {
      blocks.push(new InvItem(invTypes.BLOCK, hash));

      if (hash === packet.stop)
        break;

      if (blocks.length === 500) {
        peer.hashContinue = hash;
        break;
      }

      hash = await this.chain.getNextHash(hash);
    }

    peer.sendInv(blocks);
  }

  /**
   * Handle `getheaders` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {GetHeadersPacket} packet
   */

  async handleGetHeaders(peer, packet) {
    if (!this.chain.synced)
      return;

    if (this.options.selfish)
      return;

    if (this.chain.options.spv)
      return;

    if (this.chain.options.prune)
      return;

    let hash;
    if (packet.locator.length > 0) {
      hash = await this.chain.findLocator(packet.locator);
      if (hash)
        hash = await this.chain.getNextHash(hash);
    } else {
      hash = packet.stop;
    }

    let entry;
    if (hash)
      entry = await this.chain.getEntry(hash);

    const headers = [];

    while (entry) {
      headers.push(entry.toHeaders());

      if (entry.hash === packet.stop)
        break;

      if (headers.length === 2000)
        break;

      entry = await this.chain.getNext(entry);
    }

    peer.sendHeaders(headers);
  }

  /**
   * Handle `headers` packet from a given peer.
   * @method
   * @private
   * @param {Peer} peer
   * @param {HeadersPacket} packet
   * @returns {Promise}
   */

  async handleHeaders(peer, packet) {
    const unlock = await this.locker.lock();
    try {
      return await this._handleHeaders(peer, packet);
    } finally {
      unlock();
    }
  }

  /**
   * Handle `headers` packet from
   * a given peer without a lock.
   * @method
   * @private
   * @param {Peer} peer
   * @param {HeadersPacket} packet
   * @returns {Promise}
   */

  async _handleHeaders(peer, packet) {
    const headers = packet.items;

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

    let checkpoint = false;
    let node = null;

    for (const header of headers) {
      const last = this.headerChain.tail;
      const hash = header.hash('hex');
      const height = last.height + 1;

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
        peer.destroy();
        return;
      }

      node = new HeaderEntry(hash, height);

      if (node.height === this.headerTip.height) {
        if (node.hash !== this.headerTip.hash) {
          this.logger.warning(
            'Peer sent an invalid checkpoint (%s).',
            peer.hostname());
          peer.destroy();
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
    peer.blockTime = Date.now();

    // Request the blocks we just added.
    if (checkpoint) {
      this.headerChain.shift();
      this.resolveHeaders(peer);
      return;
    }

    // Request more headers.
    peer.sendGetHeaders([node.hash], this.headerTip.hash);
  }

  /**
   * Handle `sendheaders` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {SendHeadersPacket} packet
   * @returns {Promise}
   */

  async handleSendHeaders(peer, packet) {
    ;
  }

  /**
   * Handle `block` packet. Attempt to add to chain.
   * @method
   * @private
   * @param {Peer} peer
   * @param {BlockPacket} packet
   * @returns {Promise}
   */

  async handleBlock(peer, packet) {
    const flags = chainCommon.flags.DEFAULT_FLAGS;

    if (this.options.spv) {
      this.logger.warning(
        'Peer sent unsolicited block (%s).',
        peer.hostname());
      return;
    }

    await this.addBlock(peer, packet.block, flags);
  }

  /**
   * Attempt to add block to chain.
   * @method
   * @private
   * @param {Peer} peer
   * @param {Block} block
   * @returns {Promise}
   */

  async addBlock(peer, block, flags) {
    const hash = block.hash('hex');
    const unlock = await this.locker.lock(hash);
    try {
      return await this._addBlock(peer, block, flags);
    } finally {
      unlock();
    }
  }

  /**
   * Attempt to add block to chain (without a lock).
   * @method
   * @private
   * @param {Peer} peer
   * @param {Block} block
   * @returns {Promise}
   */

  async _addBlock(peer, block, flags) {
    if (!this.syncing)
      return;

    const hash = block.hash('hex');

    if (!this.resolveBlock(peer, hash)) {
      this.logger.warning(
        'Received unrequested block: %s (%s).',
        block.rhash(), peer.hostname());
      peer.destroy();
      return;
    }

    peer.blockTime = Date.now();

    let entry;
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
      if (this.checkpoints) {
        this.logger.warning(
          'Peer sent orphan block with getheaders (%s).',
          peer.hostname());
        return;
      }

      // During a getblocks sync, peers send
      // their best tip frequently. We can grab
      // the height commitment from the coinbase.
      const height = block.getCoinbaseHeight();

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
  }

  /**
   * Resolve header chain.
   * @method
   * @private
   * @param {Peer} peer
   * @param {Hash} hash
   * @returns {Promise}
   */

  async resolveChain(peer, hash) {
    if (!this.checkpoints)
      return;

    if (!peer.loader)
      return;

    if (peer.destroyed)
      throw new Error('Peer was destroyed (header chain resolution).');

    const node = this.headerChain.head;

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
  }

  /**
   * Switch to getblocks.
   * @method
   * @private
   * @param {Peer} peer
   * @param {Hash} hash
   * @returns {Promise}
   */

  async switchSync(peer, hash) {
    assert(this.checkpoints);

    this.checkpoints = false;
    this.headerTip = null;
    this.headerChain.reset();
    this.headerNext = null;

    await this.getBlocks(peer, hash);
  }

  /**
   * Handle bad orphan.
   * @method
   * @private
   * @param {String} msg
   * @param {VerifyError} err
   * @param {Number} id
   */

  handleBadOrphan(msg, err, id) {
    const peer = this.peers.find(id);

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
  }

  /**
   * Log sync status.
   * @private
   * @param {Block} block
   */

  logStatus(block) {
    if (this.chain.height % 20 === 0) {
      this.logger.debug('Status:'
        + ' time=%s height=%d progress=%s'
        + ' orphans=%d active=%d'
        + ' target=%s peers=%d',
        util.date(block.time),
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
  }

  /**
   * Handle a transaction. Attempt to add to mempool.
   * @method
   * @private
   * @param {Peer} peer
   * @param {TXPacket} packet
   * @returns {Promise}
   */

  async handleTX(peer, packet) {
    const hash = packet.tx.hash('hex');
    const unlock = await this.locker.lock(hash);
    try {
      return await this._handleTX(peer, packet);
    } finally {
      unlock();
    }
  }

  /**
   * Handle a transaction. Attempt to add to mempool (without a lock).
   * @method
   * @private
   * @param {Peer} peer
   * @param {TXPacket} packet
   * @returns {Promise}
   */

  async _handleTX(peer, packet) {
    const tx = packet.tx;
    const hash = tx.hash('hex');
    const flags = chainCommon.flags.VERIFY_NONE;
    const block = peer.merkleBlock;

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

        block.txs.push(tx);

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

    let missing;
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
  }

  /**
   * Handle peer reject event.
   * @method
   * @private
   * @param {Peer} peer
   * @param {RejectPacket} packet
   */

  async handleReject(peer, packet) {
    this.logger.warning(
      'Received reject (%s): msg=%s code=%s reason=%s hash=%s.',
      peer.hostname(),
      packet.message,
      packet.getCode(),
      packet.reason,
      packet.rhash());

    if (!packet.hash)
      return;

    const entry = this.invMap.get(packet.hash);

    if (!entry)
      return;

    entry.handleReject(peer);
  }

  /**
   * Handle `mempool` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {MempoolPacket} packet
   */

  async handleMempool(peer, packet) {
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

    const items = [];

    for (const hash of this.mempool.map.keys())
      items.push(new InvItem(invTypes.TX, hash));

    this.logger.debug(
      'Sending mempool snapshot (%s).',
      peer.hostname());

    peer.queueInv(items);
  }

  /**
   * Handle `filterload` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {FilterLoadPacket} packet
   */

  async handleFilterLoad(peer, packet) {
    ;
  }

  /**
   * Handle `filteradd` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {FilterAddPacket} packet
   */

  async handleFilterAdd(peer, packet) {
    ;
  }

  /**
   * Handle `filterclear` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {FilterClearPacket} packet
   */

  async handleFilterClear(peer, packet) {
    ;
  }

  /**
   * Handle `merkleblock` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {MerkleBlockPacket} block
   */

  async handleMerkleBlock(peer, packet) {
    const hash = packet.block.hash('hex');
    const unlock = await this.locker.lock(hash);
    try {
      return await this._handleMerkleBlock(peer, packet);
    } finally {
      unlock();
    }
  }

  /**
   * Handle `merkleblock` packet (without a lock).
   * @method
   * @private
   * @param {Peer} peer
   * @param {MerkleBlockPacket} block
   */

  async _handleMerkleBlock(peer, packet) {
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

    const block = packet.block;
    const hash = block.hash('hex');

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

    const tree = block.getTree();

    if (tree.matches.length === 0) {
      const flags = chainCommon.flags.VERIFY_NONE;
      await this._addBlock(peer, block, flags);
      return;
    }

    peer.merkleBlock = block;
    peer.merkleTime = Date.now();
    peer.merkleMatches = tree.matches.length;
    peer.merkleMap = new Set();
  }

  /**
   * Handle `sendcmpct` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {FeeFilterPacket} packet
   */

  async handleFeeFilter(peer, packet) {
    ;
  }

  /**
   * Handle `sendcmpct` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {SendCmpctPacket} packet
   */

  async handleSendCmpct(peer, packet) {
    ;
  }

  /**
   * Handle `cmpctblock` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {CompactBlockPacket} packet
   */

  async handleCmpctBlock(peer, packet) {
    const block = packet.block;
    const hash = block.hash('hex');
    const witness = peer.compactWitness;

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
      peer.blockMap.set(hash, Date.now());
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

    let result;
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

    const full = block.fillMempool(witness, this.mempool);

    if (full) {
      this.logger.debug(
        'Received full compact block %s (%s).',
        block.rhash(), peer.hostname());
      const flags = chainCommon.flags.VERIFY_BODY;
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

    block.now = Date.now();

    assert(!peer.compactBlocks.has(hash));
    peer.compactBlocks.set(hash, block);

    this.compactBlocks.add(hash);

    this.logger.debug(
      'Received non-full compact block %s tx=%d/%d (%s).',
      block.rhash(), block.count, block.totalTX, peer.hostname());

    peer.send(new packets.GetBlockTxnPacket(block.toRequest()));
  }

  /**
   * Handle `getblocktxn` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {GetBlockTxnPacket} packet
   */

  async handleGetBlockTxn(peer, packet) {
    const req = packet.request;

    if (this.chain.options.spv)
      return;

    if (this.chain.options.prune)
      return;

    if (this.options.selfish)
      return;

    const item = new InvItem(invTypes.BLOCK, req.hash);

    const block = await this.getItem(peer, item);

    if (!block) {
      this.logger.debug(
        'Peer sent getblocktxn for non-existent block (%s).',
        peer.hostname());
      peer.increaseBan(100);
      return;
    }

    const height = await this.chain.getHeight(req.hash);

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

    const res = BIP152.TXResponse.fromBlock(block, req);

    peer.send(new packets.BlockTxnPacket(res, peer.compactWitness));
  }

  /**
   * Handle `blocktxn` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {BlockTxnPacket} packet
   */

  async handleBlockTxn(peer, packet) {
    const res = packet.response;
    const block = peer.compactBlocks.get(res.hash);
    const flags = chainCommon.flags.VERIFY_BODY;

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
  }

  /**
   * Handle `encinit` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {EncinitPacket} packet
   */

  async handleEncinit(peer, packet) {
    ;
  }

  /**
   * Handle `encack` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {EncackPacket} packet
   */

  async handleEncack(peer, packet) {
    ;
  }

  /**
   * Handle `authchallenge` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {AuthChallengePacket} packet
   */

  async handleAuthChallenge(peer, packet) {
    ;
  }

  /**
   * Handle `authreply` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {AuthReplyPacket} packet
   */

  async handleAuthReply(peer, packet) {
    ;
  }

  /**
   * Handle `authpropose` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {AuthProposePacket} packet
   */

  async handleAuthPropose(peer, packet) {
    ;
  }

  /**
   * Handle `unknown` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {UnknownPacket} packet
   */

  async handleUnknown(peer, packet) {
    this.logger.warning(
      'Unknown packet: %s (%s).',
      packet.cmd, peer.hostname());
  }

  /**
   * Create an inbound peer from an existing socket.
   * @private
   * @param {net.Socket} socket
   */

  addInbound(socket) {
    if (!this.opened) {
      socket.destroy();
      return;
    }

    const peer = this.createInbound(socket);

    this.logger.info('Added inbound peer (%s).', peer.hostname());

    this.peers.add(peer);
  }

  /**
   * Allocate a host from the host list.
   * @returns {NetAddress}
   */

  getHost() {
    for (const addr of this.hosts.nodes) {
      if (this.peers.has(addr.hostname))
        continue;

      return addr;
    }

    const services = this.options.getRequiredServices();
    const now = this.network.now();

    for (let i = 0; i < 100; i++) {
      const entry = this.hosts.getHost();

      if (!entry)
        break;

      const addr = entry.addr;

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

    return null;
  }

  /**
   * Create an outbound non-loader peer. These primarily
   * exist for transaction relaying.
   * @private
   */

  addOutbound() {
    if (!this.opened)
      return;

    if (this.peers.outbound >= this.options.maxOutbound)
      return;

    // Hang back if we don't
    // have a loader peer yet.
    if (!this.peers.load)
      return;

    const addr = this.getHost();

    if (!addr)
      return;

    const peer = this.createOutbound(addr);

    this.peers.add(peer);

    this.emit('peer', peer);
  }

  /**
   * Attempt to refill the pool with peers (no lock).
   * @private
   */

  fillOutbound() {
    const need = this.options.maxOutbound - this.peers.outbound;

    if (!this.peers.load)
      this.addLoader();

    if (need <= 0)
      return;

    this.logger.debug('Refilling peers (%d/%d).',
      this.peers.outbound,
      this.options.maxOutbound);

    for (let i = 0; i < need; i++)
      this.addOutbound();
  }

  /**
   * Attempt to refill the pool with peers (no lock).
   * @private
   */

  refill() {
    if (this.pendingRefill != null)
      return;

    this.pendingRefill = setTimeout(() => {
      this.pendingRefill = null;
      this.fillOutbound();
    }, 3000);
  }

  /**
   * Remove a peer from any list. Drop all load requests.
   * @private
   * @param {Peer} peer
   */

  removePeer(peer) {
    this.peers.remove(peer);

    for (const hash of peer.blockMap.keys())
      this.resolveBlock(peer, hash);

    for (const hash of peer.txMap.keys())
      this.resolveTX(peer, hash);

    for (const hash of peer.compactBlocks.keys()) {
      assert(this.compactBlocks.has(hash));
      this.compactBlocks.delete(hash);
    }

    peer.compactBlocks.clear();
  }

  /**
   * Ban peer.
   * @param {NetAddress} addr
   */

  ban(addr) {
    const peer = this.peers.get(addr.hostname);

    this.logger.debug('Banning peer (%s).', addr.hostname);

    this.hosts.ban(addr.host);
    this.hosts.remove(addr.hostname);

    if (peer)
      peer.destroy();
  }

  /**
   * Unban peer.
   * @param {NetAddress} addr
   */

  unban(addr) {
    this.hosts.unban(addr.host);
  }

  /**
   * Set the spv filter.
   * @param {BloomFilter} filter
   * @param {String?} enc
   */

  setFilter(filter) {
    if (!this.options.spv)
      return;

    this.spvFilter = filter;
    this.queueFilterLoad();
  }

  /**
   * Watch a an address hash (filterload, SPV-only).
   * @param {Buffer|Hash} data
   * @param {String?} enc
   */

  watch(data, enc) {
    if (!this.options.spv)
      return;

    this.spvFilter.add(data, enc);
    this.queueFilterLoad();
  }

  /**
   * Reset the spv filter (filterload, SPV-only).
   */

  unwatch() {
    if (!this.options.spv)
      return;

    this.spvFilter.reset();
    this.queueFilterLoad();
  }

  /**
   * Queue a resend of the bloom filter.
   */

  queueFilterLoad() {
    if (!this.options.spv)
      return;

    if (this.pendingFilter != null)
      return;

    this.pendingFilter = setTimeout(() => {
      this.pendingFilter = null;
      this.sendFilterLoad();
    }, 100);
  }

  /**
   * Resend the bloom filter to peers.
   */

  sendFilterLoad() {
    if (!this.options.spv)
      return;

    assert(this.spvFilter);

    for (let peer = this.peers.head(); peer; peer = peer.next)
      peer.sendFilterLoad(this.spvFilter);
  }

  /**
   * Add an address to the bloom filter (SPV-only).
   * @param {Address|AddressString} address
   */

  watchAddress(address) {
    const hash = Address.getHash(address);
    this.watch(hash);
  }

  /**
   * Add an outpoint to the bloom filter (SPV-only).
   * @param {Outpoint} outpoint
   */

  watchOutpoint(outpoint) {
    this.watch(outpoint.toRaw());
  }

  /**
   * Send `getblocks` to peer after building
   * locator and resolving orphan root.
   * @method
   * @param {Peer} peer
   * @param {Hash} orphan - Orphan hash to resolve.
   * @returns {Promise}
   */

  async resolveOrphan(peer, orphan) {
    const locator = await this.chain.getLocator();
    const root = this.chain.getOrphanRoot(orphan);

    assert(root);

    peer.sendGetBlocks(locator, root);
  }

  /**
   * Send `getheaders` to peer after building locator.
   * @method
   * @param {Peer} peer
   * @param {Hash} tip - Tip to build chain locator from.
   * @param {Hash?} stop
   * @returns {Promise}
   */

  async getHeaders(peer, tip, stop) {
    const locator = await this.chain.getLocator(tip);
    peer.sendGetHeaders(locator, stop);
  }

  /**
   * Send `getblocks` to peer after building locator.
   * @method
   * @param {Peer} peer
   * @param {Hash} tip - Tip hash to build chain locator from.
   * @param {Hash?} stop
   * @returns {Promise}
   */

  async getBlocks(peer, tip, stop) {
    const locator = await this.chain.getLocator(tip);
    peer.sendGetBlocks(locator, stop);
  }

  /**
   * Queue a `getdata` request to be sent.
   * @param {Peer} peer
   * @param {Hash[]} hashes
   */

  getBlock(peer, hashes) {
    if (!this.opened)
      return;

    if (!peer.handshake)
      throw new Error('Peer handshake not complete (getdata).');

    if (peer.destroyed)
      throw new Error('Peer is destroyed (getdata).');

    let now = Date.now();

    const items = [];

    for (const hash of hashes) {
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
  }

  /**
   * Queue a `getdata` request to be sent.
   * @param {Peer} peer
   * @param {Hash[]} hashes
   */

  getTX(peer, hashes) {
    if (!this.opened)
      return;

    if (!peer.handshake)
      throw new Error('Peer handshake not complete (getdata).');

    if (peer.destroyed)
      throw new Error('Peer is destroyed (getdata).');

    let now = Date.now();

    const items = [];

    for (const hash of hashes) {
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
  }

  /**
   * Test whether the chain has or has seen an item.
   * @method
   * @param {Hash} hash
   * @returns {Promise} - Returns Boolean.
   */

  async hasBlock(hash) {
    // Check the lock.
    if (this.locker.has(hash))
      return true;

    // Check the chain.
    if (await this.chain.has(hash))
      return true;

    return false;
  }

  /**
   * Test whether the mempool has or has seen an item.
   * @param {Hash} hash
   * @returns {Boolean}
   */

  hasTX(hash) {
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
  }

  /**
   * Queue a `getdata` request to be sent.
   * Check tx existence before requesting.
   * @param {Peer} peer
   * @param {Hash[]} hashes
   */

  ensureTX(peer, hashes) {
    const items = [];

    for (const hash of hashes) {
      if (this.hasTX(hash))
        continue;

      items.push(hash);
    }

    this.getTX(peer, items);
  }

  /**
   * Fulfill a requested tx.
   * @param {Peer} peer
   * @param {Hash} hash
   * @returns {Boolean}
   */

  resolveTX(peer, hash) {
    if (!peer.txMap.has(hash))
      return false;

    peer.txMap.delete(hash);

    assert(this.txMap.has(hash));
    this.txMap.delete(hash);

    return true;
  }

  /**
   * Fulfill a requested block.
   * @param {Peer} peer
   * @param {Hash} hash
   * @returns {Boolean}
   */

  resolveBlock(peer, hash) {
    if (!peer.blockMap.has(hash))
      return false;

    peer.blockMap.delete(hash);

    assert(this.blockMap.has(hash));
    this.blockMap.delete(hash);

    return true;
  }

  /**
   * Fulfill a requested item.
   * @param {Peer} peer
   * @param {InvItem} item
   * @returns {Boolean}
   */

  resolveItem(peer, item) {
    if (item.isBlock())
      return this.resolveBlock(peer, item.hash);

    if (item.isTX())
      return this.resolveTX(peer, item.hash);

    return false;
  }

  /**
   * Broadcast a transaction or block.
   * @param {TX|Block} msg
   * @returns {Promise}
   */

  broadcast(msg) {
    const hash = msg.hash('hex');

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
  }

  /**
   * Announce a block to all peers.
   * @param {Block} tx
   */

  announceBlock(msg) {
    for (let peer = this.peers.head(); peer; peer = peer.next)
      peer.announceBlock(msg);
  }

  /**
   * Announce a transaction to all peers.
   * @param {TX} tx
   */

  announceTX(msg) {
    for (let peer = this.peers.head(); peer; peer = peer.next)
      peer.announceTX(msg);
  }
}

/**
 * Discovery interval for UPNP and DNS seeds.
 * @const {Number}
 * @default
 */

Pool.DISCOVERY_INTERVAL = 120000;

/**
 * Pool Options
 * @alias module:net.PoolOptions
 */

class PoolOptions {
  /**
   * Create pool options.
   * @constructor
   */

  constructor(options) {
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
    this.memory = true;

    this.fromOptions(options);
  }

  /**
   * Inject properties from object.
   * @private
   * @param {Object} options
   * @returns {PoolOptions}
   */

  fromOptions(options) {
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
      const raw = IP.toBuffer(options.host);
      this.host = IP.toString(raw);
      if (IP.isRoutable(raw))
        this.publicHost = this.host;
    }

    if (options.port != null) {
      assert((options.port & 0xffff) === options.port);
      this.port = options.port;
      this.publicPort = options.port;
    }

    if (options.publicHost != null) {
      assert(typeof options.publicHost === 'string');
      this.publicHost = IP.normalize(options.publicHost);
    }

    if (options.publicPort != null) {
      assert((options.publicPort & 0xffff) === options.publicPort);
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

    if (options.memory != null) {
      assert(typeof options.memory === 'boolean');
      this.memory = options.memory;
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
      assert((options.services >>> 0) === options.services);
      this.services = options.services;
    }

    if (options.requiredServices != null) {
      assert((options.requiredServices >>> 0) === options.requiredServices);
      this.requiredServices = options.requiredServices;
    }

    return this;
  }

  /**
   * Instantiate options from object.
   * @param {Object} options
   * @returns {PoolOptions}
   */

  static fromOptions(options) {
    return new PoolOptions().fromOptions(options);
  }

  /**
   * Get the chain height.
   * @private
   * @returns {Number}
   */

  getHeight() {
    return this.chain.height;
  }

  /**
   * Test whether the chain is synced.
   * @private
   * @returns {Boolean}
   */

  isFull() {
    return this.chain.synced;
  }

  /**
   * Get required services for outbound peers.
   * @private
   * @returns {Number}
   */

  getRequiredServices() {
    let services = this.requiredServices;
    if (this.hasWitness())
      services |= common.services.WITNESS;
    return services;
  }

  /**
   * Whether segwit is enabled.
   * @private
   * @returns {Boolean}
   */

  hasWitness() {
    return this.chain.state.hasWitness();
  }

  /**
   * Create a version packet nonce.
   * @private
   * @param {String} hostname
   * @returns {Buffer}
   */

  createNonce(hostname) {
    return this.nonces.alloc(hostname);
  }

  /**
   * Test whether version nonce is ours.
   * @private
   * @param {Buffer} nonce
   * @returns {Boolean}
   */

  hasNonce(nonce) {
    return this.nonces.has(nonce);
  }

  /**
   * Get fee rate for txid.
   * @private
   * @param {Hash} hash
   * @returns {Rate}
   */

  getRate(hash) {
    if (!this.mempool)
      return -1;

    const entry = this.mempool.getEntry(hash);

    if (!entry)
      return -1;

    return entry.getRate();
  }

  /**
   * Default createSocket call.
   * @private
   * @param {Number} port
   * @param {String} host
   * @returns {net.Socket}
   */

  _createSocket(port, host) {
    if (this.proxy)
      return socks.connect(this.proxy, port, host);

    return tcp.createSocket(port, host);
  }

  /**
   * Default resolve call.
   * @private
   * @param {String} name
   * @returns {String[]}
   */

  _resolve(name) {
    if (this.onion)
      return socks.resolve(this.proxy, name);

    return dns.lookup(name);
  }
}

/**
 * Peer List
 * @alias module:net.PeerList
 */

class PeerList {
  /**
   * Create peer list.
   * @constructor
   * @param {Object} options
   */

  constructor() {
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

  head() {
    return this.list.head;
  }

  /**
   * Get the list tail.
   * @returns {Peer}
   */

  tail() {
    return this.list.tail;
  }

  /**
   * Get list size.
   * @returns {Number}
   */

  size() {
    return this.list.size;
  }

  /**
   * Add peer to list.
   * @param {Peer} peer
   */

  add(peer) {
    assert(this.list.push(peer));

    assert(!this.map.has(peer.hostname()));
    this.map.set(peer.hostname(), peer);

    assert(!this.ids.has(peer.id));
    this.ids.set(peer.id, peer);

    if (peer.outbound)
      this.outbound += 1;
    else
      this.inbound += 1;
  }

  /**
   * Remove peer from list.
   * @param {Peer} peer
   */

  remove(peer) {
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
      this.outbound -= 1;
    else
      this.inbound -= 1;
  }

  /**
   * Get peer by hostname.
   * @param {String} hostname
   * @returns {Peer}
   */

  get(hostname) {
    return this.map.get(hostname);
  }

  /**
   * Test whether a peer exists.
   * @param {String} hostname
   * @returns {Boolean}
   */

  has(hostname) {
    return this.map.has(hostname);
  }

  /**
   * Get peer by ID.
   * @param {Number} id
   * @returns {Peer}
   */

  find(id) {
    return this.ids.get(id);
  }

  /**
   * Destroy peer list (kills peers).
   */

  destroy() {
    let next;

    for (let peer = this.list.head; peer; peer = next) {
      next = peer.next;
      peer.destroy();
    }
  }
}

/**
 * Broadcast Item
 * Represents an item that is broadcasted via an inv/getdata cycle.
 * @alias module:net.BroadcastItem
 * @extends EventEmitter
 * @private
 * @emits BroadcastItem#ack
 * @emits BroadcastItem#reject
 * @emits BroadcastItem#timeout
 */

class BroadcastItem extends EventEmitter {
  /**
   * Create broadcast item.
   * @constructor
   * @param {Pool} pool
   * @param {TX|Block} msg
   */

  constructor(pool, msg) {
    super();

    assert(!msg.mutable, 'Cannot broadcast mutable item.');

    const item = msg.toInv();

    this.pool = pool;
    this.hash = item.hash;
    this.type = item.type;
    this.msg = msg;
    this.jobs = [];
  }

  /**
   * Add a job to be executed on ack, timeout, or reject.
   * @returns {Promise}
   */

  addJob(resolve, reject) {
    this.jobs.push({ resolve, reject });
  }

  /**
   * Start the broadcast.
   */

  start() {
    assert(!this.timeout, 'Already started.');
    assert(!this.pool.invMap.has(this.hash), 'Already started.');

    this.pool.invMap.set(this.hash, this);

    this.refresh();

    return this;
  }

  /**
   * Refresh the timeout on the broadcast.
   */

  refresh() {
    if (this.timeout != null) {
      clearTimeout(this.timeout);
      this.timeout = null;
    }

    this.timeout = setTimeout(() => {
      this.emit('timeout');
      this.reject(new Error('Timed out.'));
    }, this.pool.options.invTimeout);
  }

  /**
   * Announce the item.
   */

  announce() {
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
  }

  /**
   * Finish the broadcast.
   */

  cleanup() {
    assert(this.timeout != null, 'Already finished.');
    assert(this.pool.invMap.has(this.hash), 'Already finished.');

    clearTimeout(this.timeout);
    this.timeout = null;

    this.pool.invMap.delete(this.hash);
  }

  /**
   * Finish the broadcast, return with an error.
   * @param {Error} err
   */

  reject(err) {
    this.cleanup();

    for (const job of this.jobs)
      job.reject(err);

    this.jobs.length = 0;
  }

  /**
   * Finish the broadcast successfully.
   */

  resolve() {
    this.cleanup();

    for (const job of this.jobs)
      job.resolve(false);

    this.jobs.length = 0;
  }

  /**
   * Handle an ack from a peer.
   * @param {Peer} peer
   */

  handleAck(peer) {
    setTimeout(() => {
      this.emit('ack', peer);

      for (const job of this.jobs)
        job.resolve(true);

      this.jobs.length = 0;
    }, 1000);
  }

  /**
   * Handle a reject from a peer.
   * @param {Peer} peer
   */

  handleReject(peer) {
    this.emit('reject', peer);

    for (const job of this.jobs)
      job.resolve(false);

    this.jobs.length = 0;
  }

  /**
   * Inspect the broadcast item.
   * @returns {String}
   */

  inspect() {
    const type = this.type === invTypes.TX ? 'tx' : 'block';
    const hash = util.revHex(this.hash);
    return `<BroadcastItem: type=${type} hash=${hash}>`;
  }
}

/**
 * Nonce List
 * @ignore
 */

class NonceList {
  /**
   * Create nonce list.
   * @constructor
   */

  constructor() {
    this.map = new Map();
    this.hosts = new Map();
  }

  alloc(hostname) {
    for (;;) {
      const nonce = common.nonce();
      const key = nonce.toString('hex');

      if (this.map.has(key))
        continue;

      this.map.set(key, hostname);

      assert(!this.hosts.has(hostname));
      this.hosts.set(hostname, key);

      return nonce;
    }
  }

  has(nonce) {
    const key = nonce.toString('hex');
    return this.map.has(key);
  }

  remove(hostname) {
    const key = this.hosts.get(hostname);

    if (!key)
      return false;

    this.hosts.delete(hostname);

    assert(this.map.has(key));
    this.map.delete(key);

    return true;
  }
}

/**
 * Header Entry
 * @ignore
 */

class HeaderEntry {
  /**
   * Create header entry.
   * @constructor
   */

  constructor(hash, height) {
    this.hash = hash;
    this.height = height;
    this.prev = null;
    this.next = null;
  }
}

/*
 * Expose
 */

module.exports = Pool;
