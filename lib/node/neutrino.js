/*!
 * neutrino.js - spv node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const Chain = require('../blockchain/chain');
const Pool = require('../net/pool');
const Node = require('./node');
const HTTP = require('./http');
const RPC = require('./rpc');
const blockstore = require('../blockstore');
const FilterIndexer = require('../indexer/filterindexer');

/**
 * Neutrino Node
 * Create a neutrino node which only maintains
 * a chain, a pool, and an http server.
 * @alias module:node.Neutrino
 * @extends Node
 */

class Neutrino extends Node {
  /**
   * Create Neutrino node.
   * @constructor
   * @param {Object?} options
   * @param {Buffer?} options.sslKey
   * @param {Buffer?} options.sslCert
   * @param {Number?} options.httpPort
   * @param {String?} options.httpHost
   */

  constructor(options) {
    super('bcoin', 'bcoin.conf', 'debug.log', options);

    this.opened = false;

    // SPV flag.
    this.spv = false;
    this.neutrino = true;

    // Instantiate block storage.
    this.blocks = blockstore.create({
      network: this.network,
      logger: this.logger,
      prefix: this.config.prefix,
      cacheSize: this.config.mb('block-cache-size'),
      memory: this.memory,
      spv: this.spv,
      neutrino: this.neutrino
    });

    this.chain = new Chain({
      blocks: this.blocks,
      network: this.network,
      logger: this.logger,
      prefix: this.config.prefix,
      memory: this.memory,
      maxFiles: this.config.uint('max-files'),
      cacheSize: this.config.mb('cache-size'),
      entryCache: this.config.uint('entry-cache'),
      forceFlags: this.config.bool('force-flags'),
      checkpoints: this.config.bool('checkpoints'),
      bip91: this.config.bool('bip91'),
      bip148: this.config.bool('bip148'),
      spv: true,
      neutrino: this.neutrino
    });

    this.filterIndexers.set(
      'BASIC',
      new FilterIndexer({
        network: this.network,
        logger: this.logger,
        blocks: this.blocks,
        chain: this.chain,
        memory: this.config.bool('memory'),
        prefix: this.config.str('index-prefix', this.config.prefix),
        filterType: 'BASIC'
      })
    );

    this.pool = new Pool({
      network: this.network,
      logger: this.logger,
      chain: this.chain,
      prefix: this.config.prefix,
      checkpoints: true,
      proxy: this.config.str('proxy'),
      onion: this.config.bool('onion'),
      upnp: this.config.bool('upnp'),
      seeds: this.config.array('seeds'),
      nodes: this.config.array('nodes'),
      only: this.config.array('only'),
      maxOutbound: this.config.uint('max-outbound'),
      createSocket: this.config.func('create-socket'),
      memory: this.memory,
      selfish: true,
      listen: false,
      neutrino: this.neutrino,
      spv: this.spv
    });

    this.rpc = new RPC(this);

    this.http = new HTTP({
      network: this.network,
      logger: this.logger,
      node: this,
      prefix: this.config.prefix,
      ssl: this.config.bool('ssl'),
      keyFile: this.config.path('ssl-key'),
      certFile: this.config.path('ssl-cert'),
      host: this.config.str('http-host'),
      port: this.config.uint('http-port'),
      apiKey: this.config.str('api-key'),
      noAuth: this.config.bool('no-auth'),
      cors: this.config.bool('cors')
    });

    this.init();
  }

  /**
   * Initialize the node.
   * @private
   */

  init() {
    console.log('Initializing Neutrino Node.');
    // Bind to errors
    this.chain.on('error', err => this.error(err));
    this.pool.on('error', err => this.error(err));

    if (this.http)
      this.http.on('error', err => this.error(err));

    this.pool.on('tx', (tx) => {
      this.emit('tx', tx);
    });

    this.chain.on('block', (block) => {
      this.emit('block', block);
    });

    this.chain.on('connect', async (entry, block) => {
      this.emit('connect', entry, block);
    });

    this.chain.on('disconnect', (entry, block) => {
      this.emit('disconnect', entry, block);
    });

    this.chain.on('reorganize', (tip, competitor) => {
      this.emit('reorganize', tip, competitor);
    });

    this.chain.on('reset', (tip) => {
      this.emit('reset', tip);
    });

    this.chain.on('headersFull', () => {
      this.logger.info('Block Headers are fully synced');
      console.log('Block Headers are fully synced \n\n\n\n\n');
      // this.pool.startFilterCheckPtSync(); // TODO: Maybe implement this later
      this.pool.startFilterHeadersSync();
    });

    this.pool.on('cfheaders', () => {
      this.logger.info('CF Headers Synced');
      this.pool.startFilterSync();
    });

    this.loadPlugins();
  }

  /**
   * Open the node and all its child objects,
   * wait for the database to load.
   * @returns {Promise}
   */

  async open() {
    assert(!this.opened, 'Neutrino Node is already open.');
    this.opened = true;

    await this.handlePreopen();
    await this.blocks.open();
    await this.chain.open();
    await this.pool.open();

    await this.openPlugins();

    await this.http.open();
    await this.handleOpen();

    this.logger.info('Node is loaded.');
  }

  /**
   * Close the node, wait for the database to close.
   * @returns {Promise}
   */

  async close() {
    assert(this.opened, 'Neutrino Node is not open.');
    this.opened = false;

    await this.handlePreclose();
    await this.http.close();

    await this.closePlugins();

    await this.pool.close();
    await this.chain.close();
    await this.handleClose();
  }

  /**
   * Scan for any missed transactions.
   * Note that this will replay the blockchain sync.
   * @param {Number|Hash} start - Start block.
   * @returns {Promise}
   */

  async scan(start) {
    throw new Error('Not implemented.');
  }

  /**
   * Broadcast a transaction (note that this will _not_ be verified
   * by the mempool - use with care, lest you get banned from
   * bitcoind nodes).
   * @param {TX|Block} item
   * @returns {Promise}
   */

  async broadcast(item) {
    try {
      await this.pool.broadcast(item);
    } catch (e) {
      this.emit('error', e);
    }
  }

  /**
   * Broadcast a transaction (note that this will _not_ be verified
   * by the mempool - use with care, lest you get banned from
   * bitcoind nodes).
   * @param {TX} tx
   * @returns {Promise}
   */

  sendTX(tx) {
    return this.broadcast(tx);
  }

  /**
   * Broadcast a transaction. Silence errors.
   * @param {TX} tx
   * @returns {Promise}
   */

  relay(tx) {
    return this.broadcast(tx);
  }

  /**
   * Connect to the network.
   * @returns {Promise}
   */

  connect() {
    return this.pool.connect();
  }

  /**
   * Disconnect from the network.
   * @returns {Promise}
   */

  disconnect() {
    return this.pool.disconnect();
  }

  /**
   * Start the blockchain sync.
   */

  startSync() {
    return this.pool.startSync();
  }

  /**
   * Stop syncing the blockchain.
   */

  stopSync() {
    return this.pool.stopSync();
  }
}

/*
 * Expose
 */

module.exports = Neutrino;
