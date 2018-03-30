/*!
 * server.js - wallet server for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const Node = require('../node/node');
const WalletDB = require('./walletdb');
const HTTP = require('./http');
const Client = require('./client');
const RPC = require('./rpc');

/**
 * Wallet Node
 * @extends Node
 */

class WalletNode extends Node {
  /**
   * Create a wallet node.
   * @constructor
   * @param {Object?} options
   */

  constructor(options) {
    super('bcoin', 'wallet.conf', 'wallet.log', options);

    this.opened = false;

    this.client = new Client({
      network: this.network,
      url: this.config.str('node-url'),
      host: this.config.str('node-host'),
      port: this.config.str('node-port', this.network.rpcPort),
      ssl: this.config.str('node-ssl'),
      apiKey: this.config.str('node-api-key')
    });

    this.wdb = new WalletDB({
      network: this.network,
      logger: this.logger,
      workers: this.workers,
      client: this.client,
      prefix: this.config.prefix,
      memory: this.config.bool('memory'),
      maxFiles: this.config.uint('max-files'),
      cacheSize: this.config.mb('cache-size'),
      witness: this.config.bool('witness'),
      checkpoints: this.config.bool('checkpoints'),
      wipeNoReally: this.config.bool('wipe-no-really'),
      spv: this.config.bool('spv')
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
      walletAuth: this.config.bool('wallet-auth'),
      noAuth: this.config.bool('no-auth'),
      cors: this.config.bool('cors'),
      adminToken: this.config.str('admin-token')
    });

    this.init();
  }

  /**
   * Initialize the node.
   * @private
   */

  init() {
    this.wdb.on('error', err => this.error(err));
    this.http.on('error', err => this.error(err));

    this.loadPlugins();
  }

  /**
   * Open the node and all its child objects,
   * wait for the database to load.
   * @returns {Promise}
   */

  async open() {
    assert(!this.opened, 'WalletNode is already open.');
    this.opened = true;

    await this.handlePreopen();
    await this.wdb.open();

    this.rpc.wallet = this.wdb.primary;

    await this.openPlugins();

    await this.http.open();
    await this.handleOpen();

    this.logger.info('Wallet node is loaded.');
  }

  /**
   * Close the node, wait for the database to close.
   * @returns {Promise}
   */

  async close() {
    assert(this.opened, 'WalletNode is not open.');
    this.opened = false;

    await this.handlePreclose();
    await this.http.close();

    await this.closePlugins();

    this.rpc.wallet = null;

    await this.wdb.close();
    await this.handleClose();
  }
}

/*
 * Expose
 */

module.exports = WalletNode;
