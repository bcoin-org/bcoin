/*!
 * plugin.js - wallet plugin for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const EventEmitter = require('events');
const WalletDB = require('./walletdb');
const NodeClient = require('./nodeclient');
const HTTP = require('./http');
const RPC = require('./rpc');

/**
 * @exports wallet/plugin
 */

const plugin = exports;

/**
 * Plugin
 * @extends EventEmitter
 */

class Plugin extends EventEmitter {
  /**
   * Create a plugin.
   * @constructor
   * @param {Node} node
   */

  constructor(node) {
    super();

    this.config = node.config.filter('wallet');
    this.config.open('wallet.conf');

    this.network = node.network;
    this.logger = node.logger;

    this.client = new NodeClient(node);

    this.wdb = new WalletDB({
      network: this.network,
      logger: this.logger,
      workers: this.workers,
      client: this.client,
      prefix: this.config.prefix,
      memory: this.config.bool('memory', node.memory),
      maxFiles: this.config.uint('max-files'),
      cacheSize: this.config.mb('cache-size'),
      witness: this.config.bool('witness'),
      checkpoints: this.config.bool('checkpoints'),
      wipeNoReally: this.config.bool('wipe-no-really'),
      spv: node.spv
    });

    this.rpc = new RPC(this);

    this.http = new HTTP({
      network: this.network,
      logger: this.logger,
      node: this,
      ssl: this.config.bool('ssl'),
      keyFile: this.config.path('ssl-key'),
      certFile: this.config.path('ssl-cert'),
      host: this.config.str('http-host'),
      port: this.config.uint('http-port'),
      apiKey: this.config.str('api-key', node.config.str('api-key')),
      walletAuth: this.config.bool('wallet-auth'),
      noAuth: this.config.bool('no-auth'),
      cors: this.config.bool('cors'),
      adminToken: this.config.str('admin-token')
    });

    this.init();
  }

  init() {
    this.wdb.on('error', err => this.emit('error', err));
    this.http.on('error', err => this.emit('error', err));
  }

  async open() {
    await this.wdb.open();
    this.rpc.wallet = this.wdb.primary;
    await this.http.open();
  }

  async close() {
    await this.http.close();
    this.rpc.wallet = null;
    await this.wdb.close();
  }
}

/**
 * Plugin name.
 * @const {String}
 */

plugin.id = 'walletdb';

/**
 * Plugin initialization.
 * @param {Node} node
 * @returns {WalletDB}
 */

plugin.init = function init(node) {
  return new Plugin(node);
};
