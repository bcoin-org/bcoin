/*!
 * walletonlynode.js - WalletOnlyNode node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const Node = require('./node');
const notavail = new Object();

/**
 * WalletOnlyNode Node
 * Create an WalletOnlyNode node which only maintains a wallet.
 * @alias module:node.WalletOnlyNode
 * @extends Node
 */

class WalletOnlyNode extends Node {
  /**
   * Create WalletOnlyNode node.
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

    this.chain = new Proxy(notavail, {
      get(target, name) {
        throw new Error('Chain methods not available in wallet-only mode');
      }
    });

    this.pool = new Proxy(notavail, {
      get(target, name) {
        throw new Error('Pool methods not available in wallet-only mode');
      }
    });

    this.http = new Proxy(notavail, {
      get(target, name) {
        throw new Error('Node http methods not available in wallet-only mode');
      }
    });

    this.rpc = new Proxy(notavail, {
      get(target, name) {
        throw new Error('Node RPC methods not available in wallet-only mode');
      }
    });

    this.init();
  }

  /**
   * Initialize the node.
   * @private
   */

  init() {
    this.loadPlugins();
  }

  /**
   * Open the node and all its child objects,
   * wait for the database to load.
   * @returns {Promise}
   */

  async open() {
    assert(!this.opened, 'WalletOnlyNode is already open.');
    this.opened = true;

    await this.handlePreopen();
    await this.openPlugins();
    await this.handleOpen();

    this.logger.info('WalletOnlyNode is loaded.');
  }

  /**
   * Close the node, wait for the database to close.
   * @returns {Promise}
   */

  async close() {
    assert(this.opened, 'WalletOnlyNode is not open.');
    this.opened = false;

    await this.handlePreclose();
    await this.http.close();
    await this.closePlugins();
    await this.handleClose();
  }
}

/*
 * Expose
 */

module.exports = WalletOnlyNode;
