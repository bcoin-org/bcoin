/*!
 * plugin.js - wallet plugin for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const EventEmitter = require('events');
const WalletDB = require('./walletdb');
const NodeClient = require('./nodeclient');
const HTTPServer = require('./http');
const RPC = require('./rpc');

/**
 * @exports wallet/plugin
 */

const plugin = exports;

/**
 * Plugin
 * @constructor
 * @param {Node} node
 */

function Plugin(node) {
  if (!(this instanceof Plugin))
    return new Plugin(node);

  const config = node.config;

  this.network = node.network;
  this.logger = node.logger;

  this.client = new NodeClient(node);
  this.plugin = true;

  this.wdb = new WalletDB({
    network: node.network,
    logger: node.logger,
    workers: node.workers,
    client: this.client,
    prefix: config.prefix,
    db: config.str(['wallet-db', 'db']),
    maxFiles: config.uint('wallet-max-files'),
    cacheSize: config.mb('wallet-cache-size'),
    witness: config.bool('wallet-witness'),
    checkpoints: config.bool('wallet-checkpoints'),
    startHeight: config.uint('wallet-start-height'),
    wipeNoReally: config.bool('wallet-wipe-no-really'),
    spv: node.spv
  });

  this.rpc = new RPC(this);

  this.http = new HTTPServer({
    network: node.network,
    logger: node.logger,
    node: this,
    apiKey: config.str(['wallet-api-key', 'api-key']),
    walletAuth: config.bool('wallet-auth'),
    noAuth: config.bool(['wallet-no-auth', 'no-auth'])
  });

  this.http.attach('/wallet', node.http);

  this.init();
}

Object.setPrototypeOf(Plugin.prototype, EventEmitter.prototype);

Plugin.prototype.init = function init() {
  this.client.on('error', err => this.emit('error', err));
  this.wdb.on('error', err => this.emit('error', err));
  this.http.on('error', err => this.emit('error', err));
};

Plugin.prototype.open = async function open() {
  await this.wdb.open();
  this.rpc.wallet = this.wdb.primary;
};

Plugin.prototype.close = async function close() {
  this.rpc.wallet = this.wdb.primary;
  await this.wdb.open();
};

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
