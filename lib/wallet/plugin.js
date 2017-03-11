/*!
 * plugin.js - wallet plugin for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var WalletDB = require('./walletdb');
var NodeClient = require('../node/nodeclient');

/**
 * @exports wallet/plugin
 */

var plugin = exports;

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
  var config = node.config;
  var client = new NodeClient(node);
  var wdb;

  wdb = new WalletDB({
    network: node.network,
    logger: node.logger,
    client: client,
    prefix: config.prefix,
    db: config.str(['wallet-db', 'db']),
    maxFiles: config.num('wallet-max-files'),
    cacheSize: config.mb('wallet-cache-size'),
    witness: config.bool('wallet-witness'),
    checkpoints: config.bool('wallet-checkpoints'),
    startHeight: config.num('wallet-start-height'),
    wipeNoReally: config.bool('wallet-wipe-no-really'),
    apiKey: config.str(['wallet-api-key', 'api-key']),
    walletAuth: config.bool('wallet-auth'),
    noAuth: config.bool(['wallet-no-auth', 'no-auth']),
    ssl: config.str('wallet-ssl'),
    host: config.str('wallet-host'),
    port: config.num('wallet-port'),
    spv: node.spv,
    verify: node.spv,
    listen: false
  });

  if (node.http && wdb.http)
    wdb.http.attach(node.http);

  wdb.rpc.attach(node.rpc);

  return wdb;
};
