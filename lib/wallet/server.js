/*!
 * server.js - wallet server for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var WalletDB = require('./walletdb');
var Config = require('../node/config');
var Logger = require('../node/logger');
var Client = require('./client');

/**
 * @exports wallet/server
 */

var server = exports;

/**
 * Create a wallet server.
 * @param {Object} options
 * @returns {WalletDB}
 */

server.create = function create(options) {
  var config = new Config('bcoin');
  var logger = new Logger('debug');
  var client;

  config.inject(options);
  config.load(options);

  if (options.config)
    config.open('wallet.conf');

  if (config.has('logger'))
    logger = config.obj('logger');

  client = new Client({
    network: config.network,
    uri: config.str('node-uri'),
    apiKey: config.str('node-api-key')
  });

  logger.set({
    filename: config.bool('log-file')
      ? config.location('wallet.log')
      : null,
    level: config.str('log-level'),
    console: config.bool('log-console'),
    shrink: config.bool('log-shrink')
  });

  return new WalletDB({
    network: config.network,
    logger: logger,
    client: client,
    prefix: config.prefix,
    db: config.str('db'),
    maxFiles: config.num('max-files'),
    cacheSize: config.mb('cache-size'),
    witness: config.bool('witness'),
    checkpoints: config.bool('checkpoints'),
    startHeight: config.num('start-height'),
    wipeNoReally: config.bool('wipe-no-really'),
    apiKey: config.str('api-key'),
    walletAuth: config.bool('auth'),
    noAuth: config.bool('no-auth'),
    ssl: config.str('ssl'),
    host: config.str('host'),
    port: config.num('port'),
    spv: config.bool('spv'),
    verify: config.bool('spv'),
    listen: true
  });
};
