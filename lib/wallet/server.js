/*!
 * server.js - wallet server for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const WalletDB = require('./walletdb');
const Config = require('../node/config');
const Logger = require('../node/logger');
const Client = require('./client');

/**
 * @exports wallet/server
 */

const server = exports;

/**
 * Create a wallet server.
 * @param {Object} options
 * @returns {WalletDB}
 */

server.create = function create(options) {
  let config = new Config('bcoin');
  let logger = new Logger('debug');
  let client, wdb;

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

  wdb = new WalletDB({
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

  wdb.on('error', () => {});

  return wdb;
};
