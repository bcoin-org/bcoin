/*!
 * blockstore/index.js - bitcoin blockstore for bcoin
 * Copyright (c) 2019, Braydon Fuller (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {join} = require('path');

const AbstractBlockStore = require('./abstract');
const LevelBlockStore = require('./level');

/**
 * @module blockstore
 */

exports.create = (options) => {
  const location = join(options.prefix, 'blocks');

  return new LevelBlockStore({
    network: options.network,
    logger: options.logger,
    location: location,
    cacheSize: options.cacheSize,
    memory: options.memory
  });
};

exports.AbstractBlockStore = AbstractBlockStore;
exports.LevelBlockStore = LevelBlockStore;
