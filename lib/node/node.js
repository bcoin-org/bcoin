/*!
 * node.js - node object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const AsyncObject = require('../utils/asyncobject');
const util = require('../utils/util');
const Network = require('../protocol/network');
const Logger = require('./logger');
const WorkerPool = require('../workers/workerpool');
const secp256k1 = require('../crypto/secp256k1');
const native = require('../native');
const Config = require('./config');

/**
 * Base class from which every other
 * Node-like object inherits.
 * @alias module:node.Node
 * @constructor
 * @abstract
 * @param {Object} options
 */

function Node(options) {
  if (!(this instanceof Node))
    return new Node(options);

  AsyncObject.call(this);

  this.config = new Config('bcoin');
  this.config.inject(options);
  this.config.load(options);

  if (options.config)
    this.config.open('bcoin.conf');

  this.network = Network.get(this.config.network);
  this.startTime = -1;
  this.bound = [];
  this.plugins = {};
  this.stack = [];

  this.logger = null;
  this.workers = null;

  this.spv = false;
  this.chain = null;
  this.fees = null;
  this.mempool = null;
  this.pool = null;
  this.miner = null;
  this.http = null;

  this.init();
}

util.inherits(Node, AsyncObject);

/**
 * Initialize options.
 * @private
 * @param {Object} options
 */

Node.prototype.initOptions = function initOptions() {
  let logger = new Logger();
  let config = this.config;

  if (config.has('logger'))
    logger = config.obj('logger');

  logger.set({
    filename: config.bool('log-file')
      ? config.location('debug.log')
      : null,
    level: config.str('log-level'),
    console: config.bool('log-console'),
    shrink: config.bool('log-shrink')
  });

  this.logger = logger.context('node');

  this.workers = new WorkerPool({
    enabled: config.bool('workers'),
    size: config.num('workers-size'),
    timeout: config.num('workers-timeout'),
    file: config.str('worker-file')
  });
};

/**
 * Initialize node.
 * @private
 * @param {Object} options
 */

Node.prototype.init = function init() {
  this.initOptions();

  this.on('error', () => {});

  this.workers.on('spawn', (child) => {
    this.logger.info('Spawning worker process: %d.', child.id);
  });

  this.workers.on('exit', (code, child) => {
    this.logger.warning('Worker %d exited: %s.', child.id, code);
  });

  this.workers.on('log', (text, child) => {
    this.logger.debug('Worker %d says:', child.id);
    this.logger.debug(text);
  });

  this.workers.on('error', (err, child) => {
    if (child) {
      this.logger.error('Worker %d error: %s', child.id, err.message);
      return;
    }
    this.emit('error', err);
  });

  this.hook('preopen', () => this.handlePreopen());
  this.hook('preclose', () => this.handlePreclose());
  this.hook('open', () => this.handleOpen());
  this.hook('close', () => this.handleClose());
};

/**
 * Ensure prefix directory.
 * @returns {Promise}
 */

Node.prototype.ensure = function ensure() {
  return this.config.ensure();
};

/**
 * Create a file path using `prefix`.
 * @param {String} file
 * @returns {String}
 */

Node.prototype.location = function location(name) {
  return this.config.location(name);
};

/**
 * Open node. Bind all events.
 * @private
 */

Node.prototype.handlePreopen = async function handlePreopen() {
  await this.logger.open();
  await this.workers.open();

  this.bind(this.network.time, 'offset', (offset) => {
    this.logger.info('Time offset: %d (%d minutes).', offset, offset / 60 | 0);
  });

  this.bind(this.network.time, 'sample', (sample, total) => {
    this.logger.debug(
      'Added time data: samples=%d, offset=%d (%d minutes).',
      total, sample, sample / 60 | 0);
  });

  this.bind(this.network.time, 'mismatch', () => {
    this.logger.warning('Adjusted time mismatch!');
    this.logger.warning('Please make sure your system clock is correct!');
  });
};

/**
 * Open node.
 * @private
 */

Node.prototype.handleOpen = async function handleOpen() {
  this.startTime = util.now();

  if (!secp256k1.binding) {
    this.logger.warning('Warning: secp256k1-node was not built.');
    this.logger.warning('Verification will be slow.');
  }

  if (!native.binding) {
    this.logger.warning('Warning: bcoin-native was not built.');
    this.logger.warning('Hashing will be slow.');
  }

  if (!this.workers.enabled) {
    this.logger.warning('Warning: worker pool is disabled.');
    this.logger.warning('Verification will be slow.');
  }
};

/**
 * Open node. Bind all events.
 * @private
 */

Node.prototype.handlePreclose = async function handlePreclose() {
  ;
};

/**
 * Close node. Unbind all events.
 * @private
 */

Node.prototype.handleClose = async function handleClose() {
  for (let [obj, event, listener] of this.bound)
    obj.removeListener(event, listener);

  this.bound.length = 0;
  this.startTime = -1;

  await this.workers.close();
  await this.logger.close();
};

/**
 * Bind to an event on `obj`, save listener for removal.
 * @private
 * @param {EventEmitter} obj
 * @param {String} event
 * @param {Function} listener
 */

Node.prototype.bind = function bind(obj, event, listener) {
  this.bound.push([obj, event, listener]);
  obj.on(event, listener);
};

/**
 * Emit and log an error.
 * @private
 * @param {Error} err
 */

Node.prototype.error = function error(err) {
  this.logger.error(err);
  this.emit('error', err);
};

/**
 * Get node uptime in seconds.
 * @returns {Number}
 */

Node.prototype.uptime = function uptime() {
  if (this.startTime === -1)
    return 0;

  return util.now() - this.startTime;
};

/**
 * Attach a plugin.
 * @param {Object} plugin
 * @returns {Object} Plugin instance.
 */

Node.prototype.use = function use(plugin) {
  let instance;

  assert(plugin, 'Plugin must be an object.');
  assert(typeof plugin.init === 'function', '`init` must be a function.');

  assert(!this.loaded, 'Cannot add plugin after node is loaded.');

  instance = plugin.init(this);

  assert(!instance.open || typeof instance.open === 'function',
    '`open` must be a function.');
  assert(!instance.close || typeof instance.close === 'function',
    '`close` must be a function.');

  if (plugin.id) {
    assert(typeof plugin.id === 'string', '`id` must be a string.');

    // Reserved names
    switch (plugin.id) {
      case 'chain':
      case 'fees':
      case 'mempool':
      case 'miner':
      case 'pool':
      case 'rpc':
      case 'http':
        assert(false, `${plugin.id} is already added.`);
        break;
    }

    assert(!this.plugins[plugin.id], `${plugin.id} is already added.`);

    this.plugins[plugin.id] = instance;
  }

  this.stack.push(instance);

  if (typeof instance.on === 'function')
    instance.on('error', err => this.error(err));

  return instance;
};

/**
 * Test whether a plugin is available.
 * @param {String} name
 * @returns {Boolean}
 */

Node.prototype.has = function has(name) {
  return this.plugins[name] != null;
};

/**
 * Get a plugin.
 * @param {String} name
 * @returns {Object|null}
 */

Node.prototype.get = function get(name) {
  assert(typeof name === 'string', 'Plugin name must be a string.');

  // Reserved names.
  switch (name) {
    case 'chain':
      assert(this.chain, 'chain is not loaded.');
      return this.chain;
    case 'fees':
      assert(this.fees, 'fees is not loaded.');
      return this.fees;
    case 'mempool':
      assert(this.mempool, 'mempool is not loaded.');
      return this.mempool;
    case 'miner':
      assert(this.miner, 'miner is not loaded.');
      return this.miner;
    case 'pool':
      assert(this.pool, 'pool is not loaded.');
      return this.pool;
    case 'rpc':
      assert(this.rpc, 'rpc is not loaded.');
      return this.rpc;
    case 'http':
      assert(this.http, 'http is not loaded.');
      return this.http;
  }

  return this.plugins[name];
};

/**
 * Require a plugin.
 * @param {String} name
 * @returns {Object}
 * @throws {Error} on onloaded plugin
 */

Node.prototype.require = function require(name) {
  let plugin = this.get(name);
  assert(plugin, `${name} is not loaded.`);
  return plugin;
};

/**
 * Load plugins.
 * @private
 */

Node.prototype.loadPlugins = function loadPlugins() {
  let plugins = this.config.array('plugins', []);
  let loader = this.config.func('loader');

  for (let plugin of plugins) {
    if (typeof plugin === 'string') {
      assert(loader, 'Must pass a loader function.');
      plugin = loader(plugin);
    }
    this.use(plugin);
  }
};

/**
 * Open plugins.
 * @private
 */

Node.prototype.openPlugins = async function openPlugins() {
  for (let plugin of this.stack) {
    if (plugin.open)
      await plugin.open();
  }
};

/**
 * Close plugins.
 * @private
 */

Node.prototype.closePlugins = async function closePlugins() {
  for (let plugin of this.stack) {
    if (plugin.close)
      await plugin.close();
  }
};

/*
 * Expose
 */

module.exports = Node;
