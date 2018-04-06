/*!
 * node.js - node object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const fs = require('bfile');
const Logger = require('blgr');
const Config = require('bcfg');
const Network = require('../protocol/network');
const WorkerPool = require('../workers/workerpool');

/**
 * Node
 * Base class from which every other
 * Node-like object inherits.
 * @alias module:node.Node
 * @extends EventEmitter
 * @abstract
 */

class Node extends EventEmitter {
  /**
   * Create a node.
   * @constructor
   * @param {Object} options
   */

  constructor(module, config, file, options) {
    super();

    this.config = new Config(module, {
      suffix: 'network',
      fallback: 'main',
      alias: { 'n': 'network' }
    });

    this.config.inject(options);
    this.config.load(options);

    if (options.config)
      this.config.open(config);

    this.network = Network.get(this.config.getSuffix());
    this.memory = this.config.bool('memory', true);
    this.startTime = -1;
    this.bound = [];
    this.plugins = Object.create(null);
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

    this._init(file);
  }

  /**
   * Initialize node.
   * @private
   * @param {Object} options
   */

  _init(file) {
    const config = this.config;

    let logger = new Logger();

    if (config.has('logger'))
      logger = config.obj('logger');

    logger.set({
      filename: !this.memory && config.bool('log-file')
        ? config.location(file)
        : null,
      level: config.str('log-level'),
      console: config.bool('log-console'),
      shrink: config.bool('log-shrink')
    });

    this.logger = logger.context('node');

    this.workers = new WorkerPool({
      enabled: config.bool('workers'),
      size: config.uint('workers-size'),
      timeout: config.uint('workers-timeout'),
      file: config.str('worker-file')
    });

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
  }

  /**
   * Ensure prefix directory.
   * @returns {Promise}
   */

  async ensure() {
    if (fs.unsupported)
      return undefined;

    if (this.memory)
      return undefined;

    return fs.mkdirp(this.config.prefix);
  }

  /**
   * Create a file path using `prefix`.
   * @param {String} file
   * @returns {String}
   */

  location(name) {
    return this.config.location(name);
  }

  /**
   * Open node. Bind all events.
   * @private
   */

  async handlePreopen() {
    await this.logger.open();
    await this.workers.open();

    this._bind(this.network.time, 'offset', (offset) => {
      this.logger.info(
        'Time offset: %d (%d minutes).',
        offset, offset / 60 | 0);
    });

    this._bind(this.network.time, 'sample', (sample, total) => {
      this.logger.debug(
        'Added time data: samples=%d, offset=%d (%d minutes).',
        total, sample, sample / 60 | 0);
    });

    this._bind(this.network.time, 'mismatch', () => {
      this.logger.warning('Adjusted time mismatch!');
      this.logger.warning('Please make sure your system clock is correct!');
    });
  }

  /**
   * Open node.
   * @private
   */

  async handleOpen() {
    this.startTime = Date.now();

    if (!this.workers.enabled) {
      this.logger.warning('Warning: worker pool is disabled.');
      this.logger.warning('Verification will be slow.');
    }
  }

  /**
   * Open node. Bind all events.
   * @private
   */

  async handlePreclose() {
    ;
  }

  /**
   * Close node. Unbind all events.
   * @private
   */

  async handleClose() {
    for (const [obj, event, listener] of this.bound)
      obj.removeListener(event, listener);

    this.bound.length = 0;
    this.startTime = -1;

    await this.workers.close();
    await this.logger.close();
  }

  /**
   * Bind to an event on `obj`, save listener for removal.
   * @private
   * @param {EventEmitter} obj
   * @param {String} event
   * @param {Function} listener
   */

  _bind(obj, event, listener) {
    this.bound.push([obj, event, listener]);
    obj.on(event, listener);
  }

  /**
   * Emit and log an error.
   * @private
   * @param {Error} err
   */

  error(err) {
    this.logger.error(err);
    this.emit('error', err);
  }

  /**
   * Get node uptime in seconds.
   * @returns {Number}
   */

  uptime() {
    if (this.startTime === -1)
      return 0;

    return Math.floor((Date.now() - this.startTime) / 1000);
  }

  /**
   * Attach a plugin.
   * @param {Object} plugin
   * @returns {Object} Plugin instance.
   */

  use(plugin) {
    assert(plugin, 'Plugin must be an object.');
    assert(typeof plugin.init === 'function', '`init` must be a function.');

    assert(!this.loaded, 'Cannot add plugin after node is loaded.');

    const instance = plugin.init(this);

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
  }

  /**
   * Test whether a plugin is available.
   * @param {String} name
   * @returns {Boolean}
   */

  has(name) {
    return this.plugins[name] != null;
  }

  /**
   * Get a plugin.
   * @param {String} name
   * @returns {Object|null}
   */

  get(name) {
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

    return this.plugins[name] || null;
  }

  /**
   * Require a plugin.
   * @param {String} name
   * @returns {Object}
   * @throws {Error} on onloaded plugin
   */

  require(name) {
    const plugin = this.get(name);
    assert(plugin, `${name} is not loaded.`);
    return plugin;
  }

  /**
   * Load plugins.
   * @private
   */

  loadPlugins() {
    const plugins = this.config.array('plugins', []);
    const loader = this.config.func('loader');

    for (let plugin of plugins) {
      if (typeof plugin === 'string') {
        assert(loader, 'Must pass a loader function.');
        plugin = loader(plugin);
      }
      this.use(plugin);
    }
  }

  /**
   * Open plugins.
   * @private
   */

  async openPlugins() {
    for (const plugin of this.stack) {
      if (plugin.open)
        await plugin.open();
    }
  }

  /**
   * Close plugins.
   * @private
   */

  async closePlugins() {
    for (const plugin of this.stack) {
      if (plugin.close)
        await plugin.close();
    }
  }
}

/*
 * Expose
 */

module.exports = Node;
