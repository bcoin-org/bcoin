/*!
 * workerpool.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

/* eslint no-nested-ternary: "off" */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const os = require('os');
const Network = require('../protocol/network');
const Child = require('./child');
const jobs = require('./jobs');
const Parser = require('./parser');
const Framer = require('./framer');
const packets = require('./packets');

/**
 * Worker Pool
 * @alias module:workers.WorkerPool
 * @extends EventEmitter
 * @property {Number} size
 * @property {Number} timeout
 * @property {Map} children
 * @property {Number} uid
 */

class WorkerPool extends EventEmitter {
  /**
   * Create a worker pool.
   * @constructor
   * @param {Object} options
   * @param {Number} [options.size=num-cores] - Max pool size.
   * @param {Number} [options.timeout=120000] - Execution timeout.
   */

  constructor(options) {
    super();

    this.enabled = false;
    this.size = getCores();
    this.timeout = 120000;
    this.file = process.env.BCOIN_WORKER_FILE || 'worker.js';

    this.children = new Map();
    this.uid = 0;

    this.set(options);
  }

  /**
   * Set worker pool options.
   * @param {Object} options
   */

  set(options) {
    if (!options)
      return;

    if (options.enabled != null) {
      assert(typeof options.enabled === 'boolean');
      this.enabled = options.enabled;
    }

    if (options.size != null) {
      assert((options.size >>> 0) === options.size);
      assert(options.size > 0);
      this.size = options.size;
    }

    if (options.timeout != null) {
      assert(Number.isSafeInteger(options.timeout));
      assert(options.timeout >= -1);
      this.timeout = options.timeout;
    }

    if (options.file != null) {
      assert(typeof options.file === 'string');
      this.file = options.file;
    }
  }

  /**
   * Open worker pool.
   * @returns {Promise}
   */

  async open() {
    ;
  }

  /**
   * Close worker pool.
   * @returns {Promise}
   */

  async close() {
    this.destroy();
  }

  /**
   * Spawn a new worker.
   * @param {Number} id - Worker ID.
   * @returns {Worker}
   */

  spawn(id) {
    const child = new Worker(this.file);

    child.id = id;

    child.on('error', (err) => {
      this.emit('error', err, child);
    });

    child.on('exit', (code) => {
      this.emit('exit', code, child);

      if (this.children.get(id) === child)
        this.children.delete(id);
    });

    child.on('event', (items) => {
      this.emit('event', items, child);
      this.emit(...items);
    });

    child.on('log', (text) => {
      this.emit('log', text, child);
    });

    this.emit('spawn', child);

    return child;
  }

  /**
   * Allocate a new worker, will not go above `size` option
   * and will automatically load balance the workers.
   * @returns {Worker}
   */

  alloc() {
    const id = this.uid++ % this.size;

    if (!this.children.has(id))
      this.children.set(id, this.spawn(id));

    return this.children.get(id);
  }

  /**
   * Emit an event on the worker side (all workers).
   * @param {String} event
   * @param {...Object} arg
   * @returns {Boolean}
   */

  sendEvent() {
    let result = true;

    for (const child of this.children.values()) {
      if (!child.sendEvent.apply(child, arguments))
        result = false;
    }

    return result;
  }

  /**
   * Destroy all workers.
   */

  destroy() {
    for (const child of this.children.values())
      child.destroy();
  }

  /**
   * Call a method for a worker to execute.
   * @param {Packet} packet
   * @param {Number} timeout
   * @returns {Promise}
   */

  execute(packet, timeout) {
    if (!this.enabled || !Child.hasSupport()) {
      return new Promise((resolve, reject) => {
        setImmediate(() => {
          let result;
          try {
            result = jobs.handle(packet);
          } catch (e) {
            reject(e);
            return;
          }
          resolve(result);
        });
      });
    }

    if (!timeout)
      timeout = this.timeout;

    const child = this.alloc();

    return child.execute(packet, timeout);
  }

  /**
   * Execute the tx check job (default timeout).
   * @method
   * @param {TX} tx
   * @param {CoinView} view
   * @param {VerifyFlags} flags
   * @returns {Promise}
   */

  async check(tx, view, flags) {
    const packet = new packets.CheckPacket(tx, view, flags);
    const result = await this.execute(packet, -1);

    if (result.error)
      throw result.error;

    return null;
  }

  /**
   * Execute the tx signing job (default timeout).
   * @method
   * @param {MTX} tx
   * @param {KeyRing[]} ring
   * @param {SighashType} type
   * @returns {Promise}
   */

  async sign(tx, ring, type) {
    let rings = ring;

    if (!Array.isArray(rings))
      rings = [rings];

    const packet = new packets.SignPacket(tx, rings, type);
    const result = await this.execute(packet, -1);

    result.inject(tx);

    return result.total;
  }

  /**
   * Execute the tx input check job (default timeout).
   * @method
   * @param {TX} tx
   * @param {Number} index
   * @param {Coin|Output} coin
   * @param {VerifyFlags} flags
   * @returns {Promise}
   */

  async checkInput(tx, index, coin, flags) {
    const packet = new packets.CheckInputPacket(tx, index, coin, flags);
    const result = await this.execute(packet, -1);

    if (result.error)
      throw result.error;

    return null;
  }

  /**
   * Execute the tx input signing job (default timeout).
   * @method
   * @param {MTX} tx
   * @param {Number} index
   * @param {Coin|Output} coin
   * @param {KeyRing} ring
   * @param {SighashType} type
   * @returns {Promise}
   */

  async signInput(tx, index, coin, ring, type) {
    const packet = new packets.SignInputPacket(tx, index, coin, ring, type);
    const result = await this.execute(packet, -1);
    result.inject(tx);
    return result.value;
  }

  /**
   * Execute the secp256k1 verify job (no timeout).
   * @method
   * @param {Buffer} msg
   * @param {Buffer} sig - DER formatted.
   * @param {Buffer} key
   * @returns {Promise}
   */

  async ecVerify(msg, sig, key) {
    const packet = new packets.ECVerifyPacket(msg, sig, key);
    const result = await this.execute(packet, -1);
    return result.value;
  }

  /**
   * Execute the secp256k1 signing job (no timeout).
   * @method
   * @param {Buffer} msg
   * @param {Buffer} key
   * @returns {Promise}
   */

  async ecSign(msg, key) {
    const packet = new packets.ECSignPacket(msg, key);
    const result = await this.execute(packet, -1);
    return result.sig;
  }

  /**
   * Execute the mining job (no timeout).
   * @method
   * @param {Buffer} data
   * @param {Buffer} target
   * @param {Number} min
   * @param {Number} max
   * @returns {Promise} - Returns {Number}.
   */

  async mine(data, target, min, max) {
    const packet = new packets.MinePacket(data, target, min, max);
    const result = await this.execute(packet, -1);
    return result.nonce;
  }

  /**
   * Execute scrypt job (no timeout).
   * @method
   * @param {Buffer} passwd
   * @param {Buffer} salt
   * @param {Number} N
   * @param {Number} r
   * @param {Number} p
   * @param {Number} len
   * @returns {Promise}
   */

  async scrypt(passwd, salt, N, r, p, len) {
    const packet = new packets.ScryptPacket(passwd, salt, N, r, p, len);
    const result = await this.execute(packet, -1);
    return result.key;
  }
}

/**
 * Worker
 * @alias module:workers.Worker
 * @extends EventEmitter
 */

class Worker extends EventEmitter {
  /**
   * Create a worker.
   * @constructor
   * @param {String} file
   */

  constructor(file) {
    super();

    this.id = -1;
    this.framer = new Framer();
    this.parser = new Parser();
    this.pending = new Map();

    this.child = new Child(file);

    this.init();
  }

  /**
   * Initialize worker. Bind to events.
   * @private
   */

  init() {
    this.child.on('data', (data) => {
      this.parser.feed(data);
    });

    this.child.on('exit', (code, signal) => {
      this.emit('exit', code, signal);
    });

    this.child.on('error', (err) => {
      this.emit('error', err);
    });

    this.parser.on('error', (err) => {
      this.emit('error', err);
    });

    this.parser.on('packet', (packet) => {
      this.emit('packet', packet);
    });

    this.listen();
  }

  /**
   * Listen for packets.
   * @private
   */

  listen() {
    this.on('exit', (code, signal) => {
      this.killJobs();
    });

    this.on('error', (err) => {
      this.killJobs();
    });

    this.on('packet', (packet) => {
      try {
        this.handlePacket(packet);
      } catch (e) {
        this.emit('error', e);
      }
    });

    this.sendEnv({
      BCOIN_WORKER_NETWORK: Network.type,
      BCOIN_WORKER_ISTTY: process.stdout
        ? (process.stdout.isTTY ? '1' : '0')
        : '0'
    });
  }

  /**
   * Handle packet.
   * @private
   * @param {Packet} packet
   */

  handlePacket(packet) {
    switch (packet.cmd) {
      case packets.types.EVENT:
        this.emit('event', packet.items);
        this.emit(...packet.items);
        break;
      case packets.types.LOG:
        this.emit('log', packet.text);
        break;
      case packets.types.ERROR:
        this.emit('error', packet.error);
        break;
      case packets.types.ERRORRESULT:
        this.rejectJob(packet.id, packet.error);
        break;
      default:
        this.resolveJob(packet.id, packet);
        break;
    }
  }

  /**
   * Send data to worker.
   * @param {Buffer} data
   * @returns {Boolean}
   */

  write(data) {
    return this.child.write(data);
  }

  /**
   * Frame and send a packet.
   * @param {Packet} packet
   * @returns {Boolean}
   */

  send(packet) {
    return this.write(this.framer.packet(packet));
  }

  /**
   * Send environment.
   * @param {Object} env
   * @returns {Boolean}
   */

  sendEnv(env) {
    return this.send(new packets.EnvPacket(env));
  }

  /**
   * Emit an event on the worker side.
   * @param {String} event
   * @param {...Object} arg
   * @returns {Boolean}
   */

  sendEvent(...items) {
    return this.send(new packets.EventPacket(items));
  }

  /**
   * Destroy the worker.
   */

  destroy() {
    return this.child.destroy();
  }

  /**
   * Call a method for a worker to execute.
   * @param {Packet} packet
   * @param {Number} timeout
   * @returns {Promise}
   */

  execute(packet, timeout) {
    return new Promise((resolve, reject) => {
      this._execute(packet, timeout, resolve, reject);
    });
  }

  /**
   * Call a method for a worker to execute.
   * @private
   * @param {Packet} packet
   * @param {Number} timeout
   * @param {Function} resolve
   * @param {Function} reject
   * the worker method specifies.
   */

  _execute(packet, timeout, resolve, reject) {
    const job = new PendingJob(this, packet.id, resolve, reject);

    assert(!this.pending.has(packet.id), 'ID overflow.');

    this.pending.set(packet.id, job);

    job.start(timeout);

    this.send(packet);
  }

  /**
   * Resolve a job.
   * @param {Number} id
   * @param {Packet} result
   */

  resolveJob(id, result) {
    const job = this.pending.get(id);

    if (!job)
      throw new Error(`Job ${id} is not in progress.`);

    job.resolve(result);
  }

  /**
   * Reject a job.
   * @param {Number} id
   * @param {Error} err
   */

  rejectJob(id, err) {
    const job = this.pending.get(id);

    if (!job)
      throw new Error(`Job ${id} is not in progress.`);

    job.reject(err);
  }

  /**
   * Kill all jobs associated with worker.
   */

  killJobs() {
    for (const job of this.pending.values())
      job.destroy();
  }
}

/**
 * Pending Job
 * @ignore
 */

class PendingJob {
  /**
   * Create a pending job.
   * @constructor
   * @param {Worker} worker
   * @param {Number} id
   * @param {Function} resolve
   * @param {Function} reject
   */

  constructor(worker, id, resolve, reject) {
    this.worker = worker;
    this.id = id;
    this.job = { resolve, reject };
    this.timer = null;
  }

  /**
   * Start the timer.
   * @param {Number} timeout
   */

  start(timeout) {
    if (!timeout || timeout <= 0)
      return;

    this.timer = setTimeout(() => {
      this.reject(new Error('Worker timed out.'));
    }, timeout);
  }

  /**
   * Destroy the job with an error.
   */

  destroy() {
    this.reject(new Error('Job was destroyed.'));
  }

  /**
   * Cleanup job state.
   * @returns {Job}
   */

  cleanup() {
    const job = this.job;

    assert(job, 'Already finished.');

    this.job = null;

    if (this.timer != null) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    assert(this.worker.pending.has(this.id));
    this.worker.pending.delete(this.id);

    return job;
  }

  /**
   * Complete job with result.
   * @param {Object} result
   */

  resolve(result) {
    const job = this.cleanup();
    job.resolve(result);
  }

  /**
   * Complete job with error.
   * @param {Error} err
   */

  reject(err) {
    const job = this.cleanup();
    job.reject(err);
  }
}

/*
 * Helpers
 */

function getCores() {
  return Math.max(2, os.cpus().length);
}

/*
 * Expose
 */

module.exports = WorkerPool;
