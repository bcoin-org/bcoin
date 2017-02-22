/*!
 * workerpool.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var EventEmitter = require('events').EventEmitter;
var os = require('os');
var cp = require('child_process');
var util = require('../utils/util');
var co = require('../utils/co');
var global = util.global;
var Network = require('../protocol/network');
var jobs = require('./jobs');
var Parser = require('./parser');
var Framer = require('./framer');
var packets = require('./packets');

/**
 * A worker pool.
 * @alias module:workers.WorkerPool
 * @constructor
 * @param {Object} options
 * @param {Number} [options.size=num-cores] - Max pool size.
 * @param {Number} [options.timeout=10000] - Execution timeout.
 * @property {Number} size
 * @property {Number} timeout
 * @property {Object} children
 * @property {Number} nonce
 */

function WorkerPool(options) {
  if (!(this instanceof WorkerPool))
    return new WorkerPool(options);

  EventEmitter.call(this);

  this.size = WorkerPool.CORES;
  this.timeout = 60000;
  this.children = [];
  this.nonce = 0;
  this.enabled = true;

  this.set(options);

  this.on('error', util.nop);
}

util.inherits(WorkerPool, EventEmitter);

/**
 * Whether workers are supported.
 * @const {Boolean}
 */

WorkerPool.support = true;

if (util.isBrowser) {
  WorkerPool.support = typeof global.Worker === 'function'
    || typeof global.postMessage === 'function';
}

/**
 * Number of CPUs/cores available.
 * @const {Number}
 */

WorkerPool.CORES = getCores();

/**
 * Global list of workers.
 * @type {Array}
 */

WorkerPool.children = [];

/**
 * Destroy all workers.
 * Used for cleaning up workers on exit.
 * @private
 */

WorkerPool.cleanup = function cleanup() {
  while (WorkerPool.children.length > 0)
    WorkerPool.children.pop().destroy();
};

/**
 * Whether exit events have been bound globally.
 * @private
 * @type {Boolean}
 */

WorkerPool.bound = false;

/**
 * Bind to process events in
 * order to cleanup listeners.
 * @private
 */

WorkerPool.bindExit = function bindExit() {
  if (util.isBrowser)
    return;

  if (WorkerPool.bound)
    return;

  WorkerPool.bound = true;

  function onSignal() {
    WorkerPool.cleanup();
    process.exit(0);
  }

  function onError(err) {
    WorkerPool.cleanup();
    if (err && err.stack)
      util.error(err.stack + '');
    process.exit(1);
  }

  process.once('exit', function() {
    WorkerPool.cleanup();
  });

  if (process.listeners('SIGINT').length === 0)
    process.once('SIGINT', onSignal);

  if (process.listeners('SIGTERM').length === 0)
    process.once('SIGTERM', onSignal);

  if (process.listeners('uncaughtException').length === 0)
    process.once('uncaughtException', onError);

  process.on('newListener', function(name) {
    switch (name) {
      case 'SIGINT':
      case 'SIGTERM':
        process.removeListener(name, onSignal);
        break;
      case 'uncaughtException':
        process.removeListener(name, onError);
        break;
    }
  });
};

/**
 * Set worker pool options.
 * @param {Object} options
 */

WorkerPool.prototype.set = function set(options) {
  if (!options)
    return;

  if (options.enabled != null) {
    assert(typeof options.enabled === 'boolean');
    this.enabled = options.enabled;
  }

  if (options.size != null) {
    assert(util.isNumber(options.size));
    assert(options.size > 0);
    this.size = options.size;
  }

  if (options.timeout != null) {
    assert(util.isNumber(options.timeout));
    assert(options.timeout > 0);
    this.timeout = options.timeout;
  }
};

/**
 * Spawn a new worker.
 * @param {Number} id - Worker ID.
 * @returns {Worker}
 */

WorkerPool.prototype.spawn = function spawn(id) {
  var self = this;
  var child;

  child = new Worker(id);

  child.on('error', function(err) {
    self.emit('error', err, child);
  });

  child.on('exit', function(code) {
    self.emit('exit', code, child);
    if (self.children[child.id] === child)
      self.children[child.id] = null;
  });

  child.on('event', function(items) {
    self.emit('event', items, child);
    self.emit.apply(self, items);
  });

  this.emit('spawn', child);

  return child;
};

/**
 * Allocate a new worker, will not go above `size` option
 * and will automatically load balance the workers.
 * @returns {Worker}
 */

WorkerPool.prototype.alloc = function alloc() {
  var id = this.nonce++ % this.size;
  if (!this.children[id])
    this.children[id] = this.spawn(id);
  return this.children[id];
};

/**
 * Emit an event on the worker side (all workers).
 * @param {String} event
 * @param {...Object} arg
 * @returns {Boolean}
 */

WorkerPool.prototype.sendEvent = function sendEvent() {
  var result = true;
  var i, child;

  for (i = 0; i < this.children.length; i++) {
    child = this.children[i];

    if (!child)
      continue;

    if (!child.sendEvent.apply(child, arguments))
      result = false;
  }

  return result;
};

/**
 * Destroy all workers.
 */

WorkerPool.prototype.destroy = function destroy() {
  var i, child;

  for (i = 0; i < this.children.length; i++) {
    child = this.children[i];

    if (!child)
      continue;

    child.destroy();
  }
};

/**
 * Call a method for a worker to execute.
 * @param {Packet} packet
 * @param {Number} timeout
 * @returns {Promise}
 */

WorkerPool.prototype.execute = function execute(packet, timeout) {
  var result, child;

  if (!this.enabled || !WorkerPool.support) {
    return new Promise(function(resolve, reject) {
      util.nextTick(function() {
        try {
          result = jobs._execute(packet);
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

  child = this.alloc();

  return child.execute(packet, timeout);
};

/**
 * Execute the tx verification job (default timeout).
 * @method
 * @param {TX} tx
 * @param {CoinView} view
 * @param {VerifyFlags} flags
 * @returns {Promise} - Returns Boolean.
 */

WorkerPool.prototype.verify = co(function* verify(tx, view, flags) {
  var packet = new packets.VerifyPacket(tx, view, flags);
  var result = yield this.execute(packet, -1);
  return result.value;
});

/**
 * Execute the tx signing job (default timeout).
 * @method
 * @param {MTX} tx
 * @param {KeyRing[]} ring
 * @param {SighashType} type
 * @returns {Promise}
 */

WorkerPool.prototype.sign = co(function* sign(tx, ring, type) {
  var rings = ring;
  var packet, result;

  if (!Array.isArray(rings))
    rings = [rings];

  packet = new packets.SignPacket(tx, rings, type);
  result = yield this.execute(packet, -1);

  result.inject(tx);

  return result.total;
});

/**
 * Execute the tx input verification job (default timeout).
 * @method
 * @param {TX} tx
 * @param {Number} index
 * @param {Coin|Output} coin
 * @param {VerifyFlags} flags
 * @returns {Promise} - Returns Boolean.
 */

WorkerPool.prototype.verifyInput = co(function* verifyInput(tx, index, coin, flags) {
  var packet = new packets.VerifyInputPacket(tx, index, coin, flags);
  var result = yield this.execute(packet, -1);
  return result.value;
});

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

WorkerPool.prototype.signInput = co(function* signInput(tx, index, coin, ring, type) {
  var packet = new packets.SignInputPacket(tx, index, coin, ring, type);
  var result = yield this.execute(packet, -1);
  result.inject(tx);
  return result.value;
});

/**
 * Execute the ec verify job (no timeout).
 * @method
 * @param {Buffer} msg
 * @param {Buffer} sig - DER formatted.
 * @param {Buffer} key
 * @returns {Promise}
 */

WorkerPool.prototype.ecVerify = co(function* ecVerify(msg, sig, key) {
  var packet = new packets.ECVerifyPacket(msg, sig, key);
  var result = yield this.execute(packet, -1);
  return result.value;
});

/**
 * Execute the ec signing job (no timeout).
 * @method
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Promise}
 */

WorkerPool.prototype.ecSign = co(function* ecSign(msg, key) {
  var packet = new packets.ECSignPacket(msg, key);
  var result = yield this.execute(packet, -1);
  return result.sig;
});

/**
 * Execute the mining job (no timeout).
 * @method
 * @param {Buffer} data
 * @param {Buffer} target
 * @param {Number} min
 * @param {Number} max
 * @returns {Promise} - Returns {Number}.
 */

WorkerPool.prototype.mine = co(function* mine(data, target, min, max) {
  var packet = new packets.MinePacket(data, target, min, max);
  var result = yield this.execute(packet, -1);
  return result.nonce;
});

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

WorkerPool.prototype.scrypt = co(function* scrypt(passwd, salt, N, r, p, len) {
  var packet = new packets.ScryptPacket(passwd, salt, N, r, p, len);
  var result = yield this.execute(packet, -1);
  return result.key;
});

/**
 * Represents a worker.
 * @alias module:workers.Worker
 * @constructor
 * @param {Number?} id
 */

function Worker(id) {
  if (!(this instanceof Worker))
    return new Worker(id);

  EventEmitter.call(this);

  this.framer = new Framer();
  this.parser = new Parser();

  this.id = id != null ? id : -1;
  this.child = null;
  this.pending = {};

  this.env = {
    BCOIN_WORKER_NETWORK: Network.type,
    BCOIN_WORKER_ISTTY: process.stdout
      ? (process.stdout.isTTY ? '1' : '0')
      : '0'
  };

  this._init();
}

util.inherits(Worker, EventEmitter);

/**
 * Initialize worker. Bind to events.
 * @private
 */

Worker.prototype._init = function _init() {
  var self = this;

  this.on('data', function(data) {
    self.parser.feed(data);
  });

  this.parser.on('error', function(err) {
    self.emit('error', err);
  });

  this.parser.on('packet', function(packet) {
    self.emit('packet', packet);
  });

  if (util.isBrowser) {
    // Web workers
    this._initWebWorkers();
  } else {
    // Child process + pipes
    this._initChildProcess();
  }

  this._bind();
  this._listen();
};

/**
 * Initialize worker (web workers).
 * @private
 */

Worker.prototype._initWebWorkers = function _initWebWorkers() {
  var self = this;

  this.child = new global.Worker('/bcoin-worker.js');

  this.child.onerror = function onerror(err) {
    self.emit('error', err);
    self.emit('exit', -1, null);
  };

  this.child.onmessage = function onmessage(event) {
    var data;
    if (typeof event.data !== 'string') {
      data = event.data.buf;
      data.__proto__ = Buffer.prototype;
    } else {
      data = new Buffer(event.data, 'hex');
    }
    self.emit('data', data);
  };

  this.child.postMessage(JSON.stringify(this.env));
};

/**
 * Initialize worker (node.js).
 * @private
 */

Worker.prototype._initChildProcess = function _initChildProcess() {
  var self = this;
  var file = process.argv[0];
  var argv = [__dirname + '/worker.js'];
  var env = util.merge({}, process.env, this.env);
  var options = { stdio: 'pipe', env: env };

  this.child = cp.spawn(file, argv, options);

  this.child.on('error', function(err) {
    self.emit('error', err);
  });

  this.child.on('exit', function(code, signal) {
    self.emit('exit', code == null ? -1 : code, signal);
  });

  this.child.on('close', function() {
    self.emit('exit', -1, null);
  });

  this.child.stdin.on('error', function(err) {
    self.emit('error', err);
  });

  this.child.stdout.on('error', function(err) {
    self.emit('error', err);
  });

  this.child.stderr.on('error', function(err) {
    self.emit('error', err);
  });

  this.child.stdout.on('data', function(data) {
    self.emit('data', data);
  });
};

/**
 * Bind to exit listener.
 * @private
 */

Worker.prototype._bind = function _bind() {
  var self = this;

  this.on('exit', function(code) {
    var i = WorkerPool.children.indexOf(self);
    if (i !== -1)
      WorkerPool.children.splice(i, 1);
  });

  WorkerPool.children.push(this);

  WorkerPool.bindExit();
};

/**
 * Listen for packets.
 * @private
 */

Worker.prototype._listen = function _listen() {
  var self = this;

  this.on('exit', function() {
    self.killJobs();
  });

  this.on('error', function(err) {
    self.killJobs();
  });

  this.on('packet', function(packet) {
    try {
      self.handlePacket(packet);
    } catch (e) {
      self.emit('error', e);
    }
  });
};

/**
 * Handle packet.
 * @private
 * @param {Packet} packet
 */

Worker.prototype.handlePacket = function handlePacket(packet) {
  switch (packet.cmd) {
    case packets.types.EVENT:
      this.emit.apply(this, packet.items);
      this.emit('event', packet.items);
      break;
    case packets.types.LOG:
      util.log('Worker %d:', this.id);
      util.log(packet.text);
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
};

/**
 * Send data to worker.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Worker.prototype.write = function write(data) {
  if (util.isBrowser) {
    if (this.child.postMessage.length === 2) {
      data.__proto__ = Uint8Array.prototype;
      this.child.postMessage({ buf: data }, [data]);
    } else {
      this.child.postMessage(data.toString('hex'));
    }
    return true;
  }
  return this.child.stdin.write(data);
};

/**
 * Frame and send a packet.
 * @param {Packet} packet
 * @returns {Boolean}
 */

Worker.prototype.send = function send(packet) {
  return this.write(this.framer.packet(packet));
};

/**
 * Emit an event on the worker side.
 * @param {String} event
 * @param {...Object} arg
 * @returns {Boolean}
 */

Worker.prototype.sendEvent = function sendEvent() {
  var items = new Array(arguments.length);
  var i;

  for (i = 0; i < items.length; i++)
    items[i] = arguments[i];

  return this.send(new packets.EventPacket(items));
};

/**
 * Destroy the worker.
 */

Worker.prototype.destroy = function destroy() {
  if (util.isBrowser) {
    this.child.terminate();
    this.emit('exit', -1, 'SIGTERM');
    return;
  }
  return this.child.kill('SIGTERM');
};

/**
 * Call a method for a worker to execute.
 * @param {Packet} packet
 * @param {Number} timeout
 * @returns {Promise}
 */

Worker.prototype.execute = function execute(packet, timeout) {
  var self = this;
  return new Promise(function(resolve, reject) {
    self._execute(packet, timeout, resolve, reject);
  });
};

/**
 * Call a method for a worker to execute.
 * @private
 * @param {Packet} packet
 * @param {Number} timeout
 * @param {Function} resolve
 * @param {Function} reject
 * the worker method specifies.
 */

Worker.prototype._execute = function _execute(packet, timeout, resolve, reject) {
  var job = new PendingJob(this, packet.id, resolve, reject);

  assert(!this.pending[packet.id], 'ID overflow.');

  this.pending[packet.id] = job;

  job.start(timeout);

  this.send(packet);
};

/**
 * Resolve a job.
 * @param {Number} id
 * @param {Packet} result
 */

Worker.prototype.resolveJob = function resolveJob(id, result) {
  var job = this.pending[id];

  if (!job)
    throw new Error('Job ' + id + ' is not in progress.');

  job.resolve(result);
};

/**
 * Reject a job.
 * @param {Number} id
 * @param {Error} err
 */

Worker.prototype.rejectJob = function rejectJob(id, err) {
  var job = this.pending[id];

  if (!job)
    throw new Error('Job ' + id + ' is not in progress.');

  job.reject(err);
};

/**
 * Kill all jobs associated with worker.
 */

Worker.prototype.killJobs = function killJobs() {
  var keys = Object.keys(this.pending);
  var i, key, job;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    job = this.pending[key];
    job.destroy();
  }
};

/**
 * Pending Job
 * @constructor
 * @ignore
 * @param {Worker} worker
 * @param {Number} id
 * @param {Function} resolve
 * @param {Function} reject
 */

function PendingJob(worker, id, resolve, reject) {
  this.worker = worker;
  this.id = id;
  this.job = co.job(resolve, reject);
  this.timer = null;
}

/**
 * Start the timer.
 * @param {Number} timeout
 */

PendingJob.prototype.start = function start(timeout) {
  var self = this;

  if (!timeout || timeout === -1)
    return;

  this.timer = setTimeout(function() {
    self.reject(new Error('Worker timed out.'));
  }, timeout);
};

/**
 * Destroy the job with an error.
 */

PendingJob.prototype.destroy = function destroy() {
  this.reject(new Error('Job was destroyed.'));
};

/**
 * Cleanup job state.
 * @returns {Job}
 */

PendingJob.prototype.cleanup = function cleanup() {
  var job = this.job;

  assert(job, 'Already finished.');

  this.job = null;

  if (this.timer != null) {
    clearTimeout(this.timer);
    this.timer = null;
  }

  assert(this.worker.pending[this.id]);
  delete this.worker.pending[this.id];

  return job;
};

/**
 * Complete job with result.
 * @param {Object} result
 */

PendingJob.prototype.resolve = function resolve(result) {
  var job = this.cleanup();
  job.resolve(result);
};

/**
 * Complete job with error.
 * @param {Error} err
 */

PendingJob.prototype.reject = function reject(err) {
  var job = this.cleanup();
  job.reject(err);
};

/*
 * Helpers
 */

function getCores() {
  if (os.unsupported)
    return 2;

  return Math.max(1, os.cpus().length);
}

/*
 * Default Pool
 */

exports.pool = new WorkerPool();
exports.pool.enabled = true;

exports.set = function set(options) {
  this.pool.set({
    enabled: options.useWorkers,
    size: options.maxWorkers || null,
    timeout: options.workerTimeout || null
  });
};

exports.set({
  useWorkers: +process.env.BCOIN_USE_WORKERS !== 0,
  maxWorkers: +process.env.BCOIN_MAX_WORKERS,
  workerTimeout: +process.env.BCOIN_WORKER_TIMEOUT
});

/*
 * Expose
 */

exports.WorkerPool = WorkerPool;
exports.Worker = Worker;
