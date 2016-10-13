/*!
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var utils = require('../utils/utils');
var co = require('../utils/co');
var global = utils.global;
var Network = require('../protocol/network');
var jobs = require('./jobs');
var Parser = require('./parser');
var Framer = require('./framer');

/**
 * A worker pool.
 * @exports WorkerPool
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

  if (!options)
    options = {};

  this.size = Math.max(1, options.size || WorkerPool.CORES);
  this.timeout = options.timeout || 60000;
  this.children = [];
  this.nonce = 0;
  this.enabled = true;
}

utils.inherits(WorkerPool, EventEmitter);

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

WorkerPool._exitBound = false;

/**
 * Bind to process events in order to cleanup listeners.
 * @private
 */

WorkerPool._bindExit = function _bindExit() {
  if (utils.isBrowser)
    return;

  if (WorkerPool._exitBound)
    return;

  WorkerPool._exitBound = true;

  function onExit(err) {
    WorkerPool.cleanup();

    if (err) {
      utils.error(err.stack + '');
      process.exit(1);
      return;
    }

    process.exit(0);
  }

  process.once('exit', function() {
    WorkerPool.cleanup();
  });

  if (process.listeners('SIGINT').length === 0)
    process.once('SIGINT', onExit);

  if (process.listeners('SIGTERM').length === 0)
    process.once('SIGTERM', onExit);

  if (process.listeners('uncaughtException').length === 0)
    process.once('uncaughtException', onExit);

  process.on('newListener', function(name) {
    if (name === 'SIGINT'
        || name === 'SIGTERM'
        || name === 'uncaughtException') {
      process.removeListener(name, onExit);
    }
  });
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
  var i, child;
  var result = true;

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
 * @param {String} method - Method name.
 * @param {Array} args - Arguments.
 * @returns {Promise}
 * the worker method specifies.
 */

WorkerPool.prototype.execute = function execute(method, args, timeout) {
  var result, child;

  if (!this.enabled || !exports.support) {
    return new Promise(function(resolve, reject) {
      utils.nextTick(function() {
        try {
          result = jobs[method].apply(jobs, args);
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

  return child.execute(method, args, timeout);
};

/**
 * Execute the tx verification job (default timeout).
 * @param {TX} tx
 * @param {VerifyFlags} flags
 * @returns {Promise} - Returns Boolean.
 */

WorkerPool.prototype.verify = function verify(tx, flags) {
  return this.execute('verify', [tx, flags], -1);
};

/**
 * Execute the tx input verification job (default timeout).
 * @param {TX} tx
 * @param {Number} index
 * @param {VerifyFlags} flags
 * @returns {Promise} - Returns Boolean.
 */

WorkerPool.prototype.verifyInput = function verifyInput(tx, index, flags) {
  return this.execute('verifyInput', [tx, index, flags], -1);
};

/**
 * Execute the tx signing job (default timeout).
 * @param {MTX} tx
 * @param {KeyRing[]} ring
 * @param {SighashType} type
 * @returns {Promise}
 */

WorkerPool.prototype.sign = co(function* sign(tx, ring, type) {
  var i, result, input, sig, sigs, total;

  result = yield this.execute('sign', [tx, ring, type], -1);

  sigs = result[0];
  total = result[1];

  for (i = 0; i < sigs.length; i++) {
    sig = sigs[i];
    input = tx.inputs[i];
    input.script = sig[0];
    input.witness = sig[1];
  }

  return total;
});

/**
 * Execute the tx input signing job (default timeout).
 * @param {MTX} tx
 * @param {Number} index
 * @param {Buffer} key
 * @param {SighashType} type
 * @returns {Promise}
 */

WorkerPool.prototype.signInput = co(function* signInput(tx, index, key, type) {
  var sig = yield this.execute('signInput', [tx, index, key, type], -1);
  var input = tx.inputs[index];

  if (!sig)
    return false;

  input.script = sig[0];
  input.witness = sig[1];

  return true;
});

/**
 * Execute the ec verify job (no timeout).
 * @param {Buffer} msg
 * @param {Buffer} sig - DER formatted.
 * @param {Buffer} key
 * @returns {Promise}
 */

WorkerPool.prototype.ecVerify = function ecVerify(msg, sig, key) {
  return this.execute('ecVerify', [msg, sig, key], -1);
};

/**
 * Execute the ec signing job (no timeout).
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Promise}
 */

WorkerPool.prototype.ecSign = function ecSign(msg, key) {
  return this.execute('ecSign', [msg, key], -1);
};

/**
 * Execute the mining job (no timeout).
 * @param {Buffer} data
 * @param {Buffer} target
 * @param {Number} min
 * @param {Number} max
 * @returns {Promise} - Returns {Number}.
 */

WorkerPool.prototype.mine = function mine(data, target, min, max) {
  return this.execute('mine', [data, target, min, max], -1);
};

/**
 * Execute scrypt job (no timeout).
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @returns {Promise}
 * @returns {Buffer}
 */

WorkerPool.prototype.scrypt = function scrypt(passwd, salt, N, r, p, len) {
  return this.execute('scrypt', [passwd, salt, N, r, p, len], -1);
};

/**
 * Represents a worker.
 * @exports Worker
 * @constructor
 * @param {Number?} id
 */

function Worker(id) {
  if (!(this instanceof Worker))
    return new Worker(id);

  EventEmitter.call(this);

  this.framer = new Framer();
  this.parser = new Parser();
  this.setMaxListeners(utils.MAX_SAFE_INTEGER);
  this.uid = 0;
  this.id = id != null ? id : -1;
  this.child = null;

  this._init();
}

utils.inherits(Worker, EventEmitter);

/**
 * Initialize worker. Bind to events.
 * @private
 */

Worker.prototype._init = function _init() {
  var self = this;
  var penv, cp;

  penv = {
    BCOIN_WORKER_NETWORK: Network.type
  };

  if (utils.isBrowser) {
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

    this.child.postMessage(JSON.stringify(penv));
  } else {
    cp = require('child_process');

    this.child = cp.spawn(process.argv[0], [__dirname + '/worker.js'], {
      stdio: 'pipe',
      env: utils.merge({}, process.env, penv)
    });

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
  }

  this.on('data', function(data) {
    self.parser.feed(data);
  });

  this.parser.on('error', function(e) {
    self.emit('error', e);
  });

  this.parser.on('packet', function(packet) {
    self.emit('packet', packet);
  });

  this._bind();
};

/**
 * Initialize worker. Bind to more events.
 * @private
 */

Worker.prototype._bind = function _bind() {
  var self = this;

  this.on('worker error', function(err) {
    self.emit('error', toError(err));
  });

  this.on('exit', function(code) {
    var i = WorkerPool.children.indexOf(self);
    if (i !== -1)
      WorkerPool.children.splice(i, 1);
  });

  this.on('log', function(items) {
    utils.log('Worker %d:', self.id);
    utils.log.apply(utils, items);
  });

  this.on('packet', function(packet) {
    var err, result;

    if (packet.cmd === 'event') {
      self.emit.apply(self, packet.items);
      self.emit('event', packet.items);
      return;
    }

    if (packet.cmd === 'response') {
      err = packet.items[0];
      result = packet.items[1];

      if (err)
        err = toError(err);

      self.emit('response ' + packet.job, err, result);

      return;
    }

    err = new Error('Unknown packet: ' + packet.cmd);
    self.emit('error', err);
  });

  WorkerPool.children.push(this);

  WorkerPool._bindExit();
};

/**
 * Send data to worker.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Worker.prototype.write = function write(data) {
  if (utils.isBrowser) {
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
 * @param {String} job
 * @param {String} cmd
 * @param {Array} items
 * @returns {Boolean}
 */

Worker.prototype.send = function send(job, cmd, items) {
  return this.write(this.framer.packet(job, cmd, items));
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

  return this.send(0, 'event', items);
};

/**
 * Destroy the worker.
 */

Worker.prototype.destroy = function destroy() {
  if (utils.isBrowser) {
    this.child.terminate();
    this.emit('exit', -1, 'SIGTERM');
    return;
  }
  return this.child.kill('SIGTERM');
};

/**
 * Call a method for a worker to execute.
 * @private
 * @param {Number} job - Job ID.
 * @param {String} method - Method name.
 * @param {Array} args - Arguments.
 * @returns {Promise}
 * the worker method specifies.
 */

Worker.prototype._execute = function _execute(method, args, timeout, callback) {
  var self = this;
  var job = this.uid;
  var event, timer;

  if (++this.uid === 0x100000000)
    this.uid = 0;

  event = 'response ' + job;

  function listener(err, result) {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    self.removeListener(event, listener);
    self.removeListener('error', listener);
    self.removeListener('exit', exitListener);
    callback(err, result);
  }

  function exitListener(code) {
    listener(new Error('Worker exited: ' + code));
  }

  this.once(event, listener);
  this.once('error', listener);
  this.once('exit', exitListener);

  if (timeout !== -1) {
    timer = setTimeout(function() {
      listener(new Error('Worker timed out.'));
    }, timeout);
  }

  this.send(job, method, args);
};

/**
 * Call a method for a worker to execute.
 * @param {Number} job - Job ID.
 * @param {String} method - Method name.
 * @param {Array} args - Arguments.
 * @returns {Promise}
 * the worker method specifies.
 */

Worker.prototype.execute = function execute(method, args, timeout) {
  var self = this;
  return new Promise(function(resolve, reject) {
    self._execute(method, args, timeout, co.wrap(resolve, reject));
  });
};

/**
 * Represents the master process.
 * @exports Master
 * @constructor
 */

function Master() {
  if (!(this instanceof Master))
    return new Master();

  EventEmitter.call(this);

  this.framer = new Framer();
  this.parser = new Parser();

  this._init();
}

utils.inherits(Master, EventEmitter);

/**
 * Initialize master. Bind events.
 * @private
 */

Master.prototype._init = function _init() {
  var self = this;

  if (utils.isBrowser) {
    global.onerror = function onerror(err) {
      self.emit('error', err);
    };
    global.onmessage = function onmessage(event) {
      var data;
      if (typeof event.data !== 'string') {
        data = event.data.buf;
        data.__proto__ = Buffer.prototype;
      } else {
        data = new Buffer(event.data, 'hex');
      }
      self.emit('data', data);
    };
  } else {
    process.stdin.on('data', function(data) {
      self.emit('data', data);
    });
    // Nowhere to send these errors:
    process.stdin.on('error', utils.nop);
    process.stdout.on('error', utils.nop);
    process.stderr.on('error', utils.nop);
  }

  this.on('data', function(data) {
    self.parser.feed(data);
  });

  this.parser.on('error', function(e) {
    self.emit('error', e);
  });

  this.parser.on('packet', function(packet) {
    self.emit('packet', packet);
  });
};

/**
 * Send data to worker.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Master.prototype.write = function write(data) {
  if (utils.isBrowser) {
    if (global.postMessage.length === 2) {
      data.__proto__ = Uint8Array.prototype;
      global.postMessage({ buf: data }, [data]);
    } else {
      global.postMessage(data.toString('hex'));
    }
    return true;
  }
  return process.stdout.write(data);
};

/**
 * Frame and send a packet.
 * @param {String} job
 * @param {String} cmd
 * @param {Array} items
 * @returns {Boolean}
 */

Master.prototype.send = function send(job, cmd, items) {
  return this.write(this.framer.packet(job, cmd, items));
};

/**
 * Emit an event on the worker side.
 * @param {String} event
 * @param {...Object} arg
 * @returns {Boolean}
 */

Master.prototype.sendEvent = function sendEvent() {
  var items = new Array(arguments.length);
  var i;

  for (i = 0; i < items.length; i++)
    items[i] = arguments[i];

  return this.send(0, 'event', items);
};

/**
 * Destroy the worker.
 */

Master.prototype.destroy = function destroy() {
  if (utils.isBrowser)
    return global.close();
  return process.exit(0);
};

/**
 * Write a message to stdout in the master process.
 * @param {Object|String} obj
 * @param {...String} args
 */

Master.prototype.log = function log() {
  var items = new Array(arguments.length);
  var i;

  for (i = 0; i < items.length; i++)
    items[i] = arguments[i];

  this.sendEvent('log', items);
};

/**
 * Listen for messages from master process (only if worker).
 * @returns {Master}
 */

Master.listen = function listen() {
  var master = new Master();

  utils.log = master.log.bind(master);
  utils.error = utils.log;

  master.on('error', function(err) {
    master.sendEvent('worker error', fromError(err));
  });

  master.on('packet', function(packet) {
    var result;

    if (packet.cmd === 'event') {
      master.emit('event', packet.items);
      master.emit.apply(master, packet.items);
      return;
    }

    try {
      result = jobs[packet.cmd].apply(jobs, packet.items);
    } catch (e) {
      master.send(packet.job, 'response', [fromError(e)]);
      return;
    }

    master.send(packet.job, 'response', [null, result]);
  });

  jobs.master = master;

  return master;
};

/*
 * Helpers
 */

function getCores() {
  var os;

  if (utils.isBrowser)
    return 2;

  os = require('os');

  return os.cpus().length;
}

function toError(values) {
  var err = new Error(values[0]);
  err.stack = values[1];
  err.type = values[2];
  return err;
}

function fromError(err) {
  return [err.message, err.stack + '', err.type];
}

/*
 * Default
 */

exports.pool = new WorkerPool();
exports.pool.enabled = false;

exports.support = true;

if (utils.isBrowser) {
  exports.support = typeof global.Worker === 'function'
    || typeof global.postMessage === 'function';
}

exports.set = function set(options) {
  if (typeof options.useWorkerPool === 'boolean')
    this.pool.enabled = options.useWorkerPool;

  if (utils.isNumber(options.maxWorkerPool))
    this.pool.size = options.maxWorkerPool;

  if (utils.isNumber(options.workerTimeout))
    this.pool.timeout = options.workerTimeout;
};

exports.set({
  useWorkerPool: +process.env.BCOIN_USE_WORKERS === 1,
  maxWorkerPool: +process.env.BCOIN_MAX_WORKERS,
  workerTimeout: +process.env.BCOIN_WORKER_TIMEOUT
});

/*
 * Expose
 */

exports.WorkerPool = WorkerPool;
exports.Worker = Worker;
exports.Master = Master;
exports.Framer = Framer;
exports.Parser = Parser;
exports.listen = Master.listen;
