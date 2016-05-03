/*!
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var EventEmitter = require('events').EventEmitter;
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = require('./utils');
var global = utils.global;
var assert = utils.assert;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');

/**
 * A worker pool.
 * @exports Workers
 * @constructor
 * @param {Object} options
 * @param {Number} [options.size=num-cores] - Max pool size.
 * @param {Number} [options.timeout=10000] - Execution timeout.
 * @property {Number} size
 * @property {Number} timeout
 * @property {Object} children
 * @property {Number} uid
 */

function Workers(options) {
  if (!(this instanceof Workers))
    return new Workers(options);

  EventEmitter.call(this);

  this.uid = 0;
  this.size = options.size || Workers.CORES;
  this.timeout = options.timeout || 10000;
  this.children = {};
}

utils.inherits(Workers, EventEmitter);

/**
 * Number of CPUs/cores available.
 * @const {Number}
 */

Workers.CORES = getCores();

/**
 * Spawn a new worker.
 * @param {Number} index - Worker ID.
 * @returns {Worker}
 */

Workers.prototype.spawn = function spawn(id) {
  var self = this;
  var child;

  bcoin.debug('Spawning worker process: %d', id);

  child = new Worker(id);

  child.on('error', function(err) {
    bcoin.debug('Worker %d error: %s', child.id, err.message);
  });

  child.on('exit', function(code) {
    bcoin.debug('Worker %d exited: %s', child.id, code);
    if (self.children[child.id] === child)
      delete self.children[child.id];
  });

  child.on('packet', function(job, body) {
    if (body.name === 'event') {
      child.emit.apply(child, body.items);
      self.emit.apply(self, body.items);
      return;
    }
    if (body.name === 'response') {
      child.emit('response ' + job, body.items[0], body.items[1]);
      return;
    }
    self.emit('error', new Error('Unknown packet: ' + body.name));
  });

  return child;
};

/**
 * Allocate a new worker, will not go above `size` option
 * and will automatically load balance the workers based
 * on job ID.
 * @param {Number} job
 * @returns {Worker}
 */

Workers.prototype.alloc = function alloc(job) {
  var id = job % this.size;
  if (!this.children[id])
    this.children[id] = this.spawn(id);
  return this.children[id];
};

/**
 * Call a method for a worker to execute.
 * @param {String} method - Method name.
 * @param {Array} args - Arguments.
 * @param {Function} callback - Returns whatever
 * the worker method specifies.
 */

Workers.prototype.execute = function execute(method, args, timeout, callback) {
  var job = this.uid++;
  var child;

  if (job > 0xffffffff) {
    this.uid = 0;
    job = this.uid++;
  }

  if (!timeout)
    timeout = this.timeout;

  child = this.alloc(job);

  child.execute(job, method, args, timeout, callback);

  return child;
};

/**
 * Execute the tx verification job (default timeout).
 * @param {TX} tx
 * @param {Number} index
 * @param {Boolean} force
 * @param {VerifyFlags} flags
 * @param {Function} callback - Returns [Error, Boolean].
 */

Workers.prototype.verify = function verify(tx, index, force, flags, callback) {
  return this.execute('verify', [tx, index, force, flags], null, callback);
};

/**
 * Execute the mining job (no timeout).
 * @param {MinerBlock} attempt
 * @param {Function} callback - Returns [Error, {@link MinerBlock}].
 */

Workers.prototype.mine = function mine(attempt, callback) {
  var data = {
    tip: attempt.tip.toRaw(),
    version: attempt.block.version,
    target: attempt.block.bits,
    address: attempt.options.address,
    coinbaseFlags: attempt.options.coinbaseFlags,
    witness: attempt.options.witness
  };
  return this.execute('mine', [data], -1, callback);
};

/**
 * Represents a worker.
 * @exports Worker
 * @constructor
 * @param {Number} id - Worker ID.
 * @property {Number} id
 */

function Worker(id) {
  var self = this;
  var cp;

  if (!(this instanceof Worker))
    return new Worker(id);

  EventEmitter.call(this);

  this.id = id;
  this.framer = new Framer();
  this.parser = new Parser();

  if (bcoin.isBrowser) {
    this.child = new global.Worker('/bcoin-worker.js');

    this.child.onerror = function onerror(err) {
      self.emit('error', err);
      self.emit('exit', 1, null);
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

    this.child.postMessage(JSON.stringify({
      BCOIN_WORKER_ID: id + '',
      BCOIN_WORKER_NETWORK: network.type
    }));
  } else {
    cp = require('child_' + 'process');

    this.child = cp.spawn(process.argv[0], [__dirname + '/worker.js'], {
      stdio: 'pipe',
      env: utils.merge({}, process.env, {
        BCOIN_WORKER_ID: id + '',
        BCOIN_WORKER_NETWORK: network.type
      })
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

    this.child.stdout.on('data', function(data) {
      self.emit('data', data);
    });

    this.child.stderr.setEncoding('utf8');
    this.child.stderr.on('data', function(data) {
      bcoin.debug(data);
    });
  }

  this.on('data', function(data) {
    self.parser.feed(data);
  });

  this.parser.on('error', function(e) {
    self.emit('error', e);
  });

  this.parser.on('packet', function(job, body) {
    self.emit('packet', job, body);
  });
}

/**
 * Send data to worker.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Worker.prototype.write = function write(data) {
  if (bcoin.isBrowser) {
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
 * @param {String} name
 * @param {Array} items
 */

Worker.prototype.send = function send(job, name, items) {
  return this.write(this.framer.packet(job, name, items));
};

/**
 * Emit an event on the worker side.
 * @param {String} event
 * @param {...Object} arg
 */

Worker.prototype.sendEvent = function sendEvent() {
  var items = Array.prototype.slice.call(arguments);
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
 * @param {Number} job - Job ID.
 * @param {String} method - Method name.
 * @param {Array} args - Arguments.
 * @param {Function} callback - Returns whatever
 * the worker method specifies.
 */

Worker.prototype.execute = function execute(job, method, args, timeout, callback) {
  var self = this;
  var event = 'response ' + job;
  var timer;

  assert(job <= 0xffffffff);

  function listener(err, result) {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    self.removeListener('error', listener);
    self.removeListener(event, listener);
    callback(err, result);
  }

  this.once(event, listener);
  this.once('error', listener);

  if (timeout !== -1) {
    timer = setTimeout(function() {
      self.removeListener(event, listener);
      callback(new Error('Worker timed out.'));
    }, timeout);
  }

  this.send(job, method, args);
};

utils.inherits(Worker, EventEmitter);

/**
 * Represents the master process.
 * @exports Master
 * @constructor
 * @param {Number} id - Worker ID.
 * @property {Number} id
 */

function Master(id) {
  var self = this;

  if (!(this instanceof Master))
    return new Master(id);

  EventEmitter.call(this);

  this.id = id;
  this.framer = new Framer();
  this.parser = new Parser();

  if (bcoin.isBrowser) {
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
  }

  this.on('data', function(data) {
    self.parser.feed(data);
  });

  this.parser.on('error', function(e) {
    self.emit('error', e);
  });

  this.parser.on('packet', function(job, body) {
    self.emit('packet', job, body);
  });
}

utils.inherits(Master, EventEmitter);

/**
 * Send data to worker.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Master.prototype.write = function write(data) {
  if (bcoin.isBrowser) {
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
 * @param {String} name
 * @param {Array} items
 */

Master.prototype.send = function send(job, name, items) {
  return this.write(this.framer.packet(job, name, items));
};

/**
 * Emit an event on the worker side.
 * @param {String} event
 * @param {...Object} arg
 */

Master.prototype.sendEvent = function sendEvent() {
  var items = Array.prototype.slice.call(arguments);
  return this.send(0, 'event', items);
};

/**
 * Write a debug message, prefixing
 * it with the worker ID.
 * @param {...String} args
 */

Master.prototype.log = function log() {
  if (bcoin.isBrowser)
    return console.error.apply(console.error, arguments);
  process.stderr.write('Worker ' + this.id + ': ');
  return console.error.apply(console.error, arguments);
};

/**
 * Destroy the worker.
 */

Master.prototype.destroy = function destroy() {
  if (bcoin.isBrowser)
    return global.close();
  return process.exit(0);
};

/**
 * Listen for messages from master process (only if worker).
 * @param {Number} id - Worker id.
 * @returns {Master}
 */

Master.listen = function listen(id) {
  var master = new Master(id);
  var log = master.log.bind(master);

  bcoin.debug = log;
  utils.print = log;
  utils.error = log;

  master.on('error', function(err) {
    bcoin.debug('Master error: %s', err.message);
  });

  master.on('packet', function(job, body) {
    var res;

    if (body.name === 'event') {
      master.emit.apply(master, body.items);
      return;
    }

    try {
      res = jobs[body.name].apply(jobs, body.items);
    } catch (e) {
      bcoin.debug(e.stack + '');
      return master.send(job, 'response', [{
        message: e.message,
        stack: e.stack + ''
      }]);
    }

    return master.send(job, 'response', [null, res]);
  });

  return master;
};

/**
 * Jobs to execute within the worker.
 * @const {Object}
 */

var jobs = {};

/**
 * Execute tx.verify() on worker.
 * @see TX#verify
 * @param {TX} tx
 * @param {Number?} index
 * @param {Boolean?} force
 * @param {VerifyFlags?} flags
 * @returns {Boolean}
 */

jobs.verify = function verify(tx, index, force, flags) {
  return tx.verify(index, force, flags);
};

/**
 * Mine a block on worker.
 * @param {Object} attempt - Naked {@link MinerBlock}.
 * @returns {Block}
 */

jobs.mine = function mine(data) {
  var attempt = new bcoin.miner.minerblock({
    tip: bcoin.chainblock.fromRaw(null, data.tip),
    version: data.version,
    target: data.target,
    address: data.address,
    coinbaseFlags: data.coinbaseFlags,
    witness: data.witness,
    dsha256: utils.dsha256
  });
  attempt.on('status', function(stat) {
    bcoin.debug(
      'hashrate=%dkhs hashes=%d target=%d height=%d best=%s',
      stat.hashrate / 1000 | 0,
      stat.hashes,
      stat.target,
      stat.height,
      stat.best);
  });
  return attempt.mineSync();
};

/**
 * Framer
 * @constructor
 */

function Framer() {
  if (!(this instanceof Framer))
    return new Framer();

  EventEmitter.call(this);
}

utils.inherits(Framer, EventEmitter);

Framer.prototype.packet = function packet(job, name, items) {
  var p = new BufferWriter();
  var payload = this.body(name, items);
  p.writeU32(0xdeadbeef);
  p.writeU32(job);
  p.writeU32(payload.length);
  p.writeBytes(payload);
  return p.render();
}

Framer.prototype.body = function body(name, items) {
  var p = new BufferWriter();

  if (name)
    p.writeVarString(name, 'ascii');
  else
    p.writeVarint(0);

  Framer.item(items, p);

  p.writeU8(0x0a);

  return p.render();
};

Framer.item = function _item(item, p) {
  var i, keys;

  switch (typeof item) {
    case 'string':
      p.writeU8(1);
      p.writeVarString(item, 'utf8');
      break;
    case 'number':
      p.writeU8(2);
      p.write32(item);
      break;
    case 'boolean':
      p.writeU8(3);
      p.writeU8(item ? 1 : 0);
      break;
    case 'object':
    case 'undefined':
      if (item == null) {
        p.writeU8(0);
      } else {
        if (item instanceof bcoin.block) {
          p.writeU8(40);
          p.writeVarBytes(item.render());
        } else if (item instanceof bcoin.tx) {
          p.writeU8(41);
          p.writeVarBytes(item.toExtended(true));
        } else if (item instanceof bcoin.coin) {
          p.writeU8(42);
          p.writeVarBytes(item.toExtended());
        } else if (bn.isBN(item)) {
          p.writeU8(43);
          p.writeVarBytes(item.toBuffer());
        } else if (Buffer.isBuffer(item)) {
          p.writeU8(4);
          p.writeVarBytes(item);
        } else if (Array.isArray(item)) {
          p.writeU8(5);
          p.writeVarint(item.length);
          for (i = 0; i < item.length; i++)
            Framer.item(item[i], p);
        } else {
          keys = Object.keys(item);
          p.writeU8(6);
          p.writeVarint(keys.length);
          for (i = 0; i < keys.length; i++) {
            p.writeVarString(keys[i], 'utf8');
            Framer.item(item[keys[i]], p);
          }
        }
      }
      break;
    default:
      assert(false, 'Bad type: ' + typeof item);
  }
};

/**
 * Parser
 * @constructor
 */

function Parser() {
  if (!(this instanceof Parser))
    return new Parser();

  EventEmitter.call(this);

  this.waiting = 12;
  this.header = null;
  this.pending = [];
  this.pendingTotal = 0;
}

utils.inherits(Parser, EventEmitter);

Parser.prototype.feed = function feed(data) {
  var chunk, header, body, rest;

  this.pendingTotal += data.length;
  this.pending.push(data);

  if (this.pendingTotal < this.waiting)
    return;

  chunk = Buffer.concat(this.pending);

  if (chunk.length > this.waiting) {
    rest = chunk.slice(this.waiting);
    chunk = chunk.slice(0, this.waiting);
  }

  if (!this.header) {
    this.header = this.parseHeader(chunk);
    this.waiting = this.header.size;
    this.pending.length = 0;
    this.pendingTotal = 0;

    if (this.header.magic !== 0xdeadbeef) {
      this.header = null;
      this.waiting = 12;
      this.emit('error', new Error('Bad magic number.'));
      return;
    }

    if (rest)
      this.feed(rest);

    return;
  }

  header = this.header;

  this.pending.length = 0;
  this.pendingTotal = 0;
  this.waiting = 12;
  this.header = null;

  try {
    body = this.parseBody(chunk);
  } catch (e) {
    this.emit('error', e);
    return;
  }

  this.emit('packet', header.job, body);

  if (rest)
    this.feed(rest);
};

Parser.prototype.parseHeader = function parseHeader(data) {
  return {
    magic: utils.readU32(data, 0),
    job: utils.readU32(data, 4),
    size: utils.readU32(data, 8)
  };
};

Parser.prototype.parseBody = function parseBody(data) {
  var p = new BufferReader(data, true);
  var name, items;

  name = p.readVarString('ascii');
  items = Parser.parseItem(p);

  assert(p.readU8() === 0x0a);

  return {
    name: name || null,
    items: items
  };
};

Parser.parseItem = function parseItem(p) {
  var i, count, items;

  switch (p.readU8()) {
    case 0:
      return null;
    case 1:
      return p.readVarString('utf8');
    case 2:
      return p.read32();
    case 3:
      return p.readU8() === 1;
    case 4:
      return p.readVarBytes();
    case 5:
      items = [];
      count = p.readVarint();
      for (i = 0; i < count; i++)
        items.push(Parser.parseItem(p));
      return items;
    case 6:
      items = {};
      count = p.readVarint();
      for (i = 0; i < count; i++)
        items[p.readVarString('utf8')] = Parser.parseItem(p);
      return items;
    case 40:
      return bcoin.block.fromRaw(p.readVarBytes());
    case 41:
      return bcoin.tx.fromExtended(p.readVarBytes(), true);
    case 42:
      return bcoin.coin.fromExtended(p.readVarBytes());
    case 43:
      return new bn(p.readVarBytes());
    default:
      assert(false, 'Bad type.');
  }
};

/**
 * Helper to retrieve number of cores.
 * @returns {Number}
 */

function getCores() {
  var os;

  if (utils.isBrowser)
    return 4;

  os = require('o' + 's');

  return os.cpus().length;
}

Workers.workers = Workers;
Workers.worker = Worker;
Workers.master = Master;
Workers.framer = Framer;
Workers.parser = Parser;
Workers.listen = Master.listen;

return Workers;
};
