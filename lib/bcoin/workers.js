/**
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var utils = require('./utils');
var assert = utils.assert;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');
var cp = require('child_process');
var workers = exports;

var HEADER_SIZE = 12;

/**
 * Master
 */

workers.MAX_WORKERS = 30;
workers.TIMEOUT = 10000;
workers.children = {};
workers.uid = 0;

workers.spawn = function spawn(index) {
  var child;

  utils.debug('Spawning worker process: %d', index);

  child = cp.spawn(process.argv[0], [__filename], {
    stdio: ['pipe', 'pipe', 'inherit'],
    env: utils.merge({}, process.env, {
      BCOIN_WORKER: index + ''
    })
  });

  child.on('error', function(err) {
    utils.debug('Worker %d error: %s', index, err.message);
  });

  child.on('exit', function(code) {
    utils.debug('Worker %d exited: %s', index, code);
    if (workers.children[index] === child)
      delete workers.children[index];
  });

  child.on('close', function() {
    utils.debug('Worker %d closed', index);
    if (workers.children[index] === child)
      delete workers.children[index];
  });

  child.stdout.on('data', parser(function(id, result) {
    child.emit('completed ' + id, result[0], result[1]);
  }));

  return child;
};

// Load balance the workers based on job ID.
workers.alloc = function alloc(id) {
  var index = id % workers.MAX_WORKERS;
  if (!workers.children[index])
    workers.children[index] = workers.spawn(index);
  return workers.children[index];
};

workers.call = function call(method, args, callback) {
  var id = workers.uid++;
  var event, child, timeout;

  if (id > 0xffffffff) {
    workers.uid = 0;
    id = workers.uid++;
  }

  event = 'completed ' + id;
  child = workers.alloc(id);

  function listener(err, result) {
    clearTimeout(timeout);
    timeout = null;
    callback(err, result);
  }

  child.once(event, listener);

  timeout = setTimeout(function() {
    child.removeListener(event, listener);
    return callback(new Error('Worker timed out.'));
  }, workers.TIMEOUT);

  child.stdin.write(createPacket(id, [method, args]));
};

/**
 * Calls
 */

bcoin.tx.prototype.verifyAsync = function verifyAsync(index, force, flags, callback) {
  var tx;

  callback = utils.asyncify(callback);

  if (!force && this.ts !== 0)
    return callback(null, true);

  if (this.inputs.length === 0)
    return callback(null, false);

  if (this.isCoinbase())
    return callback(null, true);

  // Important: we need to serialize
  // the coins for the worker.
  tx = this.toExtended(true).toString('hex');

  return workers.call('verify', [tx, index, force, flags], callback);
};

/**
 * Child
 */

workers.listen = function listen() {
  bcoin.debug = function debug() {
    process.stderr.write('Worker %s: ', process.env.BCOIN_WORKER);
    console.error.apply(console.error, arguments);
  };

  utils.debug = bcoin.debug;
  utils.print = bcoin.debug;

  process.stdin.on('data', parser(function(id, data) {
    var method = data[0];
    var args = data[1];
    var res;

    try {
      res = workers[method].apply(workers[method], args);
    } catch (e) {
      utils.debug(e.stack + '');
      return process.stdout.write(createPacket(id, [{
        message: e.message,
        stack: e.stack + ''
      }]));
    }

    return process.stdout.write(createPacket(id, [null, res]));
  }));
};

/**
 * Calls
 * The actual calls that are run
 * in a separate worker process.
 */

workers.verify = function verify(tx, index, force, flags) {
  tx = bcoin.tx.fromExtended(new Buffer(tx, 'hex'), true);
  if (tx.getOutputValue().cmp(tx.getInputValue()) > 0) {
    utils.debug('TX is spending funds it does not have: %s', tx.rhash);
    return false;
  }
  return tx.verify(index, force, flags);
};

/**
 * Helpers
 */

function createPacket(id, json) {
  var json = new Buffer(JSON.stringify(json), 'utf8');
  var p = new BufferWriter();
  p.writeU32(0xdeadbeef);
  p.writeU32(id);
  p.writeU32(json.length + 1);
  p.writeBytes(json);
  p.writeU8(0x0a);
  return p.render();
}

function parsePacket(data) {
  return JSON.parse(data.toString('utf8'));
}

function parseHeader(data) {
  return {
    magic: utils.readU32(data, 0),
    id: utils.readU32(data, 4),
    size: utils.readU32(data, 8)
  };
}

function parser(onPacket) {
  var waiting = HEADER_SIZE;
  var wait = 0;
  var buf = [];
  var read = 0;
  var header = null;

  return function parse(data) {
    var packet, rest;

    read += data.length;
    buf.push(data);

    if (read < waiting)
      return;

    buf = Buffer.concat(buf);

    if (buf.length > waiting) {
      packet = buf.slice(0, waiting);
      rest = buf.slice(waiting);
    } else {
      packet = buf;
    }

    if (!header) {
      header = parseHeader(packet);

      if (header.magic !== 0xdeadbeef) {
        buf = [];
        waiting = HEADER_SIZE;
        read = 0;
        utils.debug('Bad magic number: %d', header.magic);
        return;
      }

      buf = [];
      waiting = header.size;
      read = 0;

      if (rest)
        parse(rest);

      return;
    }

    try {
      packet = parsePacket(packet);
    } catch (e) {
      utils.debug(e.stack + '');
      return;
    }

    onPacket(header.id, packet);

    buf = [];
    waiting = HEADER_SIZE;
    read = 0;
    header = null;

    if (rest)
      parse(rest);
  };
}

if (process.env.BCOIN_WORKER)
  workers.listen();
