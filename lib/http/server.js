/*!
 * server.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var EventEmitter = require('events').EventEmitter;
var HTTPBase = require('./base');
var util = require('../utils/util');
var co = require('../utils/co');
var base58 = require('../utils/base58');
var Amount = require('../btc/amount');
var Bloom = require('../utils/bloom');
var TX = require('../primitives/tx');
var Outpoint = require('../primitives/outpoint');
var crypto = require('../crypto/crypto');
var Network = require('../protocol/network');
var Validator = require('../utils/validator');
var pkg = require('../pkg');
var RPC = require('./rpc');

/**
 * HTTPServer
 * @alias module:http.Server
 * @constructor
 * @param {Object} options
 * @param {Fullnode} options.node
 * @see HTTPBase
 * @emits HTTPServer#websocket
 */

function HTTPServer(options) {
  if (!(this instanceof HTTPServer))
    return new HTTPServer(options);

  options = new HTTPOptions(options);

  HTTPBase.call(this, options);

  this.options = options;
  this.network = this.options.network;
  this.logger = this.options.logger;
  this.node = this.options.node;

  this.chain = this.node.chain;
  this.mempool = this.node.mempool;
  this.pool = this.node.pool;
  this.fees = this.node.fees;
  this.miner = this.node.miner;
  this.rpc = new RPC(this.node);

  this.init();
}

util.inherits(HTTPServer, HTTPBase);

/**
 * Initialize routes.
 * @private
 */

HTTPServer.prototype.init = function init() {
  var self = this;

  this.on('request', function(req, res) {
    if (req.method === 'POST' && req.pathname === '/')
      return;

    self.logger.debug('Request for method=%s path=%s (%s).',
      req.method, req.pathname, req.socket.remoteAddress);
  });

  this.on('listening', function(address) {
    self.logger.info('Node HTTP server listening on %s (port=%d).',
      address.address, address.port);
  });

  this.initRouter();
  this.initSockets();
};

/**
 * Initialize routes.
 * @private
 */

HTTPServer.prototype.initRouter = function initRouter() {
  this.use(this.cors());

  if (!this.options.noAuth) {
    this.use(this.basicAuth({
      username: 'bitcoinrpc',
      password: this.options.apiKey,
      realm: 'node'
    }));
  }

  this.use(this.bodyParser({
    contentType: 'json'
  }));

  // JSON RPC
  this.post('/', co(function* (req, res) {
    var json = yield this.rpc.call(req.body, req.query);

    json = JSON.stringify(json);
    json += '\n';

    res.setHeader('X-Long-Polling', '/?longpoll=1');

    res.send(200, json, 'json');
  }));

  this.get('/', co(function* (req, res) {
    var totalTX = this.mempool ? this.mempool.totalTX : 0;
    var size = this.mempool ? this.mempool.getSize() : 0;
    var addr = this.pool.hosts.getLocal();

    if (!addr)
      addr = this.pool.hosts.address;

    res.send(200, {
      version: pkg.version,
      network: this.network.type,
      chain: {
        height: this.chain.height,
        tip: this.chain.tip.rhash(),
        progress: this.chain.getProgress()
      },
      pool: {
        host: addr.host,
        port: addr.port,
        agent: this.pool.options.agent,
        services: this.pool.options.services.toString(2),
        outbound: this.pool.peers.outbound,
        inbound: this.pool.peers.inbound
      },
      mempool: {
        tx: totalTX,
        size: size
      },
      time: {
        uptime: this.node.uptime(),
        system: util.now(),
        adjusted: this.network.now(),
        offset: this.network.time.offset
      },
      memory: util.memoryUsage()
    });
  }));

  // UTXO by address
  this.get('/coin/address/:address', co(function* (req, res) {
    var valid = req.valid();
    var address = valid.str('address');
    var result = [];
    var i, coins, coin;

    enforce(address, 'Address is required.');
    enforce(!this.chain.options.spv, 'Cannot get coins in SPV mode.');

    coins = yield this.node.getCoinsByAddress(address);

    for (i = 0; i < coins.length; i++) {
      coin = coins[i];
      result.push(coin.getJSON(this.network));
    }

    res.send(200, result);
  }));

  // UTXO by id
  this.get('/coin/:hash/:index', co(function* (req, res) {
    var valid = req.valid();
    var hash = valid.hash('hash');
    var index = valid.num('index');
    var coin;

    enforce(hash, 'Hash is required.');
    enforce(index != null, 'Index is required.');
    enforce(!this.chain.options.spv, 'Cannot get coins in SPV mode.');

    coin = yield this.node.getCoin(hash, index);

    if (!coin) {
      res.send(404);
      return;
    }

    res.send(200, coin.getJSON(this.network));
  }));

  // Bulk read UTXOs
  this.post('/coin/address', co(function* (req, res) {
    var valid = req.valid();
    var address = valid.array('addresses');
    var result = [];
    var i, coins, coin;

    enforce(address, 'Address is required.');
    enforce(!this.chain.options.spv, 'Cannot get coins in SPV mode.');

    coins = yield this.node.getCoinsByAddress(address);

    for (i = 0; i < coins.length; i++) {
      coin = coins[i];
      result.push(coin.getJSON(this.network));
    }

    res.send(200, result);
  }));

  // TX by hash
  this.get('/tx/:hash', co(function* (req, res) {
    var valid = req.valid();
    var hash = valid.hash('hash');
    var meta, view;

    enforce(hash, 'Hash is required.');
    enforce(!this.chain.options.spv, 'Cannot get TX in SPV mode.');

    meta = yield this.node.getMeta(hash);

    if (!meta) {
      res.send(404);
      return;
    }

    view = yield this.node.getMetaView(meta);

    res.send(200, meta.getJSON(this.network, view));
  }));

  // TX by address
  this.get('/tx/address/:address', co(function* (req, res) {
    var valid = req.valid();
    var address = valid.str('address');
    var result = [];
    var i, metas, meta, view;

    enforce(address, 'Address is required.');
    enforce(!this.chain.options.spv, 'Cannot get TX in SPV mode.');

    metas = yield this.node.getMetaByAddress(address);

    for (i = 0; i < metas.length; i++) {
      meta = metas[i];
      view = yield this.node.getMetaView(meta);
      result.push(meta.getJSON(this.network, view));
    }

    res.send(200, result);
  }));

  // Bulk read TXs
  this.post('/tx/address', co(function* (req, res) {
    var valid = req.valid();
    var address = valid.array('address');
    var result = [];
    var i, metas, meta, view;

    enforce(req.options.address, 'Address is required.');
    enforce(!this.chain.options.spv, 'Cannot get TX in SPV mode.');

    metas = yield this.node.getMetaByAddress(address);

    for (i = 0; i < metas.length; i++) {
      meta = metas[i];
      view = yield this.node.getMetaView(meta);
      result.push(meta.getJSON(this.network, view));
    }

    res.send(200, result);
  }));

  // Block by hash/height
  this.get('/block/:block', co(function* (req, res) {
    var valid = req.valid();
    var hash = valid.get('block');
    var block, view, height;

    enforce(typeof hash === 'number' || typeof hash === 'string',
      'Hash or height required.');
    enforce(!this.chain.options.spv, 'Cannot get block in SPV mode.');

    block = yield this.chain.db.getBlock(hash);

    if (!block) {
      res.send(404);
      return;
    }

    view = yield this.chain.db.getBlockView(block);

    if (!view) {
      res.send(404);
      return;
    }

    height = yield this.chain.db.getHeight(hash);

    res.send(200, block.getJSON(this.network, view, height));
  }));

  // Mempool snapshot
  this.get('/mempool', co(function* (req, res) {
    var result = [];
    var i, hash, hashes;

    enforce(this.mempool, 'No mempool available.');

    hashes = this.mempool.getSnapshot();

    for (i = 0; i < hashes.length; i++) {
      hash = hashes[i];
      result.push(util.revHex(hash));
    }

    res.send(200, result);
  }));

  // Broadcast TX
  this.post('/broadcast', co(function* (req, res) {
    var valid = req.valid();
    var tx = valid.buf('tx');
    enforce(tx, 'TX is required.');
    yield this.node.sendTX(req.options.tx);
    res.send(200, { success: true });
  }));

  // Estimate fee
  this.get('/fee', function(req, res) {
    var valid = req.valid();
    var blocks = valid.num('blocks');
    var fee;

    if (!this.fees) {
      res.send(200, { rate: Amount.btc(this.network.feeRate) });
      return;
    }

    fee = this.fees.estimateFee(blocks);

    res.send(200, { rate: Amount.btc(fee) });
  });

  // Reset chain
  this.post('/reset', co(function* (req, res) {
    var valid = req.valid();
    var height = valid.num('height');

    enforce(height != null, 'Hash or height is required.');

    yield this.chain.reset(height);

    res.send(200, { success: true });
  }));
};

/**
 * Initialize websockets.
 * @private
 */

HTTPServer.prototype.initSockets = function initSockets() {
  var self = this;

  if (!this.io)
    return;

  this.on('socket', function(ws) {
    self.handleSocket(ws);
  });
};

/**
 * Handle new websocket.
 * @private
 * @param {WebSocket} socket
 */

HTTPServer.prototype.handleSocket = function handleSocket(ws) {
  var self = this;
  var socket = new ClientSocket(this, ws);

  socket.start();

  socket.on('close', function() {
    socket.destroy();
  });

  socket.hook('auth', function(args) {
    var valid = new Validator([args]);
    var key = valid.str(0);
    var hash;

    if (socket.auth)
      throw new Error('Already authed.');

    socket.stop();

    if (!self.options.noAuth) {
      hash = hash256(key);
      if (!crypto.ccmp(hash, self.options.apiHash))
        throw new Error('Bad key.');
    }

    socket.auth = true;

    self.logger.info('Successful auth from %s.', socket.host);
    self.handleAuth(socket);

    return null;
  });

  socket.emit('version', {
    version: pkg.version,
    network: self.network.type
  });
};

/**
 * Handle new auth'd websocket.
 * @private
 * @param {WebSocket} socket
 */

HTTPServer.prototype.handleAuth = function handleAuth(socket) {
  var self = this;

  socket.hook('options', function (args) {
    var options = args[0];
    socket.setOptions(options);
  });

  socket.hook('watch chain', function(args) {
    if (!socket.auth)
      throw new Error('Not authorized.');

    socket.watchChain();
  });

  socket.hook('unwatch chain', function(args) {
    if (!socket.auth)
      throw new Error('Not authorized.');

    socket.unwatchChain();
  });

  socket.hook('set filter', function(args) {
    var data = args[0];
    var filter;

    if (!util.isHex(data) && !Buffer.isBuffer(data))
      throw new Error('Invalid parameter.');

    if (!socket.auth)
      throw new Error('Not authorized.');

    filter = Bloom.fromRaw(data, 'hex');
    socket.setFilter(filter);
  });

  socket.hook('get tip', function(args) {
    return socket.frameEntry(self.chain.tip);
  });

  socket.hook('get entry', co(function* (args) {
    var block = args[0];
    var entry;

    if (typeof block === 'string') {
      if (!util.isHex256(block))
        throw new Error('Invalid parameter.');
      block = util.revHex(block);
    } else {
      if (!util.isUInt32(block))
        throw new Error('Invalid parameter.');
    }

    entry = yield self.chain.db.getEntry(block);

    if (!(yield entry.isMainChain()))
      entry = null;

    if (!entry)
      return null;

    return socket.frameEntry(entry);
  }));

  socket.hook('add filter', function(args) {
    var chunks = args[0];

    if (!Array.isArray(chunks))
      throw new Error('Invalid parameter.');

    if (!socket.auth)
      throw new Error('Not authorized.');

    socket.addFilter(chunks);
  });

  socket.hook('reset filter', function(args) {
    if (!socket.auth)
      throw new Error('Not authorized.');

    socket.resetFilter();
  });

  socket.hook('estimate fee', function(args) {
    var blocks = args[0];
    var rate;

    if (blocks != null && !util.isNumber(blocks))
      throw new Error('Invalid parameter.');

    if (!self.fees) {
      rate = self.network.feeRate;
      rate = Amount.btc(rate);
      return rate;
    }

    rate = self.fees.estimateFee(blocks);
    rate = Amount.btc(rate);

    return rate;
  });

  socket.hook('send', function(args) {
    var data = args[0];
    var tx;

    if (!util.isHex(data) && !Buffer.isBuffer(data))
      throw new Error('Invalid parameter.');

    tx = TX.fromRaw(data, 'hex');

    self.node.send(tx);
  });

  socket.hook('rescan', function(args) {
    var start = args[0];

    if (!util.isHex256(start) && !util.isUInt32(start))
      throw new Error('Invalid parameter.');

    if (!socket.auth)
      throw new Error('Not authorized.');

    if (typeof start === 'string')
      start = util.revHex(start);

    return socket.scan(start);
  });
};

/**
 * HTTPOptions
 * @alias module:http.HTTPOptions
 * @constructor
 * @param {Object} options
 */

function HTTPOptions(options) {
  if (!(this instanceof HTTPOptions))
    return new HTTPOptions(options);

  this.network = Network.primary;
  this.logger = null;
  this.node = null;
  this.apiKey = base58.encode(crypto.randomBytes(20));
  this.apiHash = hash256(this.apiKey);
  this.noAuth = false;
  this.walletAuth = false;

  this.prefix = null;
  this.host = '127.0.0.1';
  this.port = 8080;
  this.ssl = false;
  this.keyFile = null;
  this.certFile = null;

  this.fromOptions(options);
}

/**
 * Inject properties from object.
 * @private
 * @param {Object} options
 * @returns {HTTPOptions}
 */

HTTPOptions.prototype.fromOptions = function fromOptions(options) {
  assert(options);
  assert(options.node && typeof options.node === 'object',
    'HTTP Server requires a Node.');

  this.node = options.node;
  this.network = options.node.network;
  this.logger = options.node.logger;

  this.port = this.network.rpcPort;

  if (options.logger != null) {
    assert(typeof options.logger === 'object');
    this.logger = options.logger;
  }

  if (options.apiKey != null) {
    assert(typeof options.apiKey === 'string',
      'API key must be a string.');
    assert(options.apiKey.length <= 200,
      'API key must be under 200 bytes.');
    this.apiKey = options.apiKey;
    this.apiHash = hash256(this.apiKey);
  }

  if (options.noAuth != null) {
    assert(typeof options.noAuth === 'boolean');
    this.noAuth = options.noAuth;
  }

  if (options.walletAuth != null) {
    assert(typeof options.walletAuth === 'boolean');
    this.walletAuth = options.walletAuth;
  }

  if (options.prefix != null) {
    assert(typeof options.prefix === 'string');
    this.prefix = options.prefix;
    this.keyFile = this.prefix + '/key.pem';
    this.certFile = this.prefix + '/cert.pem';
  }

  if (options.host != null) {
    assert(typeof options.host === 'string');
    this.host = options.host;
  }

  if (options.port != null) {
    assert(typeof options.port === 'number', 'Port must be a number.');
    assert(options.port > 0 && options.port <= 0xffff);
    this.port = options.port;
  }

  if (options.ssl != null) {
    assert(typeof options.ssl === 'boolean');
    this.ssl = options.ssl;
  }

  if (options.keyFile != null) {
    assert(typeof options.keyFile === 'string');
    this.keyFile = options.keyFile;
  }

  if (options.certFile != null) {
    assert(typeof options.certFile === 'string');
    this.certFile = options.certFile;
  }

  // Allow no-auth implicitly
  // if we're listening locally.
  if (!options.apiKey) {
    if (this.host === '127.0.0.1' || this.host === '::1')
      this.noAuth = true;
  }

  return this;
};

/**
 * Instantiate http options from object.
 * @param {Object} options
 * @returns {HTTPOptions}
 */

HTTPOptions.fromOptions = function fromOptions(options) {
  return new HTTPOptions().fromOptions(options);
};

/**
 * ClientSocket
 * @constructor
 * @ignore
 * @param {HTTPServer} server
 * @param {SocketIO.Socket}
 */

function ClientSocket(server, socket) {
  if (!(this instanceof ClientSocket))
    return new ClientSocket(server, socket);

  EventEmitter.call(this);

  this.server = server;
  this.socket = socket;
  this.host = socket.remoteAddress;
  this.timeout = null;
  this.auth = false;
  this.filter = null;
  this.raw = false;
  this.watching = false;

  this.network = this.server.network;
  this.node = this.server.node;
  this.chain = this.server.chain;
  this.mempool = this.server.mempool;
  this.pool = this.server.pool;
  this.logger = this.server.logger;
  this.events = [];

  this.init();
}

util.inherits(ClientSocket, EventEmitter);

ClientSocket.prototype.init = function init() {
  var self = this;
  var socket = this.socket;
  var emit = EventEmitter.prototype.emit;

  socket.on('error', function(err) {
    emit.call(self, 'error', err);
  });

  socket.on('close', function() {
    emit.call(self, 'close');
  });
};

ClientSocket.prototype.setOptions = function setOptions(options) {
  assert(options && typeof options === 'object', 'Invalid parameter.');

  if (options.raw != null) {
    assert(typeof options.raw === 'boolean', 'Invalid parameter.');
    this.raw = options.raw;
  }
};

ClientSocket.prototype.setFilter = function setFilter(filter) {
  this.filter = filter;
};

ClientSocket.prototype.addFilter = function addFilter(chunks) {
  var i, data;

  if (!this.filter)
    throw new Error('No filter set.');

  for (i = 0; i < chunks.length; i++) {
    data = chunks[i];

    if (!util.isHex(data) && !Buffer.isBuffer(data))
      throw new Error('Not a hex string.');

    this.filter.add(data, 'hex');

    if (this.pool.options.spv)
      this.pool.watch(data, 'hex');
  }
};

ClientSocket.prototype.resetFilter = function resetFilter() {
  if (!this.filter)
    throw new Error('No filter set.');

  this.filter.reset();
};

ClientSocket.prototype.bind = function bind(obj, event, listener) {
  this.events.push([obj, event, listener]);
  obj.on(event, listener);
};

ClientSocket.prototype.unbind = function unbind(obj, event) {
  var i, item;

  for (i = this.events.length - 1; i >= 0; i--) {
    item = this.events[i];
    if (item[0] === obj && item[1] === event) {
      obj.removeListener(event, item[2]);
      this.events.splice(i, 1);
    }
  }
};

ClientSocket.prototype.unbindAll = function unbindAll() {
  var i, event;

  for (i = 0; i < this.events.length; i++) {
    event = this.events[i];
    event[0].removeListener(event[1], event[2]);
  }

  this.events.length = 0;
};

ClientSocket.prototype.watchChain = function watchChain() {
  var self = this;
  var pool = this.mempool || this.pool;

  if (this.watching)
    throw new Error('Already watching chain.');

  this.watching = true;

  this.bind(this.chain, 'connect', function(entry, block, view) {
    self.connectBlock(entry, block, view);
  });

  this.bind(this.chain, 'disconnect', function(entry, block, view) {
    self.disconnectBlock(entry, block, view);
  });

  this.bind(this.chain, 'reset', function(tip) {
    self.emit('chain reset', self.frameEntry(tip));
  });

  this.bind(pool, 'tx', function(tx) {
    self.sendTX(tx);
  });
};

ClientSocket.prototype.onError = function onError(err) {
  var emit = EventEmitter.prototype.emit;
  emit.call(this, 'error', err);
};

ClientSocket.prototype.unwatchChain = function unwatchChain() {
  var pool = this.mempool || this.pool;

  if (!this.watching)
    throw new Error('Not watching chain.');

  this.watching = false;

  this.unbind(this.chain, 'connect');
  this.unbind(this.chain, 'disconnect');
  this.unbind(this.chain, 'reset');
  this.unbind(pool, 'tx');
};

ClientSocket.prototype.connectBlock = function connectBlock(entry, block, view) {
  var raw = this.frameEntry(entry);
  var txs;

  this.emit('entry connect', raw);

  if (!this.filter)
    return;

  txs = this.filterBlock(entry, block, view);

  this.emit('block connect', raw, txs);
};

ClientSocket.prototype.disconnectBlock = function disconnectBlock(entry, block, view) {
  var raw = this.frameEntry(entry);

  this.emit('entry disconnect', raw);

  if (!this.filter)
    return;

  this.emit('block disconnect', raw);
};

ClientSocket.prototype.sendTX = function sendTX(tx) {
  var raw;

  if (!this.filterTX(tx))
    return;

  raw = this.frameTX(tx);

  this.emit('tx', raw);
};

ClientSocket.prototype.rescanBlock = function rescanBlock(entry, txs) {
  var self = this;
  return new Promise(function(resolve, reject) {
    var cb = TimedCB.wrap(resolve, reject);
    self.emit('block rescan', entry, txs, cb);
  });
};

ClientSocket.prototype.filterBlock = function filterBlock(entry, block, view) {
  var txs = [];
  var i, tx;

  if (!this.filter)
    return;

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];
    if (this.filterTX(tx))
      txs.push(this.frameTX(tx, view, entry, i));
  }

  return txs;
};

ClientSocket.prototype.filterTX = function filterTX(tx) {
  var found = false;
  var i, hash, input, prevout, output;

  if (!this.filter)
    return false;

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    hash = output.getHash();

    if (!hash)
      continue;

    if (this.filter.test(hash)) {
      prevout = Outpoint.fromTX(tx, i);
      this.filter.add(prevout.toRaw());
      found = true;
    }
  }

  if (found)
    return true;

  if (!tx.isCoinbase()) {
    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      prevout = input.prevout;
      if (this.filter.test(prevout.toRaw()))
        return true;
    }
  }

  return false;
};

ClientSocket.prototype.scan = co(function* scan(start) {
  var scanner = this.scanner.bind(this);
  yield this.node.scan(start, this.filter, scanner);
});

ClientSocket.prototype.scanner = function scanner(entry, txs) {
  var block = this.frameEntry(entry);
  var raw = new Array(txs.length);
  var i;

  for (i = 0; i < txs.length; i++)
    raw[i] = this.frameTX(txs[i], null, entry, i);

  return this.rescanBlock(block, raw);
};

ClientSocket.prototype.frameEntry = function frameEntry(entry) {
  if (this.raw)
    return entry.toRaw();
  return entry.toJSON();
};

ClientSocket.prototype.frameTX = function frameTX(tx, view, entry, index) {
  if (this.raw)
    return tx.toRaw();
  return tx.getJSON(this.network, view, entry, index);
};

ClientSocket.prototype.join = function join(id) {
  this.socket.join(id);
};

ClientSocket.prototype.leave = function leave(id) {
  this.socket.leave(id);
};

ClientSocket.prototype.hook = function hook(type, handler) {
  this.socket.hook(type, handler);
};

ClientSocket.prototype.emit = function emit() {
  this.socket.emit.apply(this.socket, arguments);
};

ClientSocket.prototype.start = function start() {
  var self = this;
  this.stop();
  this.timeout = setTimeout(function() {
    self.timeout = null;
    self.destroy();
  }, 60000);
};

ClientSocket.prototype.stop = function stop() {
  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }
};

ClientSocket.prototype.destroy = function() {
  this.unbindAll();
  this.stop();
  this.socket.disconnect();
};

/*
 * Helpers
 */

function hash256(data) {
  if (typeof data !== 'string')
    return new Buffer(0);

  if (data.length > 200)
    return new Buffer(0);

  return crypto.hash256(new Buffer(data, 'utf8'));
}

function enforce(value, msg) {
  var err;

  if (!value) {
    err = new Error(msg);
    err.statusCode = 400;
    throw err;
  }
}

/**
 * TimedCB
 * @constructor
 * @ignore
 */

function TimedCB(resolve, reject) {
  this.resolve = resolve;
  this.reject = reject;
  this.done = false;
}

TimedCB.wrap = function wrap(resolve, reject) {
  return new TimedCB(resolve, reject).start();
};

TimedCB.prototype.start = function start() {
  var self = this;
  var timeout;

  timeout = setTimeout(function() {
    self.cleanup(timeout);
    self.reject(new Error('Callback timed out.'));
  }, 5000);

  return function(err) {
    self.cleanup(timeout);
    if (err) {
      self.reject(err);
      return;
    }
    self.resolve();
  };
};

TimedCB.prototype.cleanup = function cleanup(timeout) {
  assert(!this.done);
  this.done = true;
  clearTimeout(timeout);
};

/*
 * Expose
 */

module.exports = HTTPServer;
