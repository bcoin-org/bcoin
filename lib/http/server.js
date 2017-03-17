/*!
 * server.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
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

/**
 * HTTPServer
 * @alias module:http.Server
 * @constructor
 * @param {Object} options
 * @param {Fullnode} options.node
 * @see HTTPBase
 * @emits HTTPServer#socket
 */

function HTTPServer(options) {
  if (!(this instanceof HTTPServer))
    return new HTTPServer(options);

  options = new HTTPOptions(options);

  HTTPBase.call(this, options);

  this.options = options;
  this.network = this.options.network;
  this.logger = this.options.logger.context('http');
  this.node = this.options.node;

  this.chain = this.node.chain;
  this.mempool = this.node.mempool;
  this.pool = this.node.pool;
  this.fees = this.node.fees;
  this.miner = this.node.miner;
  this.rpc = this.node.rpc;

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
      password: this.options.apiKey,
      realm: 'node'
    }));
  }

  this.use(this.bodyParser({
    contentType: 'json'
  }));

  this.use(this.jsonRPC(this.rpc));

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
    var index = valid.u32('index');
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
    var blocks = valid.u32('blocks');
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
    var height = valid.u32('height');

    enforce(height != null, 'Height is required.');

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

  this.on('socket', function(socket) {
    self.handleSocket(socket);
  });
};

/**
 * Handle new websocket.
 * @private
 * @param {WebSocket} socket
 */

HTTPServer.prototype.handleSocket = function handleSocket(socket) {
  socket.hook('auth', function(args) {
    var valid = new Validator([args]);
    var hash = this.options.apiHash;
    var key = valid.str(0);

    if (socket.auth)
      throw new Error('Already authed.');

    if (!this.options.noAuth) {
      if (!crypto.ccmp(hash256(key), hash))
        throw new Error('Bad key.');
    }

    socket.auth = true;

    this.logger.info('Successful auth from %s.', socket.remoteAddress);
    this.handleAuth(socket);

    return null;
  });

  socket.emit('version', {
    version: pkg.version,
    network: this.network.type
  });
};

/**
 * Handle new auth'd websocket.
 * @private
 * @param {WebSocket} socket
 */

HTTPServer.prototype.handleAuth = function handleAuth(socket) {
  socket.hook('watch chain', function(args) {
    socket.join('chain');
    return null;
  });

  socket.hook('unwatch chain', function(args) {
    socket.leave('chain');
    return null;
  });

  socket.hook('watch mempool', function(args) {
    socket.join('mempool');
    return null;
  });

  socket.hook('unwatch mempool', function(args) {
    socket.leave('mempool');
    return null;
  });

  socket.hook('set filter', function(args) {
    var valid = new Validator([args]);
    var data = valid.buf(0);

    if (!data)
      throw new Error('Invalid parameter.');

    socket.filter = Bloom.fromRaw(data);

    return null;
  });

  socket.hook('get tip', function(args) {
    return this.chain.tip.toRaw();
  });

  socket.hook('get entry', co(function* (args) {
    var valid = new Validator([args]);
    var block = valid.numhash(0);
    var entry;

    if (block == null)
      throw new Error('Invalid parameter.');

    entry = yield this.chain.db.getEntry(block);

    if (!(yield entry.isMainChain()))
      entry = null;

    if (!entry)
      return null;

    return entry.toRaw();
  }));

  socket.hook('add filter', function(args) {
    var valid = new Validator([args]);
    var chunks = valid.array(0);
    var i, data;

    if (!chunks)
      throw new Error('Invalid parameter.');

    if (!socket.filter)
      throw new Error('No filter set.');

    valid = new Validator([chunks]);

    for (i = 0; i < chunks.length; i++) {
      data = valid.buf(i);

      if (!data)
        throw new Error('Bad data chunk.');

      this.filter.add(data);

      if (this.node.spv)
        this.pool.watch(data);
    }

    return null;
  });

  socket.hook('reset filter', function(args) {
    socket.filter = null;
    return null;
  });

  socket.hook('estimate fee', function(args) {
    var valid = new Validator([args]);
    var blocks = valid.u32(0);
    var rate;

    if (!this.fees) {
      rate = this.network.feeRate;
      rate = Amount.btc(rate);
      return rate;
    }

    rate = this.fees.estimateFee(blocks);
    rate = Amount.btc(rate);

    return rate;
  });

  socket.hook('send', function(args) {
    var valid = new Validator([args]);
    var data = valid.buf(0);
    var tx;

    if (!data)
      throw new Error('Invalid parameter.');

    tx = TX.fromRaw(data);

    this.node.send(tx);

    return null;
  });

  socket.hook('rescan', function(args) {
    var valid = new Validator([args]);
    var start = valid.numhash(0);

    if (start == null)
      throw new Error('Invalid parameter.');

    return this.scan(socket, start);
  });

  this.bindChain();
};

/**
 * Bind to chain events.
 * @private
 */

HTTPServer.prototype.bindChain = function bindChain() {
  var self = this;
  var pool = this.mempool || this.pool;

  this.chain.on('connect', function(entry, block, view) {
    var list = self.channel('chain');
    var item, socket, raw, txs;

    if (!list)
      return;

    raw = entry.toRaw();

    self.to('chain', 'chain connect', raw);

    for (item = list.head; item; item = item.next) {
      socket = item.value;
      txs = self.filterBlock(socket, block);
      socket.emit('block connect', raw, txs);
    }
  });

  this.chain.on('disconnect', function(entry, block, view) {
    var list = self.channel('chain');
    var raw;

    if (!list)
      return;

    raw = entry.toRaw();

    self.to('chain', 'chain disconnect', raw);
    self.to('chain', 'block disconnect', raw);
  });

  this.chain.on('reset', function(tip) {
    var list = self.channel('chain');
    var raw;

    if (!list)
      return;

    raw = tip.toRaw();

    self.to('chain', 'chain reset', raw);
  });

  pool.on('tx', function(tx) {
    var list = self.channel('mempool');
    var item, socket, raw;

    if (!list)
      return;

    raw = tx.toRaw();

    for (item = list.head; item; item = item.next) {
      socket = item.value;

      if (!self.filterTX(socket, tx))
        continue;

      socket.emit('tx', raw);
    }
  });
};

/**
 * Filter block by socket.
 * @private
 * @param {WebSocket} socket
 * @param {Block} block
 * @returns {TX[]}
 */

HTTPServer.prototype.filterBlock = function filterBlock(socket, block) {
  var txs = [];
  var i, tx;

  if (!socket.filter)
    return txs;

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];
    if (this.filterTX(socket, tx))
      txs.push(tx.toRaw());
  }

  return txs;
};

/**
 * Filter transaction by socket.
 * @private
 * @param {WebSocket} socket
 * @param {TX} tx
 * @returns {Boolean}
 */

HTTPServer.prototype.filterTX = function filterTX(socket, tx) {
  var found = false;
  var i, hash, input, prevout, output;

  if (!socket.filter)
    return false;

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    hash = output.getHash();

    if (!hash)
      continue;

    if (socket.filter.test(hash)) {
      prevout = Outpoint.fromTX(tx, i);
      socket.filter.add(prevout.toRaw());
      found = true;
    }
  }

  if (found)
    return true;

  if (!tx.isCoinbase()) {
    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      prevout = input.prevout;
      if (socket.filter.test(prevout.toRaw()))
        return true;
    }
  }

  return false;
};

/**
 * Scan using a socket's filter.
 * @private
 * @param {WebSocket} socket
 * @param {Hash} start
 * @returns {Promise}
 */

HTTPServer.prototype.scan = co(function* scan(socket, start) {
  var scanner = this.scanner.bind(this, socket);
  yield this.node.scan(start, socket.filter, scanner);
  return null;
});

/**
 * Handle rescan iteration.
 * @private
 * @param {WebSocket} socket
 * @param {ChainEntry} entry
 * @param {TX[]} txs
 * @returns {Promise}
 */

HTTPServer.prototype.scanner = function scanner(socket, entry, txs) {
  var block = entry.toRaw();
  var raw = [];
  var i, tx;

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    raw.push(tx.toRaw());
  }

  socket.emit('block rescan', block, raw);

  return Promise.resolve();
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

/*
 * Expose
 */

module.exports = HTTPServer;
