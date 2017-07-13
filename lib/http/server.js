/*!
 * server.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const path = require('path');
const HTTPBase = require('./base');
const util = require('../utils/util');
const base58 = require('../utils/base58');
const Bloom = require('../utils/bloom');
const TX = require('../primitives/tx');
const Outpoint = require('../primitives/outpoint');
const digest = require('../crypto/digest');
const random = require('../crypto/random');
const ccmp = require('../crypto/ccmp');
const Network = require('../protocol/network');
const Validator = require('../utils/validator');
const pkg = require('../pkg');

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
  this.on('request', (req, res) => {
    if (req.method === 'POST' && req.pathname === '/')
      return;

    this.logger.debug('Request for method=%s path=%s (%s).',
      req.method, req.pathname, req.socket.remoteAddress);
  });

  this.on('listening', (address) => {
    this.logger.info('Node HTTP server listening on %s (port=%d).',
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

  this.get('/', async (req, res) => {
    let totalTX = this.mempool ? this.mempool.map.size : 0;
    let size = this.mempool ? this.mempool.getSize() : 0;
    let addr = this.pool.hosts.getLocal();

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
  });

  // UTXO by address
  this.get('/coin/address/:address', async (req, res) => {
    let valid = req.valid();
    let address = valid.str('address');
    let result = [];
    let coins;

    enforce(address, 'Address is required.');
    enforce(!this.chain.options.spv, 'Cannot get coins in SPV mode.');

    coins = await this.node.getCoinsByAddress(address);

    for (let coin of coins)
      result.push(coin.getJSON(this.network));

    res.send(200, result);
  });

  // UTXO by id
  this.get('/coin/:hash/:index', async (req, res) => {
    let valid = req.valid();
    let hash = valid.hash('hash');
    let index = valid.u32('index');
    let coin;

    enforce(hash, 'Hash is required.');
    enforce(index != null, 'Index is required.');
    enforce(!this.chain.options.spv, 'Cannot get coins in SPV mode.');

    coin = await this.node.getCoin(hash, index);

    if (!coin) {
      res.send(404);
      return;
    }

    res.send(200, coin.getJSON(this.network));
  });

  // Bulk read UTXOs
  this.post('/coin/address', async (req, res) => {
    let valid = req.valid();
    let address = valid.array('addresses');
    let result = [];
    let coins;

    enforce(address, 'Address is required.');
    enforce(!this.chain.options.spv, 'Cannot get coins in SPV mode.');

    coins = await this.node.getCoinsByAddress(address);

    for (let coin of coins)
      result.push(coin.getJSON(this.network));

    res.send(200, result);
  });

  // TX by hash
  this.get('/tx/:hash', async (req, res) => {
    let valid = req.valid();
    let hash = valid.hash('hash');
    let meta, view;

    enforce(hash, 'Hash is required.');
    enforce(!this.chain.options.spv, 'Cannot get TX in SPV mode.');

    meta = await this.node.getMeta(hash);

    if (!meta) {
      res.send(404);
      return;
    }

    view = await this.node.getMetaView(meta);

    res.send(200, meta.getJSON(this.network, view));
  });

  // TX by address
  this.get('/tx/address/:address', async (req, res) => {
    let valid = req.valid();
    let address = valid.str('address');
    let result = [];
    let metas;

    enforce(address, 'Address is required.');
    enforce(!this.chain.options.spv, 'Cannot get TX in SPV mode.');

    metas = await this.node.getMetaByAddress(address);

    for (let meta of metas) {
      let view = await this.node.getMetaView(meta);
      result.push(meta.getJSON(this.network, view));
    }

    res.send(200, result);
  });

  // Bulk read TXs
  this.post('/tx/address', async (req, res) => {
    let valid = req.valid();
    let address = valid.array('address');
    let result = [];
    let metas;

    enforce(address, 'Address is required.');
    enforce(!this.chain.options.spv, 'Cannot get TX in SPV mode.');

    metas = await this.node.getMetaByAddress(address);

    for (let meta of metas) {
      let view = await this.node.getMetaView(meta);
      result.push(meta.getJSON(this.network, view));
    }

    res.send(200, result);
  });

  // Block by hash/height
  this.get('/block/:block', async (req, res) => {
    let valid = req.valid();
    let hash = valid.get('block');
    let block, view, height;

    enforce(typeof hash === 'string', 'Hash or height required.');
    enforce(!this.chain.options.spv, 'Cannot get block in SPV mode.');

    if (hash.length === 64)
      hash = util.revHex(hash);
    else
      hash = +hash;

    block = await this.chain.db.getBlock(hash);

    if (!block) {
      res.send(404);
      return;
    }

    view = await this.chain.db.getBlockView(block);

    if (!view) {
      res.send(404);
      return;
    }

    height = await this.chain.db.getHeight(hash);

    res.send(200, block.getJSON(this.network, view, height));
  });

  // Mempool snapshot
  this.get('/mempool', async (req, res) => {
    let result = [];
    let hashes;

    enforce(this.mempool, 'No mempool available.');

    hashes = this.mempool.getSnapshot();

    for (let hash of hashes)
      result.push(util.revHex(hash));

    res.send(200, result);
  });

  // Broadcast TX
  this.post('/broadcast', async (req, res) => {
    let valid = req.valid();
    let raw = valid.buf('tx');
    let tx;

    enforce(raw, 'TX is required.');

    tx = TX.fromRaw(raw);

    await this.node.sendTX(tx);

    res.send(200, { success: true });
  });

  // Estimate fee
  this.get('/fee', async (req, res) => {
    let valid = req.valid();
    let blocks = valid.u32('blocks');
    let fee;

    if (!this.fees) {
      res.send(200, { rate: this.network.feeRate });
      return;
    }

    fee = this.fees.estimateFee(blocks);

    res.send(200, { rate: fee });
  });

  // Reset chain
  this.post('/reset', async (req, res) => {
    let valid = req.valid();
    let height = valid.u32('height');

    enforce(height != null, 'Height is required.');

    await this.chain.reset(height);

    res.send(200, { success: true });
  });
};

/**
 * Initialize websockets.
 * @private
 */

HTTPServer.prototype.initSockets = function initSockets() {
  if (!this.io)
    return;

  this.on('socket', (socket) => {
    this.handleSocket(socket);
  });
};

/**
 * Handle new websocket.
 * @private
 * @param {WebSocket} socket
 */

HTTPServer.prototype.handleSocket = function handleSocket(socket) {
  socket.hook('auth', (args) => {
    let valid = new Validator([args]);
    let hash = this.options.apiHash;
    let key = valid.str(0);

    if (socket.auth)
      throw new Error('Already authed.');

    if (!this.options.noAuth) {
      if (!ccmp(hash256(key), hash))
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
  socket.hook('watch chain', (args) => {
    socket.join('chain');
    return null;
  });

  socket.hook('unwatch chain', (args) => {
    socket.leave('chain');
    return null;
  });

  socket.hook('watch mempool', (args) => {
    socket.join('mempool');
    return null;
  });

  socket.hook('unwatch mempool', (args) => {
    socket.leave('mempool');
    return null;
  });

  socket.hook('set filter', (args) => {
    let valid = new Validator([args]);
    let data = valid.buf(0);

    if (!data)
      throw new Error('Invalid parameter.');

    socket.filter = Bloom.fromRaw(data);

    return null;
  });

  socket.hook('get tip', (args) => {
    return this.chain.tip.toRaw();
  });

  socket.hook('get entry', async (args) => {
    let valid = new Validator([args]);
    let block = valid.numhash(0);
    let entry;

    if (block == null)
      throw new Error('Invalid parameter.');

    entry = await this.chain.db.getEntry(block);

    if (!(await entry.isMainChain()))
      entry = null;

    if (!entry)
      return null;

    return entry.toRaw();
  });

  socket.hook('add filter', (args) => {
    let valid = new Validator([args]);
    let chunks = valid.array(0);

    if (!chunks)
      throw new Error('Invalid parameter.');

    if (!socket.filter)
      throw new Error('No filter set.');

    valid = new Validator([chunks]);

    for (let i = 0; i < chunks.length; i++) {
      let data = valid.buf(i);

      if (!data)
        throw new Error('Bad data chunk.');

      this.filter.add(data);

      if (this.node.spv)
        this.pool.watch(data);
    }

    return null;
  });

  socket.hook('reset filter', (args) => {
    socket.filter = null;
    return null;
  });

  socket.hook('estimate fee', (args) => {
    let valid = new Validator([args]);
    let blocks = valid.u32(0);

    if (!this.fees)
      return this.network.feeRate;

    return this.fees.estimateFee(blocks);
  });

  socket.hook('send', (args) => {
    let valid = new Validator([args]);
    let data = valid.buf(0);
    let tx;

    if (!data)
      throw new Error('Invalid parameter.');

    tx = TX.fromRaw(data);

    this.node.send(tx);

    return null;
  });

  socket.hook('rescan', (args) => {
    let valid = new Validator([args]);
    let start = valid.numhash(0);

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
  let pool = this.mempool || this.pool;

  this.chain.on('connect', (entry, block, view) => {
    let list = this.channel('chain');
    let raw;

    if (!list)
      return;

    raw = entry.toRaw();

    this.to('chain', 'chain connect', raw);

    for (let item = list.head; item; item = item.next) {
      let socket = item.value;
      let txs = this.filterBlock(socket, block);
      socket.emit('block connect', raw, txs);
    }
  });

  this.chain.on('disconnect', (entry, block, view) => {
    let list = this.channel('chain');
    let raw;

    if (!list)
      return;

    raw = entry.toRaw();

    this.to('chain', 'chain disconnect', raw);
    this.to('chain', 'block disconnect', raw);
  });

  this.chain.on('reset', (tip) => {
    let list = this.channel('chain');
    let raw;

    if (!list)
      return;

    raw = tip.toRaw();

    this.to('chain', 'chain reset', raw);
  });

  pool.on('tx', (tx) => {
    let list = this.channel('mempool');
    let raw;

    if (!list)
      return;

    raw = tx.toRaw();

    for (let item = list.head; item; item = item.next) {
      let socket = item.value;

      if (!this.filterTX(socket, tx))
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
  let txs = [];

  if (!socket.filter)
    return txs;

  for (let tx of block.txs) {
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
  let found = false;

  if (!socket.filter)
    return false;

  for (let i = 0; i < tx.outputs.length; i++) {
    let output = tx.outputs[i];
    let hash = output.getHash();

    if (!hash)
      continue;

    if (socket.filter.test(hash)) {
      let prevout = Outpoint.fromTX(tx, i);
      socket.filter.add(prevout.toRaw());
      found = true;
    }
  }

  if (found)
    return true;

  if (!tx.isCoinbase()) {
    for (let {prevout} of tx.inputs) {
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

HTTPServer.prototype.scan = async function scan(socket, start) {
  let scanner = this.scanner.bind(this, socket);
  await this.node.scan(start, socket.filter, scanner);
  return null;
};

/**
 * Handle rescan iteration.
 * @private
 * @param {WebSocket} socket
 * @param {ChainEntry} entry
 * @param {TX[]} txs
 * @returns {Promise}
 */

HTTPServer.prototype.scanner = function scanner(socket, entry, txs) {
  let block = entry.toRaw();
  let raw = [];

  for (let tx of txs)
    raw.push(tx.toRaw());

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
  this.apiKey = base58.encode(random.randomBytes(20));
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
    this.keyFile = path.join(this.prefix, 'key.pem');
    this.certFile = path.join(this.prefix, 'cert.pem');
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
    return Buffer.alloc(0);

  if (data.length > 200)
    return Buffer.alloc(0);

  return digest.hash256(Buffer.from(data, 'utf8'));
}

function enforce(value, msg) {
  if (!value) {
    let err = new Error(msg);
    err.statusCode = 400;
    throw err;
  }
}

/*
 * Expose
 */

module.exports = HTTPServer;
