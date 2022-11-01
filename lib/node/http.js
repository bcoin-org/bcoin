/*!
 * server.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const path = require('path');
const {Server} = require('bweb');
const Validator = require('bval');
const base58 = require('bcrypto/lib/encoding/base58');
const {BloomFilter} = require('bfilter');
const sha256 = require('bcrypto/lib/sha256');
const random = require('bcrypto/lib/random');
const {safeEqual} = require('bcrypto/lib/safe');
const util = require('../utils/util');
const Address = require('../primitives/address');
const TX = require('../primitives/tx');
const Outpoint = require('../primitives/outpoint');
const Network = require('../protocol/network');
const pkg = require('../pkg');

/**
 * HTTP
 * @alias module:http.Server
 */

class HTTP extends Server {
  /**
   * Create an http server.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super(new HTTPOptions(options));

    this.network = this.options.network;
    this.logger = this.options.logger.context('node-http');
    this.node = this.options.node;

    this.chain = this.node.chain;
    this.mempool = this.node.mempool;
    this.pool = this.node.pool;
    this.fees = this.node.fees;
    this.miner = this.node.miner;
    this.rpc = this.node.rpc;

    this.init();
  }

  /**
   * Initialize routes.
   * @private
   */

  init() {
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
  }

  /**
   * Initialize routes.
   * @private
   */

  initRouter() {
    if (this.options.cors)
      this.use(this.cors());

    if (!this.options.noAuth) {
      this.use(this.basicAuth({
        hash: sha256.digest,
        password: this.options.apiKey,
        realm: 'node'
      }));
    }

    this.use(this.bodyParser({
      type: 'json'
    }));

    this.use(this.jsonRPC());
    this.use(this.router());

    this.error((err, req, res) => {
      const code = err.statusCode || 500;
      res.json(code, {
        error: {
          type: err.type,
          code: err.code,
          message: err.message
        }
      });
    });

    this.get('/', async (req, res) => {
      const totalTX = this.mempool ? this.mempool.map.size : 0;
      const size = this.mempool ? this.mempool.getSize() : 0;
      const orphans = this.mempool ? this.mempool.orphans.size : 0;

      let addr = this.pool.hosts.getLocal();

      const filter = {};
      for (const type of this.node.filterIndexers.keys()) {
        const indexer = this.node.filterIndexers.get(type);
        filter[type] = {
          enabled: true,
          height: indexer.height
        };
      }

      if (!addr)
        addr = this.pool.hosts.address;

      res.json(200, {
        version: pkg.version,
        network: this.network.type,
        chain: {
          height: this.chain.height,
          tip: this.chain.tip.rhash(),
          progress: this.chain.getProgress()
        },
        indexes: {
          addr: {
            enabled: Boolean(this.node.addrindex),
            height: this.node.addrindex ? this.node.addrindex.height : 0
          },
          tx: {
            enabled: Boolean(this.node.txindex),
            height: this.node.txindex ? this.node.txindex.height : 0
          },
          filter
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
          size: size,
          orphans: orphans
        },
        time: {
          uptime: this.node.uptime(),
          system: util.now(),
          adjusted: this.network.now(),
          offset: this.network.time.offset
        },
        memory: this.logger.memoryUsage()
      });
    });

    // UTXO by id
    this.get('/coin/:hash/:index', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const hash = valid.brhash('hash');
      const index = valid.u32('index');

      enforce(hash, 'Hash is required.');
      enforce(index != null, 'Index is required.');
      enforce(!this.chain.options.spv, 'Cannot get coins in SPV mode.');

      const coin = await this.node.getCoin(hash, index);

      if (!coin) {
        res.json(404);
        return;
      }

      res.json(200, coin.getJSON(this.network));
    });

    // TX by hash
    this.get('/tx/:hash', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const hash = valid.brhash('hash');

      enforce(hash, 'Hash is required.');
      enforce(!this.chain.options.spv, 'Cannot get TX in SPV mode.');

      const meta = await this.node.getMeta(hash);

      if (!meta) {
        res.json(404);
        return;
      }

      const view = await this.node.getMetaView(meta);

      res.json(200, meta.getJSON(this.network, view, this.chain.height));
    });

    // TX by address
    this.get('/tx/address/:address', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const address = valid.str('address');
      const limit = valid.uint('limit', this.options.maxTxs);
      const reverse = valid.bool('reverse', false);
      const after = valid.brhash('after', null);

      enforce(address, 'Address is required.');
      enforce(!this.chain.options.spv, 'Cannot get TX in SPV mode.');
      enforce(limit <= this.options.maxTxs,
              `Limit above max of ${this.options.maxTxs}.`);

      const addr = Address.fromString(address, this.network);

      const metas = await this.node.getMetaByAddress(
        addr, {limit, reverse, after});

      const result = [];

      for (const meta of metas) {
        const view = await this.node.getMetaView(meta);
        result.push(meta.getJSON(this.network, view, this.chain.height));
      }

      res.json(200, result);
    });

    // Block by hash/height
    this.get('/block/:block', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const hash = valid.uintbrhash('block');

      enforce(hash != null, 'Hash or height required.');
      enforce(!this.chain.options.spv, 'Cannot get block in SPV mode.');

      const block = await this.chain.getBlock(hash);

      if (!block) {
        res.json(404);
        return;
      }

      const view = await this.chain.getBlockView(block);

      if (!view) {
        res.json(404);
        return;
      }

      const height = await this.chain.getHeight(hash);
      const depth = this.chain.height - height + 1;

      res.json(200, block.getJSON(this.network, view, height, depth));
    });

    // Block Header by hash/height
    this.get('/header/:block', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const hash = valid.uintbrhash('block');

      enforce(hash != null, 'Hash or height required.');

      const entry = await this.chain.getEntry(hash);

      if (!entry) {
        res.json(404);
        return;
      }

      res.json(200, entry.toJSON());
    });

    // Filters by hash/height
    this.get('/filter/:block', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const hash = valid.uintbrhash('block');

      enforce(hash != null, 'Hash or height required.');

      const filter = await this.node.getBlockFilter(hash);

      if (!filter) {
        res.json(404);
        return;
      }

      res.json(200, filter.toJSON());
    });

    // Mempool snapshot
    this.get('/mempool', async (req, res) => {
      enforce(this.mempool, 'No mempool available.');

      const hashes = this.mempool.getSnapshot();
      const result = [];

      for (const hash of hashes)
        result.push(util.revHex(hash));

      res.json(200, result);
    });

    // Broadcast TX
    this.post('/broadcast', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const raw = valid.buf('tx');

      enforce(raw, 'TX is required.');

      const tx = TX.fromRaw(raw);

      await this.node.sendTX(tx);

      res.json(200, { success: true });
    });

    // Estimate fee
    this.get('/fee', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const blocks = valid.u32('blocks', 1);

      if (!this.fees) {
        res.json(200, { rate: this.network.feeRate });
        return;
      }

      const fee = this.fees.estimateFee(blocks);

      res.json(200, { rate: fee });
    });

    // Reset chain
    this.post('/reset', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const height = valid.u32('height');

      enforce(height != null, 'Height is required.');
      enforce(height <= this.chain.height,
        'Height cannot be greater than chain tip.');

      await this.chain.reset(height);

      res.json(200, { success: true });
    });
  }

  /**
   * Handle new websocket.
   * @private
   * @param {WebSocket} socket
   */

  handleSocket(socket) {
    socket.hook('auth', (...args) => {
      if (socket.channel('auth'))
        throw new Error('Already authed.');

      if (!this.options.noAuth) {
        const valid = new Validator(args);
        const key = valid.str(0, '');

        if (key.length > 255)
          throw new Error('Invalid API key.');

        const data = Buffer.from(key, 'ascii');
        const hash = sha256.digest(data);

        if (!safeEqual(hash, this.options.apiHash))
          throw new Error('Invalid API key.');
      }

      socket.join('auth');

      this.logger.info('Successful auth from %s.', socket.host);
      this.handleAuth(socket);

      return null;
    });

    socket.fire('version', {
      version: pkg.version,
      network: this.network.type
    });
  }

  /**
   * Handle new auth'd websocket.
   * @private
   * @param {WebSocket} socket
   */

  handleAuth(socket) {
    socket.hook('watch chain', () => {
      socket.join('chain');
      return null;
    });

    socket.hook('unwatch chain', () => {
      socket.leave('chain');
      return null;
    });

    socket.hook('watch mempool', () => {
      socket.join('mempool');
      return null;
    });

    socket.hook('unwatch mempool', () => {
      socket.leave('mempool');
      return null;
    });

    socket.hook('set filter', (...args) => {
      const valid = new Validator(args);
      const data = valid.buf(0);

      if (!data)
        throw new Error('Invalid parameter.');

      socket.filter = BloomFilter.fromRaw(data);

      return null;
    });

    socket.hook('get tip', () => {
      return this.chain.tip.toRaw();
    });

    socket.hook('get entry', async (...args) => {
      const valid = new Validator(args);
      const block = valid.uintbrhash(0);

      if (block == null)
        throw new Error('Invalid parameter.');

      const entry = await this.chain.getEntry(block);

      if (!entry)
        return null;

      if (!await this.chain.isMainChain(entry))
        return null;

      return entry.toRaw();
    });

    socket.hook('get hashes', async (...args) => {
      const valid = new Validator(args);
      const start = valid.i32(0, -1);
      const end = valid.i32(1, -1);

      return this.chain.getHashes(start, end);
    });

    socket.hook('add filter', (...args) => {
      const valid = new Validator(args);
      const chunks = valid.array(0);

      if (!chunks)
        throw new Error('Invalid parameter.');

      if (!socket.filter)
        throw new Error('No filter set.');

      const items = new Validator(chunks);

      for (let i = 0; i < chunks.length; i++) {
        const data = items.buf(i);

        if (!data)
          throw new Error('Bad data chunk.');

        socket.filter.add(data);

        if (this.node.spv)
          this.pool.watch(data);
      }

      return null;
    });

    socket.hook('reset filter', () => {
      socket.filter = null;
      return null;
    });

    socket.hook('estimate fee', (...args) => {
      const valid = new Validator(args);
      const blocks = valid.u32(0);

      if (!this.fees)
        return this.network.feeRate;

      return this.fees.estimateFee(blocks);
    });

    socket.hook('send', (...args) => {
      const valid = new Validator(args);
      const data = valid.buf(0);

      if (!data)
        throw new Error('Invalid parameter.');

      const tx = TX.fromRaw(data);

      this.node.relay(tx);

      return null;
    });

    socket.hook('rescan', (...args) => {
      const valid = new Validator(args);
      const start = valid.uintbrhash(0);

      if (start == null)
        throw new Error('Invalid parameter.');

      return this.scan(socket, start);
    });

    socket.hook('abortrescan', () => {
      return this.chain.abortRescan();
    });
  }

  /**
   * Bind to chain events.
   * @private
   */

  initSockets() {
    const pool = this.mempool || this.pool;

    this.chain.on('connect', (entry, block, view) => {
      const sockets = this.channel('chain');

      if (!sockets)
        return;

      const raw = entry.toRaw();

      this.to('chain', 'chain connect', raw);

      for (const socket of sockets) {
        const txs = this.filterBlock(socket, block);
        socket.fire('block connect', raw, txs);
      }
    });

    this.chain.on('disconnect', (entry, block, view) => {
      const sockets = this.channel('chain');

      if (!sockets)
        return;

      const raw = entry.toRaw();

      this.to('chain', 'chain disconnect', raw);
      this.to('chain', 'block disconnect', raw);
    });

    this.chain.on('reset', (tip) => {
      const sockets = this.channel('chain');

      if (!sockets)
        return;

      this.to('chain', 'chain reset', tip.toRaw());
    });

    pool.on('tx', (tx) => {
      const sockets = this.channel('mempool');

      if (!sockets)
        return;

      const raw = tx.toRaw();

      for (const socket of sockets) {
        if (!this.filterTX(socket, tx))
          continue;

        socket.fire('tx', raw);
      }
    });
  }

  /**
   * Filter block by socket.
   * @private
   * @param {WebSocket} socket
   * @param {Block} block
   * @returns {TX[]}
   */

  filterBlock(socket, block) {
    if (!socket.filter)
      return [];

    const txs = [];

    for (const tx of block.txs) {
      if (this.filterTX(socket, tx))
        txs.push(tx.toRaw());
    }

    return txs;
  }

  /**
   * Filter transaction by socket.
   * @private
   * @param {WebSocket} socket
   * @param {TX} tx
   * @returns {Boolean}
   */

  filterTX(socket, tx) {
    if (!socket.filter)
      return false;

    let found = false;

    for (let i = 0; i < tx.outputs.length; i++) {
      const output = tx.outputs[i];
      const hash = output.getHash();

      if (!hash)
        continue;

      if (socket.filter.test(hash)) {
        const prevout = Outpoint.fromTX(tx, i);
        socket.filter.add(prevout.toRaw());
        found = true;
      }
    }

    if (found)
      return true;

    if (!tx.isCoinbase()) {
      for (const {prevout} of tx.inputs) {
        if (socket.filter.test(prevout.toRaw()))
          return true;
      }
    }

    return false;
  }

  /**
   * Scan using a socket's filter.
   * @private
   * @param {WebSocket} socket
   * @param {Hash} start
   * @returns {Promise}
   */

  async scan(socket, start) {
    if (!socket.filter)
      return null;

    await this.node.scan(start, socket.filter, (entry, txs) => {
      const block = entry.toRaw();
      const raw = [];

      for (const tx of txs)
        raw.push(tx.toRaw());

      return socket.call('block rescan', block, raw);
    });
    return null;
  }
}

class HTTPOptions {
  /**
   * HTTPOptions
   * @alias module:http.HTTPOptions
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.network = Network.primary;
    this.logger = null;
    this.node = null;
    this.apiKey = base58.encode(random.randomBytes(20));
    this.apiHash = sha256.digest(Buffer.from(this.apiKey, 'ascii'));
    this.noAuth = false;
    this.cors = false;
    this.maxTxs = 100;

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

  fromOptions(options) {
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
      assert(options.apiKey.length <= 255,
        'API key must be under 256 bytes.');
      this.apiKey = options.apiKey;
      this.apiHash = sha256.digest(Buffer.from(this.apiKey, 'ascii'));
    }

    if (options.noAuth != null) {
      assert(typeof options.noAuth === 'boolean');
      this.noAuth = options.noAuth;
    }

    if (options.cors != null) {
      assert(typeof options.cors === 'boolean');
      this.cors = options.cors;
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
      assert((options.port & 0xffff) === options.port,
        'Port must be a number.');
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

    if (options.maxTxs != null) {
      assert(Number.isSafeInteger(options.maxTxs));
      this.maxTxs = options.maxTxs;
    }

    // Allow no-auth implicitly
    // if we're listening locally.
    if (!options.apiKey) {
      if (this.host === '127.0.0.1' || this.host === '::1')
        this.noAuth = true;
    }

    return this;
  }

  /**
   * Instantiate http options from object.
   * @param {Object} options
   * @returns {HTTPOptions}
   */

  static fromOptions(options) {
    return new HTTPOptions().fromOptions(options);
  }
}

/*
 * Helpers
 */

function enforce(value, msg) {
  if (!value) {
    const err = new Error(msg);
    err.statusCode = 400;
    throw err;
  }
}

/*
 * Expose
 */

module.exports = HTTP;
