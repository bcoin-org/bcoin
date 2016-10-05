/*!
 * server.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/* jshint -W069 */
/* jshint noyield: true */

var EventEmitter = require('events').EventEmitter;
var assert = require('assert');
var constants = require('../protocol/constants');
var HTTPBase = require('./base');
var utils = require('../utils/utils');
var co = require('../utils/co');
var Address = require('../primitives/address');
var TX = require('../primitives/tx');
var KeyRing = require('../primitives/keyring');
var Outpoint = require('../primitives/outpoint');
var HD = require('../hd/hd');
var Script = require('../script/script');
var crypto = require('../crypto/crypto');
var con = co.con;
var RPC;

/**
 * HTTPServer
 * @exports HTTPServer
 * @constructor
 * @param {Object} options
 * @param {Fullnode} options.node
 * @see HTTPBase
 * @emits HTTPServer#websocket
 */

function HTTPServer(options) {
  if (!(this instanceof HTTPServer))
    return new HTTPServer(options);

  if (!options)
    options = {};

  EventEmitter.call(this);

  this.options = options;
  this.node = options.node;

  assert(this.node, 'HTTP requires a Node.');

  this.network = this.node.network;
  this.chain = this.node.chain;
  this.mempool = this.node.mempool;
  this.pool = this.node.pool;
  this.fees = this.node.fees;
  this.miner = this.node.miner;
  this.wallet = this.node.wallet;
  this.walletdb = this.node.walletdb;
  this.logger = options.logger || this.node.logger;
  this.loaded = false;
  this.apiKey = options.apiKey;
  this.apiHash = null;
  this.adminHash = null;
  this.rpc = null;

  if (!this.apiKey)
    this.apiKey = utils.toBase58(crypto.randomBytes(20));

  assert(typeof this.apiKey === 'string', 'API key must be a string.');
  assert(this.apiKey.length <= 200, 'API key must be under 200 bytes.');

  this.apiHash = hash256(this.apiKey);
  this.adminHash = this.apiHash;

  if (options.adminKey) {
    assert(typeof options.adminKey === 'string', 'API key must be a string.');
    assert(options.adminKey.length <= 200, 'API key must be under 200 bytes.');
    this.adminHash = hash256(options.adminKey);
  }

  if (options.noAuth) {
    this.apiKey = null;
    this.apiHash = null;
  }

  options.sockets = true;

  this.server = new HTTPBase(options);

  this._init();
}

utils.inherits(HTTPServer, EventEmitter);

/**
 * Initialize routes.
 * @private
 */

HTTPServer.prototype._init = function _init() {
  var self = this;

  this.server.on('request', function(req, res) {
    if (req.pathname === '/')
      return;

    self.logger.debug('Request for path=%s (%s).',
      req.pathname, req.socket.remoteAddress);
  });

  this.server.on('listening', function(address) {
    self.logger.info('HTTP server listening on %s (port=%d).',
      address.address, address.port);
  });

  this.use(function(req, res, send, next) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET,HEAD,PUT,PATCH,POST,DELETE');

    if (req.method === 'OPTIONS') {
      res.statusCode = 200;
      return res.end();
    }

    res.setHeader('X-Bcoin-Version', constants.USER_VERSION);
    res.setHeader('X-Bcoin-Agent', constants.USER_AGENT);
    res.setHeader('X-Bcoin-Network', this.network.type);
    res.setHeader('X-Bcoin-Height', this.chain.height + '');
    res.setHeader('X-Bcoin-Tip', utils.revHex(this.chain.tip.hash));

    next();
  });

  this.use(function(req, res, send, next) {
    var auth = req.headers['authorization'];
    var parts;

    if (!auth) {
      req.username = null;
      req.password = null;
      req.admin = false;
      return next();
    }

    parts = auth.split(' ');
    assert(parts.length === 2, 'Invalid auth token.');
    assert(parts[0] === 'Basic', 'Invalid auth token.');

    auth = new Buffer(parts[1], 'base64').toString('utf8');
    parts = auth.split(':');

    req.username = parts.shift();
    req.password = parts.join(':');
    req.admin = false;

    next();
  });

  this.use(function(req, res, send, next) {
    var hash;

    if (!this.apiHash)
      return next();

    hash = hash256(req.password);

    if (crypto.ccmp(hash, this.adminHash)) {
      req.admin = true;
      return next();
    }

    if (crypto.ccmp(hash, this.apiHash))
      return next();

    res.setHeader('WWW-Authenticate', 'Basic realm="node"');

    if (req.method === 'POST'
        && req.pathname === '/') {
      send(401, {
        result: null,
        error: {
          message: 'Bad auth.',
          code: 1
        },
        id: req.body.id
      });
      return;
    }

    send(401, { error: 'Bad API key.' });
  });

  this.use(function(req, res, send, next) {
    var i, params, options, output, address;

    if (req.method === 'POST' && req.pathname === '/') {
      enforce(typeof req.body.method === 'string', 'Method must be a string.');
      enforce(Array.isArray(req.body.params), 'Params must be an array.');
      req.options = {};
      return next();
    }

    params = {};
    options = {};

    softMerge(params, req.params, true);
    softMerge(params, req.query, true);
    softMerge(params, req.body);

    this.logger.debug('Params:');
    this.logger.debug(params);

    if (params.id) {
      enforce(typeof params.id === 'string', 'ID must be a string.');
      options.id = params.id;
    }

    if (params.hash) {
      enforce(typeof params.hash === 'string', 'Hash must be a string.');
      if (params.hash.length !== 64) {
        options.height = Number(params.hash);
        enforce(utils.isUInt32(options.height), 'Height must be a number.');
      } else {
        options.hash = utils.revHex(params.hash);
      }
    }

    if (params.index != null) {
      options.index = Number(params.index);
      enforce(utils.isUInt32(options.index), 'Index must be a number.');
    }

    if (params.height != null) {
      options.height = Number(params.height);
      enforce(utils.isUInt32(options.height), 'Height must be a number.');
    }

    if (params.start != null) {
      options.start = Number(params.start);
      enforce(utils.isUInt32(options.start), 'Start must be a number.');
    }

    if (params.end != null) {
      options.end = Number(params.end);
      enforce(utils.isUInt32(options.end), 'End must be a number.');
    }

    if (params.limit != null) {
      options.limit = Number(params.limit);
      enforce(utils.isUInt32(options.limit), 'Limit must be a number.');
    }

    if (params.age != null) {
      options.age = Number(params.age);
      enforce(utils.isUInt32(options.age), 'Age must be a number.');
    }

    if (params.confirmations != null) {
      options.confirmations = Number(params.confirmations);
      enforce(utils.isNumber(options.confirmations),
        'Confirmations must be a number.');
    }

    if (params.fee)
      options.fee = utils.satoshi(params.fee);

    if (params.hardFee)
      options.hardFee = utils.satoshi(params.hardFee);

    if (params.maxFee)
      options.maxFee = utils.satoshi(params.maxFee);

    if (params.rate)
      options.rate = utils.satoshi(params.rate);

    if (params.m != null) {
      options.m = Number(params.m);
      enforce(utils.isUInt32(options.m), 'm must be a number.');
    }

    if (params.n != null) {
      options.n = Number(params.n);
      enforce(utils.isUInt32(options.n), 'n must be a number.');
    }

    if (params.blocks != null) {
      options.blocks = Number(params.blocks);
      enforce(utils.isUInt32(options.blocks), 'Blocks must be a number.');
    }

    if (params.subtractFee != null) {
      if (typeof params.subtractFee === 'number') {
        options.subtractFee = params.subtractFee;
        enforce(utils.isUInt32(options.subtractFee), 'subtractFee must be a number.');
      } else {
        options.subtractFee = params.subtractFee;
        enforce(typeof options.subtractFee === 'boolean', 'subtractFee must be a boolean.');
      }
    }

    if (params.watchOnly != null) {
      enforce(typeof params.watchOnly === 'boolean', 'watchOnly must be a boolean.');
      options.watchOnly = params.watchOnly;
    }

    if (params.accountKey) {
      enforce(typeof params.accountKey === 'string', 'accountKey must be a string.');
      options.accountKey = HD.fromExtended(params.accountKey);
    }

    if (params.timeout != null) {
      options.timeout = Number(params.timeout);
      enforce(utils.isNumber(options.timeout), 'Timeout must be a number.');
    }

    if (params.witness != null) {
      enforce(typeof params.witness === 'boolean', 'witness must be a boolean.');
      options.witness = params.witness;
    }

    if (params.outputs) {
      enforce(Array.isArray(params.outputs), 'Outputs must be an array.');
      options.outputs = [];
      for (i = 0; i < params.outputs.length; i++) {
        output = params.outputs[i];

        enforce(output && typeof output === 'object', 'Output must be an object.');

        if (output.address)
          enforce(typeof output.address === 'string', 'Address must be a string.');
        else if (output.script)
          enforce(typeof output.script === 'string', 'Script must be a string.');
        else
          enforce(false, 'No address or script present.');

        options.outputs.push({
          address: output.address
            ? Address.fromBase58(output.address)
            : null,
          script: output.script
            ? Script.fromRaw(output.script, 'hex')
            : null,
          value: utils.satoshi(output.value)
        });
      }
    }

    if (params.address) {
      if (Array.isArray(options.address)) {
        options.address = [];
        for (i = 0; i < params.address.length; i++) {
          address = params.address[i];
          enforce(typeof address === 'string', 'Address must be a string.');
          address = Address.fromBase58(address);
        }
      } else {
        enforce(typeof params.address === 'string', 'Address must be a string.');
        options.address = Address.fromBase58(params.address);
      }
    }

    if (params.tx) {
      if (typeof params.tx === 'object') {
        options.tx = TX.fromJSON(params.tx);
      } else {
        enforce(typeof params.tx === 'string', 'TX must be a hex string.');
        options.tx = TX.fromRaw(params.tx, 'hex');
      }
    }

    if (params.account != null) {
      if (typeof params.account === 'number') {
        options.account = params.account;
        enforce(utils.isUInt32(options.account), 'Account must be a number.');
      } else {
        enforce(typeof params.account === 'string', 'Account must be a string.');
        options.account = params.account;
      }
    }

    if (params.type) {
      enforce(typeof params.type === 'string', 'Type must be a string.');
      options.type = params.type;
    }

    if (params.name) {
      enforce(typeof params.name === 'string', 'Name must be a string.');
      options.name = params.name;
    }

    if (params.privateKey) {
      enforce(typeof params.privateKey === 'string', 'Key must be a string.');
      options.privateKey = KeyRing.fromSecret(params.privateKey);
    }

    if (params.publicKey) {
      enforce(typeof params.publicKey === 'string', 'Key must be a string.');
      options.publicKey = new Buffer(params.publicKey, 'hex');
      options.publicKey = KeyRing.fromKey(options.publicKey, this.network);
    }

    if (params.master) {
      enforce(typeof params.key === 'string', 'Key must be a string.');
      options.master = HD.fromExtended(params.master);
    }

    if (params.mnemonic) {
      enforce(typeof params.mnemonic === 'string', 'Key must be a string.');
      options.master = HD.fromMnemonic(params.mnemonic, this.network);
    }

    if (params.old) {
      enforce(typeof params.old === 'string', 'Passphrase must be a string.');
      enforce(params.old.length > 0, 'Passphrase must be a string.');
      options.old = params.old;
    }

    if (params.passphrase) {
      enforce(typeof params.passphrase === 'string', 'Passphrase must be a string.');
      enforce(params.passphrase.length > 0, 'Passphrase must be a string.');
      options.passphrase = params.passphrase;
    }

    if (params.token) {
      enforce(utils.isHex(params.token), 'Wallet token must be a hex string.');
      enforce(params.token.length === 64, 'Wallet token must be 32 bytes.');
      options.token = new Buffer(params.token, 'hex');
    }

    if (params.path) {
      enforce(typeof params.path === 'string', 'Passphrase must be a string.');
      options.path = params.path;
    }

    req.options = options;

    next();
  });

  this.use(con(function* (req, res, send, next) {
    var wallet;

    if (req.path.length < 2 || req.path[0] !== 'wallet') {
      next();
      return;
    }

    if (!this.options.walletAuth) {
      wallet = yield this.walletdb.get(req.options.id);

      if (!wallet) {
        send(404);
        return;
      }

      req.wallet = wallet;

      next();
      return;
    }

    try {
      wallet = yield this.walletdb.auth(req.options.id, req.options.token);
    } catch (err) {
      this.logger.info('Auth failure for %s: %s.',
        req.options.id, err.message);
      send(403, { error: err.message });
      return;
    }

    if (!wallet) {
      send(404);
      return;
    }

    req.wallet = wallet;

    this.logger.info('Successful auth for %s.', req.options.id);

    next();
  }));

  // JSON RPC
  this.post('/', con(function* (req, res, send, next) {
    var json;

    if (!this.rpc) {
      RPC = require('./rpc');
      this.rpc = new RPC(this.node);
    }

    if (req.body.method === 'getwork') {
      res.setHeader('X-Long-Polling', '/?longpoll=1');
      if (req.query.longpoll)
        req.body.method = 'getworklp';
    }

    try {
      json = yield this.rpc.execute(req.body, req.admin);
    } catch (err) {
      this.logger.error(err);

      if (err.type === 'RPCError') {
        return send(400, {
          result: err.message,
          error: null,
          id: req.body.id
        });
      }

      return send(500, {
        result: null,
        error: {
          message: err.message,
          code: 1
        },
        id: req.body.id
      });
    }

    send(200, {
      result: json != null ? json : null,
      error: null,
      id: req.body.id
    });
  }));

  this.get('/', function(req, res, send, next) {
    send(200, {
      version: constants.USER_VERSION,
      agent: constants.USER_AGENT,
      services: this.pool.services,
      network: this.network.type,
      height: this.chain.height,
      tip: this.chain.tip.rhash,
      peers: this.pool.peers.all.length,
      progress: this.chain.getProgress()
    });
  });

  // UTXO by address
  this.get('/coin/address/:address', con(function* (req, res, send, next) {
    var coins;

    enforce(req.options.address, 'Address is required.');

    coins = yield this.node.getCoinsByAddress(req.options.address);

    send(200, coins.map(function(coin) {
      return coin.toJSON();
    }));
  }));

  // UTXO by id
  this.get('/coin/:hash/:index', con(function* (req, res, send, next) {
    var coin;

    enforce(req.options.hash, 'Hash is required.');
    enforce(req.options.index != null, 'Index is required.');

    coin = yield this.node.getCoin(req.options.hash, req.options.index);

    if (!coin)
      return send(404);

    send(200, coin.toJSON());
  }));

  // Bulk read UTXOs
  this.post('/coin/address', con(function* (req, res, send, next) {
    var coins;

    enforce(req.options.address, 'Address is required.');

    coins = yield this.node.getCoinsByAddress(req.options.address);

    send(200, coins.map(function(coin) {
      return coin.toJSON();
    }));
  }));

  // TX by hash
  this.get('/tx/:hash', con(function* (req, res, send, next) {
    var tx;

    enforce(req.options.hash, 'Hash is required.');

    tx = yield this.node.getTX(req.options.hash);

    if (!tx)
      return send(404);

    yield this.node.fillHistory(tx);

    send(200, tx.toJSON());
  }));

  // TX by address
  this.get('/tx/address/:address', con(function* (req, res, send, next) {
    var i, txs, tx;

    enforce(req.options.address, 'Address is required.');

    txs = yield this.node.getTXByAddress(req.options.address);

    for (i = 0; i < txs.length; i++) {
      tx = txs[i];
      yield this.node.fillHistory(tx);
    }

    send(200, txs.map(function(tx) {
      return tx.toJSON();
    }));
  }));

  // Bulk read TXs
  this.post('/tx/address', con(function* (req, res, send, next) {
    var i, txs, tx;

    enforce(req.options.address, 'Address is required.');

    txs = yield this.node.getTXByAddress(req.options.address);

    for (i = 0; i < txs.length; i++) {
      tx = txs[i];
      yield this.node.fillHistory(tx);
    }

    send(200, txs.map(function(tx) {
      return tx.toJSON();
    }));
  }));

  // Block by hash/height
  this.get('/block/:hash', con(function* (req, res, send, next) {
    var hash = req.options.hash || req.options.height;
    var block;

    enforce(hash != null, 'Hash or height required.');

    block = yield this.node.getFullBlock(hash);

    if (!block)
      return send(404);

    send(200, block.toJSON());
  }));

  // Mempool snapshot
  this.get('/mempool', con(function* (req, res, send, next) {
    var i, txs, tx;

    if (!this.mempool)
      return send(400, { error: 'No mempool available.' });

    txs = this.mempool.getHistory();

    for (i = 0; i < txs.length; i++) {
      tx = txs[i];
      yield this.node.fillHistory(tx);
    }

    send(200, txs.map(function(tx) {
      return tx.toJSON();
    }));
  }));

  // Broadcast TX
  this.post('/broadcast', con(function* (req, res, send, next) {
    enforce(req.options.tx, 'TX is required.');
    yield this.node.sendTX(req.options.tx);
    send(200, { success: true });
  }));

  // Estimate fee
  this.get('/fee', function(req, res, send, next) {
    var fee;

    if (!this.fees)
      return send(400, { error: 'Fee estimation not available.' });

    fee = this.fees.estimateFee(req.options.blocks);

    send(200, { rate: utils.btc(fee) });
  });

  // Rescan
  this.post('/rescan', con(function* (req, res, send, next) {
    var options = req.options;
    var height = options.hash || options.height;

    enforce(height != null, 'Hash or height is required.');

    if (!req.admin)
      throw new Error('Cannot scan.');

    send(200, { success: true });
    yield this.node.scan(height);
  }));

  // Backup WalletDB
  this.post('/backup', con(function* (req, res, send, next) {
    var options = req.options;
    var path = options.path;

    enforce(path, 'Path is required.');

    if (!req.admin)
      throw new Error('Cannot backup.');

    yield this.walletdb.backup(path);
    send(200, { success: true });
  }));

  // Get wallet
  this.get('/wallet/:id', function(req, res, send, next) {
    send(200, req.wallet.toJSON());
  });

  // Create wallet
  this.post('/wallet/:id?', con(function* (req, res, send, next) {
    var wallet = yield this.walletdb.create(req.options);
    send(200, wallet.toJSON());
  }));

  // List accounts
  this.get('/wallet/:id/account', con(function* (req, res, send, next) {
    var accounts = yield req.wallet.getAccounts();
    send(200, accounts);
  }));

  // Get account
  this.get('/wallet/:id/account/:account', con(function* (req, res, send, next) {
    var options = req.options;
    var acct = options.name || options.account;
    var account;

    enforce(acct != null, 'Account is required.');

    account = yield req.wallet.getAccount(acct);

    if (!account)
      return send(404);

    send(200, account.toJSON());
  }));

  // Create account
  this.post('/wallet/:id/account/:account?', con(function* (req, res, send, next) {
    var options = req.options;
    var account;

    if (typeof options.account === 'string') {
      options.name = options.account;
      options.account = null;
    }

    account = yield req.wallet.createAccount(req.options);

    if (!account)
      return send(404);

    send(200, account.toJSON());
  }));

  // Change passphrase
  this.post('/wallet/:id/passphrase', con(function* (req, res, send, next) {
    var options = req.options;
    var old = options.old;
    var new_ = options.passphrase;
    enforce(old || new_, 'Passphrase is required.');
    yield req.wallet.setPassphrase(old, new_);
    send(200, { success: true });
  }));

  // Unlock wallet
  this.post('/wallet/:id/unlock', con(function* (req, res, send, next) {
    var options = req.options;
    var passphrase = options.passphrase;
    var timeout = options.timeout;
    enforce(passphrase, 'Passphrase is required.');
    yield req.wallet.unlock(passphrase, timeout);
    send(200, { success: true });
  }));

  // Lock wallet
  this.post('/wallet/:id/lock', con(function* (req, res, send, next) {
    yield req.wallet.lock();
    send(200, { success: true });
  }));

  // Import key
  this.post('/wallet/:id/import', con(function* (req, res, send, next) {
    var options = req.options;
    var acct = req.options.name || req.options.account;
    var key = options.privateKey || options.publicKey;

    if (key) {
      yield req.wallet.importKey(acct, key);
      send(200, { success: true });
      return;
    }

    if (options.address) {
      enforce(options.address instanceof Address, 'Address is required.');
      yield req.wallet.importAddress(acct, options.address);
      send(200, { success: true });
      return;
    }

    enforce(false, 'Key or address is required.');
  }));

  // Generate new token
  this.post('/wallet/:id/retoken', con(function* (req, res, send, next) {
    var options = req.options;
    var token = yield req.wallet.retoken(options.passphrase);
    send(200, { token: token.toString('hex') });
  }));

  // Send TX
  this.post('/wallet/:id/send', con(function* (req, res, send, next) {
    var options = req.options;
    var tx = yield req.wallet.send(options);
    send(200, tx.toJSON());
  }));

  // Create TX
  this.post('/wallet/:id/create', con(function* (req, res, send, next) {
    var options = req.options;
    var tx = yield req.wallet.createTX(options);
    yield req.wallet.sign(tx, options);
    send(200, tx.toJSON());
  }));

  // Sign TX
  this.post('/wallet/:id/sign', con(function* (req, res, send, next) {
    var options = req.options;
    var tx = req.options.tx;
    enforce(tx, 'TX is required.');
    yield req.wallet.sign(tx, options);
    send(200, tx.toJSON());
  }));

  // Fill TX
  this.post('/wallet/:id/fill', con(function* (req, res, send, next) {
    var tx = req.options.tx;
    enforce(tx, 'TX is required.');
    yield req.wallet.fillHistory(tx);
    send(200, tx.toJSON());
  }));

  // Zap Wallet TXs
  this.post('/wallet/:id/zap', con(function* (req, res, send, next) {
    var options = req.options;
    var acct = options.name || options.account;
    var age = options.age;
    enforce(age, 'Age is required.');
    yield req.wallet.zap(acct, age);
    send(200, { success: true });
  }));

  // Abandon Wallet TX
  this.del('/wallet/:id/tx/:hash', con(function* (req, res, send, next) {
    var hash = req.options.hash;
    enforce(hash, 'Hash is required.');
    yield req.wallet.abandon(hash);
    send(200, { success: true });
  }));

  // Add key
  this.put('/wallet/:id/key', con(function* (req, res, send, next) {
    var options = req.options;
    var acct = options.name || options.account;
    var key = options.accountKey;
    enforce(key, 'Key is required.');
    yield req.wallet.addKey(acct, key);
    send(200, { success: true });
  }));

  // Remove key
  this.del('/wallet/:id/key', con(function* (req, res, send, next) {
    var options = req.options;
    var acct = options.name || options.account;
    var key = options.accountKey;
    enforce(key, 'Key is required.');
    yield req.wallet.removeKey(acct, key);
    send(200, { success: true });
  }));

  // Create address
  this.post('/wallet/:id/address', con(function* (req, res, send, next) {
    var options = req.options;
    var acct = options.name || options.account;
    var address = yield req.wallet.createReceive(acct);
    send(200, address.toJSON());
  }));

  // Create nested address
  this.post('/wallet/:id/nested', con(function* (req, res, send, next) {
    var options = req.options;
    var acct = options.name || options.account;
    var address = yield req.wallet.createNested(acct);
    send(200, address.toJSON());
  }));

  // Wallet Balance
  this.get('/wallet/:id/balance', con(function* (req, res, send, next) {
    var options = req.options;
    var acct = options.name || options.account;
    var balance = yield req.wallet.getBalance(acct);

    if (!balance)
      return send(404);

    send(200, balance.toJSON());
  }));

  // Wallet UTXOs
  this.get('/wallet/:id/coin', con(function* (req, res, send, next) {
    var options = req.options;
    var acct = options.name || options.account;
    var coins = yield req.wallet.getCoins(acct);

    sortCoins(coins);

    send(200, coins.map(function(coin) {
      return coin.toJSON();
    }));
  }));

  // Locked coins
  this.get('/wallet/:id/coin/locked', con(function* (req, res, send, next) {
    var locked = this.wallet.getLocked();
    send(200, locked.map(function(outpoint) {
      return outpoint.toJSON();
    }));
  }));

  // Lock coin
  this.put('/wallet/:id/coin/locked', con(function* (req, res, send, next) {
    var options = req.options.hash;
    var outpoint;

    enforce(options.hash, 'Hash is required.');
    enforce(options.index != null, 'Index is required.');

    outpoint = new Outpoint(options.hash, options.index);

    this.wallet.lockCoin(outpoint);
  }));

  // Unlock coin
  this.del('/wallet/:id/coin/locked', con(function* (req, res, send, next) {
    var options = req.options.hash;
    var outpoint;

    enforce(options.hash, 'Hash is required.');
    enforce(options.index != null, 'Index is required.');

    outpoint = new Outpoint(options.hash, options.index);

    this.wallet.unlockCoin(outpoint);
  }));

  // Wallet Coin
  this.get('/wallet/:id/coin/:hash/:index', con(function* (req, res, send, next) {
    var hash = req.options.hash;
    var index = req.options.index;
    var coin;

    enforce(hash, 'Hash is required.');
    enforce(index != null, 'Index is required.');

    coin = yield req.wallet.getCoin(hash, index);

    if (!coin)
      return send(404);

    send(200, coin.toJSON());
  }));

  // Wallet TXs
  this.get('/wallet/:id/tx/history', con(function* (req, res, send, next) {
    var options = req.options;
    var acct = options.name || options.account;
    var txs = yield req.wallet.getHistory(acct);
    var details;

    sortTX(txs);

    details = yield req.wallet.toDetails(txs);

    send(200, details.map(function(tx) {
      return tx.toJSON();
    }));
  }));

  // Wallet Pending TXs
  this.get('/wallet/:id/tx/unconfirmed', con(function* (req, res, send, next) {
    var options = req.options;
    var acct = options.name || options.account;
    var txs = yield req.wallet.getUnconfirmed(acct);
    var details;

    sortTX(txs);

    details = yield req.wallet.toDetails(txs);

    send(200, details.map(function(tx) {
      return tx.toJSON();
    }));
  }));

  // Wallet TXs within time range
  this.get('/wallet/:id/tx/range', con(function* (req, res, send, next) {
    var options = req.options;
    var acct = options.name || options.account;
    var txs = yield req.wallet.getRange(acct, options);
    var details = yield req.wallet.toDetails(txs);
    send(200, details.map(function(tx) {
      return tx.toJSON();
    }));
  }));

  // Last Wallet TXs
  this.get('/wallet/:id/tx/last', con(function* (req, res, send, next) {
    var options = req.options;
    var acct = options.name || options.account;
    var limit = options.limit;
    var txs = yield req.wallet.getLast(acct, limit);
    var details = yield req.wallet.toDetails(txs);
    send(200, details.map(function(tx) {
      return tx.toJSON();
    }));
  }));

  // Wallet TX
  this.get('/wallet/:id/tx/:hash', con(function* (req, res, send, next) {
    var hash = req.options.hash;
    var tx, details;

    enforce(hash, 'Hash is required.');

    tx = yield req.wallet.getTX(hash);

    if (!tx)
      return send(404);

    details = yield req.wallet.toDetails(tx);

    send(200, details.toJSON());
  }));

  this.server.on('error', function(err) {
    self.emit('error', err);
  });

  this._initIO();
};

/**
 * Initialize websockets.
 * @private
 */

HTTPServer.prototype._initIO = function _initIO() {
  var self = this;

  if (!this.server.io)
    return;

  this.server.on('websocket', function(ws) {
    var socket = new ClientSocket(self, ws);

    socket.start();

    socket.on('error', function(err) {
      self.emit('error', err);
    });

    socket.on('disconnect', function() {
      socket.destroy();
    });

    socket.on('auth', function(args, callback) {
      var apiKey = args[0];
      var hash;

      if (socket.auth)
        return callback({ error: 'Already authed.' });

      socket.stop();

      if (self.apiHash) {
        hash = hash256(apiKey);
        if (crypto.ccmp(hash, self.adminHash)) {
          socket.admin = true;
        } else {
          if (!crypto.ccmp(hash, self.apiHash))
            return callback({ error: 'Bad key.' });
        }
      }

      socket.auth = true;

      self.logger.info('Successful auth from %s.', socket.host);

      self.emit('websocket', socket);

      callback();
    });

    socket.emit('version', {
      version: constants.USER_VERSION,
      agent: constants.USER_AGENT,
      network: self.network.type
    });
  });

  this.on('websocket', function(socket) {
    socket.on('wallet join', function(args, callback) {
      var id = args[0];
      var token = args[1];

      if (typeof id !== 'string')
        return callback({ error: 'Invalid parameter.' });

      if (!self.options.walletAuth) {
        socket.join(id);
        return callback();
      }

      if (!utils.isHex256(token))
        return callback({ error: 'Invalid parameter.' });

      self.walletdb.auth(id, token).then(function(wallet) {
        if (!wallet)
          return callback({ error: 'Wallet does not exist.' });

        self.logger.info('Successful wallet auth for %s.', id);

        socket.join(id);

        callback();
      }, function(err) {
        self.logger.info('Wallet auth failure for %s: %s.', id, err.message);
        return callback({ error: 'Bad token.' });
      });
    });

    socket.on('wallet leave', function(args, callback) {
      var id = args[0];

      if (typeof id !== 'string')
        return callback({ error: 'Invalid parameter.' });

      socket.leave(id);

      callback();
    });

    socket.on('watch chain', function(args, callback) {
      socket.watchChain();
      callback();
    });

    socket.on('unwatch chain', function(args, callback) {
      socket.unwatchChain();
      callback();
    });

    socket.on('watch address', function(args, callback) {
      var addresses = args[0];

      if (!Array.isArray(addresses))
        return callback({ error: 'Invalid parameter.' });

      try {
        socket.addFilter(addresses);
      } catch (e) {
        return callback({ error: e.message });
      }

      callback();
    });

    socket.on('unwatch address', function(args, callback) {
      var addresses = args[0];

      if (!Array.isArray(addresses))
        return callback({ error: 'Invalid parameter.' });

      try {
        socket.removeFilter(addresses);
      } catch (e) {
        return callback({ error: e.message });
      }

      callback();
    });

    socket.on('scan chain', function(args, callback) {
      var start = args[0];

      if (!socket.admin)
        return callback({ error: 'Cannot scan.' });

      if (!utils.isHex256(start) && !utils.isUInt32(start))
        return callback({ error: 'Invalid parameter.' });

      if (typeof start === 'string')
        start = utils.revHex(start);

      socket.scan(start).then(callback, function(err) {
        callback({ error: err.message });
      });
    });
  });

  this.walletdb.on('tx', function(id, tx, info) {
    var details = info.toJSON();
    self.server.io.to(id).emit('wallet tx', details);
    self.server.io.to('!all').emit('wallet tx', id, details);
  });

  this.walletdb.on('confirmed', function(id, tx, info) {
    var details = info.toJSON();
    self.server.io.to(id).emit('wallet confirmed', details);
    self.server.io.to('!all').emit('wallet confirmed', id, details);
  });

  this.walletdb.on('unconfirmed', function(id, tx, info) {
    var details = info.toJSON();
    self.server.io.to(id).emit('wallet unconfirmed', details);
    self.server.io.to('!all').emit('wallet unconfirmed', id, details);
  });

  this.walletdb.on('conflict', function(id, tx, info) {
    var details = info.toJSON();
    self.server.io.to(id).emit('wallet conflict', details);
    self.server.io.to('!all').emit('wallet conflict', id, details);
  });

  this.walletdb.on('balance', function(id, balance) {
    var json = balance.toJSON();
    self.server.io.to(id).emit('wallet balance', json);
    self.server.io.to('!all').emit('wallet balance', id, json);
  });

  this.walletdb.on('address', function(id, receive) {
    receive = receive.map(function(address) {
      return address.toJSON();
    });
    self.server.io.to(id).emit('wallet address', receive);
    self.server.io.to('!all').emit('wallet address', id, receive);
  });
};

/**
 * Open the server, wait for socket.
 * @returns {Promise}
 */

HTTPServer.prototype.open = co(function* open() {
  yield this.server.open();

  this.logger.info('HTTP server loaded.');

  if (this.apiKey) {
    this.logger.info('HTTP API key: %s', this.apiKey);
    this.apiKey = null;
  } else if (!this.apiHash) {
    this.logger.warning('WARNING: Your http server is open to the world.');
  }
});

/**
 * Close the server, wait for server socket to close.
 * @returns {Promise}
 */

HTTPServer.prototype.close = function close() {
  return this.server.close();
};

/**
 * @see HTTPBase#use
 */

HTTPServer.prototype.use = function use(path, callback) {
  return this.server.use(path, callback, this);
};

/**
 * @see HTTPBase#get
 */

HTTPServer.prototype.get = function get(path, callback) {
  return this.server.get(path, callback, this);
};

/**
 * @see HTTPBase#post
 */

HTTPServer.prototype.post = function post(path, callback) {
  return this.server.post(path, callback, this);
};

/**
 * @see HTTPBase#put
 */

HTTPServer.prototype.put = function put(path, callback) {
  return this.server.put(path, callback, this);
};

/**
 * @see HTTPBase#del
 */

HTTPServer.prototype.del = function del(path, callback) {
  return this.server.del(path, callback, this);
};

/**
 * @see HTTPBase#listen
 */

HTTPServer.prototype.listen = function listen(port, host) {
  return this.server.listen(port, host);
};

/**
 * ClientSocket
 * @constructor
 * @param {HTTPServer} server
 * @param {SocketIO.Socket}
 */

function ClientSocket(server, socket) {
  if (!(this instanceof ClientSocket))
    return new ClientSocket(server, socket);

  EventEmitter.call(this);

  this.server = server;
  this.socket = socket;
  this.host = socket.conn.remoteAddress;
  this.timeout = null;
  this.auth = false;
  this.filter = {};
  this.filterCount = 0;
  this.admin = false;

  this.chain = this.server.chain;
  this.mempool = this.server.mempool;
  this.pool = this.server.pool;
  this.logger = this.server.logger;
  this.events = [];

  this._init();
}

utils.inherits(ClientSocket, EventEmitter);

ClientSocket.prototype._init = function _init() {
  var self = this;
  var socket = this.socket;
  var emit = EventEmitter.prototype.emit;
  var onevent = socket.onevent.bind(socket);

  socket.onevent = function(packet) {
    var result = onevent(packet);
    var args = packet.data || [];
    var event = args.shift();
    var ack;

    if (typeof args[args.length - 1] === 'function')
      ack = args.pop();
    else
      ack = self.socket.ack(packet.id);

    emit.call(self, event, args, ack);

    return result;
  };

  socket.on('error', function(err) {
    emit.call(self, 'error', err);
  });

  socket.on('disconnect', function() {
    emit.call(self, 'disconnect');
  });
};

ClientSocket.prototype.addFilter = function addFilter(addresses) {
  var i, hash;

  for (i = 0; i < addresses.length; i++) {
    hash = Address.getHash(addresses[i], 'hex');

    if (!hash)
      throw new Error('Bad address.');

    if (!this.filter[hash]) {
      this.filter[hash] = true;
      this.filterCount++;
      if (this.pool.options.spv)
        this.pool.watch(hash, 'hex');
    }
  }
};

ClientSocket.prototype.removeFilter = function removeFilter(addresses) {
  var i, hash;

  for (i = 0; i < addresses.length; i++) {
    hash = Address.getHash(addresses[i], 'hex');

    if (!hash)
      throw new Error('Bad address.');

    if (this.filter[hash]) {
      delete this.filter[hash];
      this.filterCount--;
    }
  }
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

  this.bind(this.chain, 'connect', function(entry, block) {
    var txs;

    self.emit('block connect', entry.toJSON());

    txs = self.testBlock(block);

    if (txs)
      self.emit('block tx', entry.toJSON(), txs);
  });

  this.bind(this.chain, 'disconnect', function(entry, block) {
    self.emit('block disconnect', entry.toJSON());
  });

  this.bind(pool, 'tx', function(tx) {
    if (self.testFilter(tx))
      self.emit('mempool tx', tx.toJSON());
  });
};

ClientSocket.prototype.unwatchChain = function unwatchChain() {
  var pool = this.mempool || this.pool;
  this.unbind(this.chain, 'connect');
  this.unbind(this.chain, 'disconnect');
  this.unbind(pool, 'tx');
};

ClientSocket.prototype.testBlock = function testBlock(block) {
  var txs = [];
  var i, tx;

  if (this.filterCount === 0)
    return;

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];
    if (this.testFilter(tx))
      txs.push(tx.toJSON());
  }

  if (txs.length === 0)
    return;

  return txs;
};

ClientSocket.prototype.testFilter = function testFilter(tx) {
  var i, hashes, hash;

  if (this.filterCount === 0)
    return;

  hashes = tx.getHashes('hex');

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    if (this.filter[hash])
      return true;
  }
};

ClientSocket.prototype.scan = co(function* scan(start) {
  var scanner = this.scanner.bind(this);
  var entry;

  if (this.chain.db.options.spv) {
    entry = yield this.chain.db.get(start);

    if (!entry)
      throw new Error('Block not found.');

    if (!entry.isGenesis())
      start = entry.prevBlock;

    yield this.chain.reset(start);

    return;
  }

  if (this.chain.db.options.prune)
    throw new Error('Cannot scan in pruned mode.');

  yield this.chain.db.scan(start, this.filter, scanner);
});

ClientSocket.prototype.scanner = function scanner(entry, txs) {
  var json = new Array(txs.length);
  var i;

  for (i = 0; i < txs.length; i++)
    json[i] = txs[i].toJSON();

  this.emit('block tx', entry.toJSON(), json);

  return Promise.resolve(null);
};

ClientSocket.prototype.join = function join(id) {
  this.socket.join(id);
};

ClientSocket.prototype.leave = function leave(id) {
  this.socket.leave(id);
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

function softMerge(a, b, soft) {
  var keys = Object.keys(b);
  var i, key, value;
  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    value = b[key];
    if (!soft || value)
      a[key] = value;
  }
}

function enforce(value, msg) {
  var err;

  if (!value) {
    err = new Error(msg);
    err.statusCode = 400;
    throw err;
  }
}

function sortTX(txs) {
  return txs.sort(function(a, b) {
    return a.ps - b.ps;
  });
}

function sortCoins(coins) {
  return coins.sort(function(a, b) {
    a = a.height === -1 ? 0x7fffffff : a.height;
    b = b.height === -1 ? 0x7fffffff : b.height;
    return a - b;
  });
}

/*
 * Expose
 */

module.exports = HTTPServer;
