/*!
 * server.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/* jshint -W069 */

var bcoin = require('../env');
var EventEmitter = require('events').EventEmitter;
var constants = bcoin.protocol.constants;
var http = require('./');
var HTTPBase = http.base;
var utils = require('../utils');
var assert = utils.assert;
var RPC; /*= require('./rpc'); - load lazily */

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
  this.walletdb = this.node.walletdb;
  this.mempool = this.node.mempool;
  this.pool = this.node.pool;
  this.logger = options.logger || this.node.logger;
  this.loaded = false;
  this.apiKey = options.apiKey;
  this.rpc = null;

  if (this.apiKey) {
    if (typeof this.apiKey === 'string') {
      assert(utils.isHex(this.apiKey), 'API key must be a hex string.');
      this.apiKey = new Buffer(this.apiKey, 'hex');
    }
    assert(Buffer.isBuffer(this.apiKey));
    assert(this.apiKey.length === 32, 'API key must be 32 bytes.');
  } else {
    this.apiKey = bcoin.ec.random(32);
  }

  if (options.noAuth)
    this.apiKey = null;

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
    self.logger.debug('Request for path=%s (%s).',
      req.pathname, req.socket.remoteAddress);
  });

  this.use(function(req, res, next, send) {
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
    res.setHeader('X-Bcoin-Network', self.network.type);
    res.setHeader('X-Bcoin-Height', self.node.chain.height + '');
    res.setHeader('X-Bcoin-Tip', utils.revHex(self.node.chain.tip.hash));

    next();
  });

  this.use(function(req, res, next, send) {
    var auth = req.headers['authorization'];
    var parts;

    if (!auth) {
      req.username = null;
      req.password = null;
      return next();
    }

    parts = auth.split(' ');
    assert(parts.length === 2, 'Invalid auth token.');
    assert(parts[0] === 'Basic', 'Invalid auth token.');

    auth = new Buffer(parts[1], 'base64').toString('utf8');
    parts = auth.split(':');
    assert(parts.length >= 2, 'Invalid auth token.');

    req.username = parts.shift();
    req.password = parts.join(':');

    next();
  });

  this.use(function(req, res, next, send) {
    var params, options;

    if (req.method === 'POST'
        && req.pathname === '/') {
      req.options = {};
      if (self.apiKey) {
        assert(utils.isHex(req.password), 'API key must be a hex string.');
        assert(req.password.length === 64, 'API key must be 32 bytes.');
        req.password = new Buffer(req.password, 'hex');
      }
      return next();
    }

    params = utils.merge({}, req.params, req.query, req.body);
    options = {};

    self.logger.debug('Params:');
    self.logger.debug(params);

    if (params.id) {
      assert(params.id !== '!all');
      options.id = params.id;
    }

    if (params.hash) {
      if (params.hash.length !== 64)
        options.height = params.hash >>> 0;
      else
        options.hash = utils.revHex(params.hash);
    }

    if (params.index != null)
      options.index = params.index >>> 0;

    if (params.height != null)
      options.height = params.height >>> 0;

    if (params.start != null)
      options.start = params.start >>> 0;

    if (params.end != null)
      options.end = params.end >>> 0;

    if (params.limit != null)
      options.limit = params.limit >>> 0;

    if (params.address) {
      params.addresses = params.address;
      options.address = params.address;
    }

    if (params.rate)
      options.rate = utils.satoshi(params.rate);

    if (params.subtractFee)
      options.subtractFee = params.subtractFee;

    if (Array.isArray(params.outputs)) {
      options.outputs = params.outputs.map(function(output) {
        return {
          address: output.address,
          script: decodeScript(output.script),
          value: utils.satoshi(output.value)
        };
      });
    }

    if (params.addresses) {
      if (typeof params.addresses === 'string')
        options.addresses = params.addresses.split(',');
      else
        options.addresses = params.addresses;
    }

    if (params.tx) {
      try {
        if (typeof params.tx === 'object')
          options.tx = bcoin.tx.fromJSON(params.tx);
        else
          options.tx = bcoin.tx.fromRaw(params.tx, 'hex');
      } catch (e) {
        return next(e);
      }
    }

    if (typeof params.account === 'string')
      options.account = params.account || null;
    else if (typeof params.account === 'number')
      options.account = params.account;

    if (params.name)
      options.name = params.name;

    if (params.age)
      options.age = params.age >>> 0;

    if (params.key)
      params.keys = params.key;

    if (params.keys) {
      if (typeof params.keys === 'string')
        options.keys = params.keys.split(',');
      else
        options.keys = params.keys;
    }

    if (params.passphrase)
      options.passphrase = params.passphrase;

    if (req.password) {
      assert(utils.isHex(req.password), 'API key must be a hex string.');
      assert(req.password.length === 64, 'API key must be 32 bytes.');
      options.token = new Buffer(req.password, 'hex');
    }

    if (req.headers['x-bcoin-api-key'])
      params.apiKey = req.headers['x-bcoin-api-key'];

    if (params.apiKey) {
      assert(utils.isHex(params.apiKey), 'API key must be a hex string.');
      assert(params.apiKey.length === 64, 'API key must be 32 bytes.');
      options.apiKey = new Buffer(params.apiKey, 'hex');
    }

    req.options = options;

    next();
  });

  this.use(function(req, res, next, send) {
    if (req.method === 'POST'
        && req.pathname === '/') {
      return next();
    }

    if (self.apiKey) {
      if (!utils.ccmp(req.options.apiKey, self.apiKey)) {
        send(403, { error: 'Forbidden.' });
        return;
      }
    }

    if (req.path.length < 2 || req.path[0] !== 'wallet')
      return next();

    if (!self.options.walletAuth) {
      return self.walletdb.get(req.options.id, function(err, wallet) {
        if (err)
          return next(err);

        if (!wallet)
          return send(404);

        req.wallet = wallet;

        return next();
      });
    }

    self.walletdb.auth(req.options.id, req.options.token, function(err, wallet) {
      if (err) {
        self.logger.info('Auth failure for %s: %s.',
          req.options.id, err.message);
        res.setHeader('WWW-Authenticate', 'Basic realm="wallet"');
        send(401, { error: err.message });
        return;
      }

      if (!wallet)
        return send(404);

      req.wallet = wallet;
      self.logger.info('Successful auth for %s.', req.options.id);
      next();
    });
  });

  function decodeScript(script) {
    if (!script)
      return;
    if (typeof script === 'string')
      return bcoin.script.fromRaw(script, 'hex');
    return new bcoin.script(script);
  }

  // JSON RPC
  this.post('/', function(req, res, next, send) {
    if (!(req.body.method && req.body.params))
      return next(new Error('Method not found.'));

    if (self.apiKey) {
      if (!utils.ccmp(req.password, self.apiKey)) {
        res.setHeader('WWW-Authenticate', 'Basic realm="rpc"');
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
    }

    if (!self.rpc) {
      RPC = require('./rpc');
      self.rpc = new RPC(self.node);
    }

    self.rpc.execute(req.body, function(err, json) {
      if (err) {
        self.logger.error(err);

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
        result: json,
        error: null,
        id: req.body.id
      });
    });
  });

  this.get('/', function(req, res, next, send) {
    send(200, {
      version: constants.USER_VERSION,
      agent: constants.USER_AGENT,
      network: self.network.type,
      height: self.node.chain.height,
      tip: utils.revHex(self.node.chain.tip.hash),
      peers: self.node.pool.peers.all.length,
      progress: self.node.chain.getProgress()
    });
  });

  // UTXO by address
  this.get('/coin/address/:address', function(req, res, next, send) {
    self.node.getCoinsByAddress(req.options.addresses, function(err, coins) {
      if (err)
        return next(err);

      if (!coins.length)
        return send(404);

      send(200, coins.map(function(coin) {
        return coin.toJSON();
      }));
    });
  });

  // UTXO by id
  this.get('/coin/:hash/:index', function(req, res, next, send) {
    self.node.getCoin(req.options.hash, req.options.index, function(err, coin) {
      if (err)
        return next(err);

      if (!coin)
        return send(404);

      send(200, coin.toJSON());
    });
  });

  // Bulk read UTXOs
  this.post('/coin/address', function(req, res, next, send) {
    self.node.getCoinsByAddress(req.options.addresses, function(err, coins) {
      if (err)
        return next(err);

      if (!coins.length)
        return send(404);

      send(200, coins.map(function(coin) {
        return coin.toJSON();
      }));
    });
  });

  // TX by hash
  this.get('/tx/:hash', function(req, res, next, send) {
    self.node.getTX(req.options.hash, function(err, tx) {
      if (err)
        return next(err);

      if (!tx)
        return send(404);

      self.node.fillHistory(tx, function(err) {
        if (err)
          return next(err);

        send(200, tx.toJSON());
      });
    });
  });

  // TX by address
  this.get('/tx/address/:address', function(req, res, next, send) {
    self.node.getTXByAddress(req.options.addresses, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      utils.forEachSerial(txs, function(tx, next) {
        self.node.fillHistory(tx, next);
      }, function(err) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Bulk read TXs
  this.post('/tx/address', function(req, res, next, send) {
    self.node.getTXByAddress(req.options.addresses, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      utils.forEachSerial(txs, function(tx, next) {
        self.node.fillHistory(tx, next);
      }, function(err) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Block by hash/height
  this.get('/block/:hash', function(req, res, next, send) {
    var hash = req.options.hash || req.options.height;
    self.node.getFullBlock(hash, function(err, block) {
      if (err)
        return next(err);

      if (!block)
        return send(404);

      send(200, block.toJSON());
    });
  });

  // Mempool snapshot
  this.get('/mempool', function(req, res, next, send) {
    self.node.mempool.getHistory(function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      utils.forEachSerial(txs, function(tx, next) {
        self.node.fillHistory(tx, next);
      }, function(err) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Broadcast TX
  this.post('/broadcast', function(req, res, next, send) {
    self.node.sendTX(req.options.tx, function(err) {
      if (err)
        return next(err);

      send(200, { success: true });
    });
  });

  // Get wallet
  this.get('/wallet/:id', function(req, res, next, send) {
    send(200, req.wallet.toJSON());
  });

  // Create wallet
  this.post('/wallet/:id?', function(req, res, next, send) {
    var json;
    self.walletdb.create(req.options, function(err, wallet) {
      if (err)
        return next(err);

      json = wallet.toJSON();
      wallet.destroy();

      send(200, json);
    });
  });

  // List accounts
  this.get('/wallet/:id/account', function(req, res, next, send) {
    req.wallet.getAccounts(function(err, accounts) {
      if (err)
        return next(err);

      if (accounts.length === 0)
        return send(404);

      send(200, accounts);
    });
  });

  // Create/get account
  this.post('/wallet/:id/account/:account?', function(req, res, next, send) {
    req.wallet.createAccount(req.options, function(err, account) {
      if (err)
        return next(err);

      if (!account)
        return send(404);

      send(200, account.toJSON());
    });
  });

  // Change passphrase
  this.post('/wallet/:id/passphrase', function(req, res, next, send) {
    var options = req.options;
    var old = options.old;
    var new_ = options.passphrase;
    req.wallet.setPassphrase(old, new_, function(err) {
      if (err)
        return next(err);

      send(200, { success: true });
    });
  });

  // Generate new token
  this.post('/wallet/:id/retoken', function(req, res, next, send) {
    var options = req.options;
    req.wallet.retoken(options.passphrase, function(err, token) {
      if (err)
        return next(err);

      send(200, { token: token.toString('hex') });
    });
  });

  // Send TX
  this.post('/wallet/:id/send', function(req, res, next, send) {
    var options = req.options;

    req.wallet.send(options, function(err, tx) {
      if (err)
        return next(err);

      send(200, tx.toJSON());
    });
  });

  // Create TX
  this.post('/wallet/:id/create', function(req, res, next, send) {
    var options = req.options;

    req.wallet.createTX(options, function(err, tx) {
      if (err)
        return next(err);

      req.wallet.sign(tx, options, function(err) {
        if (err)
          return next(err);

        send(200, tx.toJSON());
      });
    });
  });

  // Sign TX
  this.post('/wallet/:id/sign', function(req, res, next, send) {
    var options = req.options;
    var tx = req.options.tx;

    req.wallet.sign(tx, options, function(err) {
      if (err)
        return next(err);

      send(200, tx.toJSON());
    });
  });

  // Fill TX
  this.post('/wallet/:id/fill', function(req, res, next, send) {
    var tx = req.options.tx;

    req.wallet.fillHistory(tx, function(err) {
      if (err)
        return next(err);

      send(200, tx.toJSON());
    });
  });

  // Zap Wallet TXs
  this.post('/wallet/:id/zap', function(req, res, next, send) {
    var account = req.options.account;
    var age = req.options.age;

    req.wallet.zap(account, age, function(err) {
      if (err)
        return next(err);

      send(200, { success: true });
    });
  });

  // Add key
  this.put('/wallet/:id/key', function(req, res, next, send) {
    var account = req.options.account;
    var key = req.options.key;
    req.wallet.addKey(account, key, function(err) {
      if (err)
        return next(err);

      send(200, { success: true });
    });
  });

  // Remove key
  this.del('/wallet/:id/key', function(req, res, next, send) {
    var account = req.options.account;
    var key = req.options.key;
    req.wallet.removeKey(account, key, function(err) {
      if (err)
        return next(err);

      send(200, { success: true });
    });
  });

  // Create address
  this.post('/wallet/:id/address', function(req, res, next, send) {
    var account = req.options.account;
    req.wallet.createAddress(account, false, function(err, address) {
      if (err)
        return next(err);

      send(200, address.toJSON());
    });
  });

  // Wallet Balance
  this.get('/wallet/:id/balance', function(req, res, next, send) {
    var account = req.options.account;
    req.wallet.getBalance(account, function(err, balance) {
      if (err)
        return next(err);

      if (!balance)
        return send(404);

      send(200, balance.toJSON());
    });
  });

  // Wallet UTXOs
  this.get('/wallet/:id/coin', function(req, res, next, send) {
    var account = req.options.account;
    req.wallet.getCoins(account, function(err, coins) {
      if (err)
        return next(err);

      if (!coins.length)
        return send(404);

      send(200, coins.map(function(coin) {
        return coin.toJSON();
      }));
    });
  });

  // Wallet Coin
  this.get('/wallet/:id/coin/:hash/:index', function(req, res, next, send) {
    var hash = req.options.hash;
    var index = req.options.index;
    req.wallet.getCoin(hash, index, function(err, coin) {
      if (err)
        return next(err);

      if (!coin)
        return send(404);

      send(200, coin.toJSON());
    });
  });

  // Wallet TXs
  this.get('/wallet/:id/tx/history', function(req, res, next, send) {
    var account = req.options.account;
    req.wallet.getHistory(account, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      req.wallet.toDetails(txs, function(err, txs) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Wallet Pending TXs
  this.get('/wallet/:id/tx/unconfirmed', function(req, res, next, send) {
    var account = req.options.account;
    req.wallet.getUnconfirmed(account, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      req.wallet.toDetails(txs, function(err, txs) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Wallet TXs within time range
  this.get('/wallet/:id/tx/range', function(req, res, next, send) {
    var account = req.options.account;
    var options = req.options;
    req.walletdb.getRange(account, options, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      req.wallet.toDetails(txs, function(err, txs) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Wallet TXs within time range
  this.get('/wallet/:id/tx/last', function(req, res, next, send) {
    var account = req.options.account;
    var limit = req.options.limit;
    req.wallet.getRange(account, limit, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      req.wallet.toDetails(txs, function(err, txs) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Wallet TX
  this.get('/wallet/:id/tx/:hash', function(req, res, next, send) {
    var hash = req.options.hash;
    req.wallet.getTX(hash, function(err, tx) {
      if (err)
        return next(err);

      if (!tx)
        return send(404);

      req.wallet.toDetails(tx, function(err, tx) {
        if (err)
          return next(err);
        send(200, tx.toJSON());
      });
    });
  });

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

  this.server.on('websocket', function(socket) {
    socket.bcoin = new ClientSocket(self, socket);
    socket.bcoin.startTimeout();

    socket.on('error', function(err) {
      self.emit('error', err);
    });

    socket.on('auth', function(apiKey, callback) {
      callback = utils.ensure(callback);

      if (!self.apiKey) {
        self.logger.info('Successful auth.');
        socket.bcoin.stopTimeout();
        self.emit('websocket', socket);
        return callback();
      }

      if (!utils.isHex(apiKey))
        return callback({ error: 'Bad key.' });

      apiKey = new Buffer(apiKey, 'hex');

      if (!utils.ccmp(apiKey, self.apiKey))
        return callback({ error: 'Bad key.' });

      self.logger.info('Successful auth.');
      socket.bcoin.stopTimeout();
      self.emit('websocket', socket);

      return callback();
    });

    socket.emit('version', {
      version: constants.USER_VERSION,
      agent: constants.USER_AGENT,
      network: self.network.type
    });
  });

  this.on('websocket', function(socket) {
    socket.on('wallet join', function(id, token, callback) {
      callback = utils.ensure(callback);

      if (!self.options.walletAuth) {
        socket.join(id);
        return callback();
      }

      self.walletdb.auth(id, token, function(err, wallet) {
        if (err) {
          self.logger.info('Wallet auth failure for %s: %s.', id, err.message);
          return callback({ error: 'Bad token.' });
        }

        if (!wallet)
          return callback({ error: 'Wallet does not exist.' });

        self.logger.info('Successful wallet auth for %s.', id);
        socket.join(id);
        return callback();
      });
    });

    socket.on('wallet leave', function(id, callback) {
      callback = utils.ensure(callback);
      socket.leave(id);
      return callback();
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
 * @param {Function} callback
 */

HTTPServer.prototype.open = function open(callback) {
  if (this.apiKey)
    this.logger.info('API key: %s', this.apiKey.toString('hex'));
  else
    this.logger.warning('WARNING: Your http server is open to the world.');

  this.server.open(callback);
};

/**
 * Close the server, wait for server socket to close.
 * @param {Function} callback
 */

HTTPServer.prototype.close = function close(callback) {
  this.server.close(callback);
};

/**
 * @see HTTPBase#use
 */

HTTPServer.prototype.use = function use(path, callback) {
  return this.server.use(path, callback);
};

/**
 * @see HTTPBase#get
 */

HTTPServer.prototype.get = function get(path, callback) {
  return this.server.get(path, callback);
};

/**
 * @see HTTPBase#post
 */

HTTPServer.prototype.post = function post(path, callback) {
  return this.server.post(path, callback);
};

/**
 * @see HTTPBase#put
 */

HTTPServer.prototype.put = function put(path, callback) {
  return this.server.put(path, callback);
};

/**
 * @see HTTPBase#del
 */

HTTPServer.prototype.del = function del(path, callback) {
  return this.server.del(path, callback);
};

/**
 * @see HTTPBase#listen
 */

HTTPServer.prototype.listen = function listen(port, host, callback) {
  var self = this;
  return this.server.listen(port, host, function(err, address) {
    if (err) {
      if (callback)
        return callback(err);
      return self.emit('error', err);
    }

    self.logger.info('HTTP server listening on %s (port=%d).',
      address.address, address.port);

    self.loaded = true;
    self.emit('open');

    if (callback)
      callback();
  });
};

/**
 * ClientSocket
 * @constructor
 * @param {HTTPServer} server
 * @param {SocketIO.Socket}
 */

function ClientSocket(server, socket) {
  this.server = server;
  this.socket = socket;
  this.timeout = null;
}

ClientSocket.prototype.startTimeout = function startTimeout() {
  var self = this;
  this.stopTimeout();
  this.timeout = setTimeout(function() {
    self.destroy();
  }, 60000);
};

ClientSocket.prototype.stopTimeout = function stopTimeout() {
  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }
};

ClientSocket.prototype.destroy = function() {
  this.socket.disconnect();
};

/*
 * Expose
 */

module.exports = HTTPServer;
