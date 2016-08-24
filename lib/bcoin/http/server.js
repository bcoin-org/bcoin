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
var utils = require('../utils/utils');
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
  this.rpc = null;

  if (!this.apiKey)
    this.apiKey = utils.toBase58(bcoin.ec.random(20));

  assert(typeof this.apiKey === 'string', 'API key must be a string.');
  assert(this.apiKey.length <= 200, 'API key must be under 200 bytes.');

  this.apiHash = hash256(this.apiKey);

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
    self.logger.debug('Request for path=%s (%s).',
      req.pathname, req.socket.remoteAddress);
  });

  this.server.on('listening', function(address) {
    self.logger.info('HTTP server listening on %s (port=%d).',
      address.address, address.port);
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
    res.setHeader('X-Bcoin-Height', self.chain.height + '');
    res.setHeader('X-Bcoin-Tip', utils.revHex(self.chain.tip.hash));

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

    req.username = parts.shift();
    req.password = parts.join(':');

    next();
  });

  this.use(function(req, res, next, send) {
    if (!self.apiHash)
      return next();

    if (utils.ccmp(hash256(req.password), self.apiHash))
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

  this.use(function(req, res, next, send) {
    var i, params, options, output, address;

    if (req.method === 'POST' && req.pathname === '/') {
      assert(typeof req.body.method === 'string', 'Method must be a string.');
      assert(Array.isArray(req.body.params), 'Params must be an array.');
      req.options = {};
      return next();
    }

    params = {};
    options = {};

    softMerge(params, req.params, true);
    softMerge(params, req.query, true);
    softMerge(params, req.body);

    self.logger.debug('Params:');
    self.logger.debug(params);

    if (params.id) {
      assert(typeof params.id === 'string', 'ID must be a string.');
      options.id = params.id;
    }

    if (params.hash) {
      assert(typeof params.hash === 'string', 'Hash must be a string.');
      if (params.hash.length !== 64) {
        options.height = Number(params.hash);
        assert(utils.isUInt32(options.height), 'Height must be a number.');
      } else {
        options.hash = utils.revHex(params.hash);
      }
    }

    if (params.index != null) {
      options.index = Number(params.index);
      assert(utils.isUInt32(options.index), 'Index must be a number.');
    }

    if (params.height != null) {
      options.height = Number(params.height);
      assert(utils.isUInt32(options.height), 'Height must be a number.');
    }

    if (params.start != null) {
      options.start = Number(params.start);
      assert(utils.isUInt32(options.height), 'Start must be a number.');
    }

    if (params.end != null) {
      options.end = Number(params.end);
      assert(utils.isUInt32(options.end), 'End must be a number.');
    }

    if (params.limit != null) {
      options.limit = Number(params.limit);
      assert(utils.isUInt32(options.limit), 'Limit must be a number.');
    }

    if (params.age != null) {
      options.age = Number(params.age);
      assert(utils.isUInt32(options.age), 'Age must be a number.');
    }

    if (params.fee)
      options.fee = utils.satoshi(params.fee);

    if (params.maxFee)
      options.maxFee = utils.satoshi(params.maxFee);

    if (params.rate)
      options.rate = utils.satoshi(params.rate);

    if (params.m != null) {
      options.m = Number(params.m);
      assert(utils.isUInt32(options.m), 'm must be a number.');
    }

    if (params.n != null) {
      options.n = Number(params.n);
      assert(utils.isUInt32(options.n), 'n must be a number.');
    }

    if (params.blocks != null) {
      options.blocks = Number(params.blocks);
      assert(utils.isUInt32(options.blocks), 'Blocks must be a number.');
    }

    if (params.subtractFee != null) {
      if (typeof params.subtractFee === 'number') {
        options.subtractFee = params.subtractFee;
        assert(utils.isUInt32(options.subtractFee), 'subtractFee must be a number.');
      } else {
        assert(typeof options.subtractFee === 'boolean', 'subtractFee must be a boolean.');
        options.subtractFee = params.subtractFee;
      }
    }

    if (params.outputs) {
      assert(Array.isArray(params.outputs), 'Outputs must be an array.');
      options.outputs = [];
      for (i = 0; i < params.outputs.length; i++) {
        output = params.outputs[i];

        if (output.address)
          assert(typeof output.address === 'string', 'Address must be a string.');
        else if (output.script)
          assert(typeof output.script === 'string', 'Script must be a string.');
        else
          assert(false, 'No address or script present.');

        options.outputs.push({
          address: output.address
            ? bcoin.address.fromBase58(output.address)
            : null,
          script: output.script
            ? bcoin.script.fromRaw(output.script, 'hex')
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
          assert(typeof address === 'string', 'Address must be a string.');
          address = bcoin.address.fromBase58(address);
        }
      } else {
        assert(typeof params.address === 'string', 'Address must be a string.');
        options.address = bcoin.address.fromBase58(params.address);
      }
    }

    if (params.tx) {
      if (typeof params.tx === 'object') {
        options.tx = bcoin.tx.fromJSON(params.tx);
      } else {
        assert(typeof params.tx === 'string', 'TX must be a hex string.');
        options.tx = bcoin.tx.fromRaw(params.tx, 'hex');
      }
    }

    if (params.account != null) {
      if (typeof params.account === 'number') {
        options.account = params.account;
        assert(utils.isUInt32(options.account), 'Account must be a number.');
      } else {
        assert(typeof params.account === 'string', 'Account must be a string.');
        options.account = params.account;
      }
    }

    if (params.type) {
      assert(typeof params.type === 'string', 'Type must be a string.');
      options.type = params.type;
    }

    if (params.name) {
      assert(typeof params.name === 'string', 'Name must be a string.');
      options.name = params.name;
    }

    if (params.key) {
      assert(typeof params.key === 'string', 'Key must be a string.');
      options.key = params.key;
    }

    if (params.old) {
      assert(typeof params.old === 'string', 'Passphrase must be a string.');
      assert(params.old.length > 0, 'Passphrase must be a string.');
      options.old = params.old;
    }

    if (params.passphrase) {
      assert(typeof params.passphrase === 'string', 'Passphrase must be a string.');
      assert(params.passphrase.length > 0, 'Passphrase must be a string.');
      options.passphrase = params.passphrase;
    }

    if (params.token) {
      assert(utils.isHex(params.token), 'API key must be a hex string.');
      assert(params.token.length === 64, 'API key must be 32 bytes.');
      options.token = new Buffer(params.token, 'hex');
    }

    req.options = options;

    next();
  });

  this.use(function(req, res, next, send) {
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
        send(403, { error: err.message });
        return;
      }

      if (!wallet)
        return send(404);

      req.wallet = wallet;
      self.logger.info('Successful auth for %s.', req.options.id);
      next();
    });
  });

  // JSON RPC
  this.post('/', function(req, res, next, send) {
    if (!self.rpc) {
      RPC = require('./rpc');
      self.rpc = new RPC(self.node);
    }

    function handle(err, json) {
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
    }

    try {
      self.rpc.execute(req.body, handle);
    } catch (e) {
      handle(e);
    }
  });

  this.get('/', function(req, res, next, send) {
    send(200, {
      version: constants.USER_VERSION,
      agent: constants.USER_AGENT,
      services: self.pool.services,
      network: self.network.type,
      height: self.chain.height,
      tip: self.chain.tip.rhash,
      peers: self.pool.peers.all.length,
      progress: self.chain.getProgress()
    });
  });

  // UTXO by address
  this.get('/coin/address/:address', function(req, res, next, send) {
    self.node.getCoinsByAddress(req.options.address, function(err, coins) {
      if (err)
        return next(err);

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
    self.node.getCoinsByAddress(req.options.address, function(err, coins) {
      if (err)
        return next(err);

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
    self.node.getTXByAddress(req.options.address, function(err, txs) {
      if (err)
        return next(err);

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
    self.node.getTXByAddress(req.options.address, function(err, txs) {
      if (err)
        return next(err);

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
    self.mempool.getHistory(function(err, txs) {
      if (err)
        return next(err);

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

  // Estimate fee
  this.get('/fee', function(req, res, next, send) {
    var fee = self.fees.estimateFee(req.options.blocks);
    send(200, { rate: utils.btc(fee) });
  });

  // Get wallet
  this.get('/wallet/:id', function(req, res, next, send) {
    send(200, req.wallet.toJSON());
  });

  // Create wallet
  this.post('/wallet/:id?', function(req, res, next, send) {
    self.walletdb.create(req.options, function(err, wallet) {
      if (err)
        return next(err);

      send(200, wallet.toJSON());
    });
  });

  // List accounts
  this.get('/wallet/:id/account', function(req, res, next, send) {
    req.wallet.getAccounts(function(err, accounts) {
      if (err)
        return next(err);

      send(200, accounts);
    });
  });

  // Get account
  this.get('/wallet/:id/account/:account', function(req, res, next, send) {
    req.wallet.getAccount(req.options.account, function(err, account) {
      if (err)
        return next(err);

      if (!account)
        return send(404);

      send(200, account.toJSON());
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

  // Abandon Wallet TX
  this.del('/wallet/:id/tx/:hash', function(req, res, next, send) {
    var hash = req.options.hash;
    req.wallet.abandon(hash, function(err) {
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
    req.wallet.createReceive(account, function(err, address) {
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
    req.wallet.getRange(account, options, function(err, txs) {
      if (err)
        return next(err);

      req.wallet.toDetails(txs, function(err, txs) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Last Wallet TXs
  this.get('/wallet/:id/tx/last', function(req, res, next, send) {
    var account = req.options.account;
    var limit = req.options.limit;
    req.wallet.getLast(account, limit, function(err, txs) {
      if (err)
        return next(err);

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

      if (socket.auth)
        return callback({ error: 'Already authed.' });

      socket.stop();

      if (self.apiHash) {
        if (!utils.ccmp(hash256(apiKey), self.apiHash))
          return callback({ error: 'Bad key.' });
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

      self.walletdb.auth(id, token, function(err, wallet) {
        if (err) {
          self.logger.info('Wallet auth failure for %s: %s.', id, err.message);
          return callback({ error: 'Bad token.' });
        }

        if (!wallet)
          return callback({ error: 'Wallet does not exist.' });

        self.logger.info('Successful wallet auth for %s.', id);

        socket.join(id);

        callback();
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

      if (!utils.isHex256(start) && !utils.isNumber(start))
        return callback({ error: 'Invalid parameter.' });

      socket.scan(start, function(err) {
        if (err)
          return callback({ error: err.message });
        callback();
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
 * @param {Function} callback
 */

HTTPServer.prototype.open = function open(callback) {
  var self = this;
  this.server.open(function(err) {
    if (err)
      return callback(err);

    self.logger.info('HTTP server loaded.');

    if (self.apiKey) {
      self.logger.info('HTTP API key: %s', self.apiKey);
      self.apiKey = null;
    } else if (!self.apiHash) {
      self.logger.warning('WARNING: Your http server is open to the world.');
    }

    callback();
  });
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
  this.server.listen(port, host, callback);
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

  this.chain = this.server.chain;
  this.mempool = this.server.mempool;
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
    hash = bcoin.address.getHash(addresses[i], 'hex');

    if (!hash)
      throw new Error('Bad address.');

    if (!this.filter[hash]) {
      this.filter[hash] = true;
      this.filterCount++;
    }
  }
};

ClientSocket.prototype.removeFilter = function removeFilter(addresses) {
  var i, hash;

  for (i = 0; i < addresses.length; i++) {
    hash = bcoin.address.getHash(addresses[i], 'hex');

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

  this.bind(this.mempool, 'tx', function(tx) {
    if (self.testFilter(tx))
      self.emit('mempool tx', tx.toJSON());
  });
};

ClientSocket.prototype.unwatchChain = function unwatchChain() {
  this.unbind(this.chain, 'connect');
  this.unbind(this.chain, 'disconnect');
  this.unbind(this.mempool, 'tx');
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

ClientSocket.prototype.scan = function scan(start, callback) {
  var self = this;
  var i;

  if (typeof start === 'string')
    start = utils.revHex(start);

  this.chain.db.scan(start, this.filter, function(entry, txs, next) {
    for (i = 0; i < txs.length; i++)
      txs[i] = txs[i].toJSON();

    self.emit('block tx', entry.toJSON(), txs);

    next();
  }, callback);
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
  return utils.hash256(new Buffer(data, 'utf8'));
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

/*
 * Expose
 */

module.exports = HTTPServer;
