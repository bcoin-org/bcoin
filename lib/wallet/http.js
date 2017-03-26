/*!
 * server.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var HTTPBase = require('../http/base');
var util = require('../utils/util');
var co = require('../utils/co');
var base58 = require('../utils/base58');
var TX = require('../primitives/tx');
var Outpoint = require('../primitives/outpoint');
var Script = require('../script/script');
var crypto = require('../crypto/crypto');
var Network = require('../protocol/network');
var Validator = require('../utils/validator');
var common = require('./common');

/**
 * HTTPServer
 * @alias module:wallet.HTTPServer
 * @constructor
 * @param {Object} options
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
  this.walletdb = this.options.walletdb;

  this.server = new HTTPBase(this.options);
  this.rpc = this.walletdb.rpc;

  this.init();
}

util.inherits(HTTPServer, HTTPBase);

/**
 * Attach to server.
 * @private
 * @param {HTTPServer} server
 */

HTTPServer.prototype.attach = function attach(server) {
  server.mount('/wallet', this);
};

/**
 * Initialize http server.
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
    self.logger.info('HTTP server listening on %s (port=%d).',
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
      realm: 'wallet'
    }));
  }

  this.use(this.bodyParser({
    contentType: 'json'
  }));

  this.use(this.jsonRPC(this.rpc));

  this.hook(co(function* (req, res) {
    var valid = req.valid();
    var id, token, wallet;

    if (req.path.length === 0)
      return;

    if (req.path[0] === '_admin')
      return;

    if (req.method === 'PUT' && req.path.length === 1)
      return;

    id = valid.str('id');
    token = valid.buf('token');

    if (!this.options.walletAuth) {
      wallet = yield this.walletdb.get(id);

      if (!wallet) {
        res.send(404);
        return;
      }

      req.wallet = wallet;

      return;
    }

    try {
      wallet = yield this.walletdb.auth(id, token);
    } catch (err) {
      this.logger.info('Auth failure for %s: %s.', id, err.message);
      res.error(403, err);
      return;
    }

    if (!wallet) {
      res.send(404);
      return;
    }

    req.wallet = wallet;

    this.logger.info('Successful auth for %s.', id);
  }));

  // Rescan
  this.post('/_admin/rescan', co(function* (req, res) {
    var valid = req.valid();
    var height = valid.u32('height');

    res.send(200, { success: true });

    yield this.walletdb.rescan(height);
  }));

  // Resend
  this.post('/_admin/resend', co(function* (req, res) {
    yield this.walletdb.resend();
    res.send(200, { success: true });
  }));

  // Backup WalletDB
  this.post('/_admin/backup', co(function* (req, res) {
    var valid = req.valid();
    var path = valid.str('path');

    enforce(path, 'Path is required.');

    yield this.walletdb.backup(path);

    res.send(200, { success: true });
  }));

  // List wallets
  this.get('/_admin/wallets', co(function* (req, res) {
    var wallets = yield this.walletdb.getWallets();
    res.send(200, wallets);
  }));

  // Get wallet
  this.get('/:id', function(req, res) {
    res.send(200, req.wallet.toJSON());
  });

  // Get wallet master key
  this.get('/:id/master', function(req, res) {
    if (!req.admin) {
      res.send(403, { error: 'Admin access required.' });
      return;
    }

    res.send(200, req.wallet.master.toJSON(true));
  });

  // Create wallet (compat)
  this.post('/', co(function* (req, res) {
    var valid = req.valid();
    var wallet;

    wallet = yield this.walletdb.create({
      id: valid.str('id'),
      type: valid.str('type'),
      m: valid.u32('m'),
      n: valid.u32('n'),
      passphrase: valid.str('passphrase'),
      master: valid.str('master'),
      mnemonic: valid.str('mnemonic'),
      accountKey: valid.str('accountKey'),
      watchOnly: valid.bool('watchOnly')
    });

    res.send(200, wallet.toJSON());
  }));

  // Create wallet
  this.put('/:id', co(function* (req, res) {
    var valid = req.valid();
    var wallet;

    wallet = yield this.walletdb.create({
      id: valid.str('id'),
      type: valid.str('type'),
      m: valid.u32('m'),
      n: valid.u32('n'),
      passphrase: valid.str('passphrase'),
      master: valid.str('master'),
      mnemonic: valid.str('mnemonic'),
      accountKey: valid.str('accountKey'),
      watchOnly: valid.bool('watchOnly')
    });

    res.send(200, wallet.toJSON());
  }));

  // List accounts
  this.get('/:id/account', co(function* (req, res) {
    var accounts = yield req.wallet.getAccounts();
    res.send(200, accounts);
  }));

  // Get account
  this.get('/:id/account/:account', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var account = yield req.wallet.getAccount(acct);

    if (!account) {
      res.send(404);
      return;
    }

    res.send(200, account.toJSON());
  }));

  // Create account (compat)
  this.post('/:id/account', co(function* (req, res) {
    var valid = req.valid();
    var passphrase = valid.str('passphrase');
    var options, account;

    options = {
      name: valid.str(['account', 'name']),
      witness: valid.bool('witness'),
      watchOnly: valid.bool('watchOnly'),
      type: valid.str('type'),
      m: valid.u32('m'),
      n: valid.u32('n'),
      accountKey: valid.str('accountKey'),
      lookahead: valid.u32('lookahead')
    };

    account = yield req.wallet.createAccount(options, passphrase);

    if (!account) {
      res.send(404);
      return;
    }

    res.send(200, account.toJSON());
  }));

  // Create account
  this.put('/:id/account/:account', co(function* (req, res) {
    var valid = req.valid();
    var passphrase = valid.str('passphrase');
    var options, account;

    options = {
      name: valid.str('account'),
      witness: valid.bool('witness'),
      watchOnly: valid.bool('watchOnly'),
      type: valid.str('type'),
      m: valid.u32('m'),
      n: valid.u32('n'),
      accountKey: valid.str('accountKey'),
      lookahead: valid.u32('lookahead')
    };

    account = yield req.wallet.createAccount(options, passphrase);

    if (!account) {
      res.send(404);
      return;
    }

    res.send(200, account.toJSON());
  }));

  // Change passphrase
  this.post('/:id/passphrase', co(function* (req, res) {
    var valid = req.valid();
    var old = valid.str('old');
    var new_ = valid.str('new');
    enforce(old || new_, 'Passphrase is required.');
    yield req.wallet.setPassphrase(old, new_);
    res.send(200, { success: true });
  }));

  // Unlock wallet
  this.post('/:id/unlock', co(function* (req, res) {
    var valid = req.valid();
    var passphrase = valid.str('passphrase');
    var timeout = valid.u32('timeout');
    enforce(passphrase, 'Passphrase is required.');
    yield req.wallet.unlock(passphrase, timeout);
    res.send(200, { success: true });
  }));

  // Lock wallet
  this.post('/:id/lock', co(function* (req, res) {
    yield req.wallet.lock();
    res.send(200, { success: true });
  }));

  // Import key
  this.post('/:id/import', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var pub = valid.str('publicKey');
    var priv = valid.str('privateKey');
    var address = valid.str('address');

    if (pub) {
      yield req.wallet.importKey(acct, pub);
      res.send(200, { success: true });
      return;
    }

    if (priv) {
      yield req.wallet.importKey(acct, priv);
      res.send(200, { success: true });
      return;
    }

    if (address) {
      yield req.wallet.importAddress(acct, address);
      res.send(200, { success: true });
      return;
    }

    enforce(false, 'Key or address is required.');
  }));

  // Generate new token
  this.post('/:id/retoken', co(function* (req, res) {
    var valid = req.valid();
    var passphrase = valid.str('passphrase');
    var token = yield req.wallet.retoken(passphrase);
    res.send(200, { token: token.toString('hex') });
  }));

  // Send TX
  this.post('/:id/send', co(function* (req, res) {
    var valid = req.valid();
    var passphrase = valid.str('passphrase');
    var outputs = valid.array('outputs');
    var i, options, tx, details, output, script;

    options = {
      rate: valid.amt('rate'),
      blocks: valid.u32('blocks'),
      maxFee: valid.amt('maxFee'),
      selection: valid.str('selection'),
      smart: valid.bool('smart'),
      subtractFee: valid.bool('subtractFee'),
      depth: valid.u32(['confirmations', 'depth']),
      outputs: []
    };

    for (i = 0; i < outputs.length; i++) {
      output = outputs[i];
      valid = new Validator(output);
      script = null;

      if (valid.has('script')) {
        script = valid.buf('script');
        script = Script.fromRaw(script);
      }

      options.outputs.push({
        script: script,
        address: valid.str('address'),
        value: valid.amt('value')
      });
    }

    tx = yield req.wallet.send(options, passphrase);

    details = yield req.wallet.getDetails(tx.hash('hex'));

    res.send(200, details.toJSON());
  }));

  // Create TX
  this.post('/:id/create', co(function* (req, res) {
    var valid = req.valid();
    var passphrase = valid.str('passphrase');
    var outputs = valid.array('outputs');
    var i, options, tx, output, script;

    options = {
      rate: valid.amt('rate'),
      maxFee: valid.amt('maxFee'),
      selection: valid.str('selection'),
      smart: valid.bool('smart'),
      subtractFee: valid.bool('subtractFee'),
      depth: valid.u32(['confirmations', 'depth']),
      outputs: []
    };

    for (i = 0; i < outputs.length; i++) {
      output = outputs[i];
      valid = new Validator(output);
      script = null;

      if (valid.has('script')) {
        script = valid.buf('script');
        script = Script.fromRaw(script);
      }

      options.outputs.push({
        script: script,
        address: valid.str('address'),
        value: valid.amt('value')
      });
    }

    tx = yield req.wallet.createTX(options);
    yield req.wallet.sign(tx, passphrase);
    res.send(200, tx.getJSON(this.network));
  }));

  // Sign TX
  this.post('/:id/sign', co(function* (req, res) {
    var valid = req.valid();
    var passphrase = valid.str('passphrase');
    var raw = valid.buf('tx');
    var tx;

    enforce(raw, 'TX is required.');

    tx = TX.fromRaw(raw);

    yield req.wallet.sign(tx, passphrase);

    res.send(200, tx.getJSON(this.network));
  }));

  // Zap Wallet TXs
  this.post('/:id/zap', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var age = valid.u32('age');
    enforce(age, 'Age is required.');
    yield req.wallet.zap(acct, age);
    res.send(200, { success: true });
  }));

  // Abandon Wallet TX
  this.del('/:id/tx/:hash', co(function* (req, res) {
    var valid = req.valid();
    var hash = valid.hash('hash');
    enforce(hash, 'Hash is required.');
    yield req.wallet.abandon(hash);
    res.send(200, { success: true });
  }));

  // List blocks
  this.get('/:id/block', co(function* (req, res) {
    var heights = yield req.wallet.getBlocks();
    res.send(200, heights);
  }));

  // Get Block Record
  this.get('/:id/block/:height', co(function* (req, res) {
    var valid = req.valid();
    var height = valid.u32('height');
    var block;

    enforce(height != null, 'Height is required.');

    block = yield req.wallet.getBlock(height);

    if (!block) {
      res.send(404);
      return;
    }

    res.send(200, block.toJSON());
  }));

  // Add key
  this.put('/:id/shared-key', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var key = valid.str('accountKey');
    enforce(key, 'Key is required.');
    yield req.wallet.addSharedKey(acct, key);
    res.send(200, { success: true });
  }));

  // Remove key
  this.del('/:id/shared-key', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var key = valid.str('accountKey');
    enforce(key, 'Key is required.');
    yield req.wallet.removeSharedKey(acct, key);
    res.send(200, { success: true });
  }));

  // Get key by address
  this.get('/:id/key/:address', co(function* (req, res) {
    var valid = req.valid();
    var address = valid.str('address');
    var key;

    enforce(address, 'Address is required.');

    key = yield req.wallet.getKey(address);

    if (!key) {
      res.send(404);
      return;
    }

    res.send(200, key.toJSON());
  }));

  // Get private key
  this.get('/:id/wif/:address', co(function* (req, res) {
    var valid = req.valid();
    var address = valid.str('address');
    var passphrase = valid.str('passphrase');
    var key;

    enforce(address, 'Address is required.');

    key = yield req.wallet.getPrivateKey(address, passphrase);

    if (!key) {
      res.send(404);
      return;
    }

    res.send(200, { privateKey: key.toSecret() });
  }));

  // Create address
  this.post('/:id/address', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var address = yield req.wallet.createReceive(acct);
    res.send(200, address.toJSON());
  }));

  // Create change address
  this.post('/:id/change', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var address = yield req.wallet.createChange(acct);
    res.send(200, address.toJSON());
  }));

  // Create nested address
  this.post('/:id/nested', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var address = yield req.wallet.createNested(acct);
    res.send(200, address.toJSON());
  }));

  // Wallet Balance
  this.get('/:id/balance', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var balance = yield req.wallet.getBalance(acct);

    if (!balance) {
      res.send(404);
      return;
    }

    res.send(200, balance.toJSON());
  }));

  // Wallet UTXOs
  this.get('/:id/coin', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var coins = yield req.wallet.getCoins(acct);
    var result = [];
    var i, coin;

    common.sortCoins(coins);

    for (i = 0; i < coins.length; i++) {
      coin = coins[i];
      result.push(coin.getJSON(this.network));
    }

    res.send(200, result);
  }));

  // Locked coins
  this.get('/:id/locked', co(function* (req, res) {
    var locked = this.wallet.getLocked();
    var result = [];
    var i, outpoint;

    for (i = 0; i < locked.length; i++) {
      outpoint = locked[i];
      result.push(outpoint.toJSON());
    }

    res.send(200, result);
  }));

  // Lock coin
  this.put('/:id/locked/:hash/:index', co(function* (req, res) {
    var valid = req.valid();
    var hash = valid.hash('hash');
    var index = valid.u32('index');
    var outpoint;

    enforce(hash, 'Hash is required.');
    enforce(index != null, 'Index is required.');

    outpoint = new Outpoint(hash, index);

    this.wallet.lockCoin(outpoint);
  }));

  // Unlock coin
  this.del('/:id/locked/:hash/:index', co(function* (req, res) {
    var valid = req.valid();
    var hash = valid.hash('hash');
    var index = valid.u32('index');
    var outpoint;

    enforce(hash, 'Hash is required.');
    enforce(index != null, 'Index is required.');

    outpoint = new Outpoint(hash, index);

    this.wallet.unlockCoin(outpoint);
  }));

  // Wallet Coin
  this.get('/:id/coin/:hash/:index', co(function* (req, res) {
    var valid = req.valid();
    var hash = valid.hash('hash');
    var index = valid.u32('index');
    var coin;

    enforce(hash, 'Hash is required.');
    enforce(index != null, 'Index is required.');

    coin = yield req.wallet.getCoin(hash, index);

    if (!coin) {
      res.send(404);
      return;
    }

    res.send(200, coin.getJSON(this.network));
  }));

  // Wallet TXs
  this.get('/:id/tx/history', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var txs = yield req.wallet.getHistory(acct);
    var result = [];
    var i, details, item;

    common.sortTX(txs);

    details = yield req.wallet.toDetails(txs);

    for (i = 0; i < details.length; i++) {
      item = details[i];
      result.push(item.toJSON());
    }

    res.send(200, result);
  }));

  // Wallet Pending TXs
  this.get('/:id/tx/unconfirmed', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var txs = yield req.wallet.getPending(acct);
    var result = [];
    var i, details, item;

    common.sortTX(txs);

    details = yield req.wallet.toDetails(txs);

    for (i = 0; i < details.length; i++) {
      item = details[i];
      result.push(item.toJSON());
    }

    res.send(200, result);
  }));

  // Wallet TXs within time range
  this.get('/:id/tx/range', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var result = [];
    var i, options, txs, details, item;

    options = {
      start: valid.u32('start'),
      end: valid.u32('end'),
      limit: valid.u32('limit'),
      reverse: valid.bool('reverse')
    };

    txs = yield req.wallet.getRange(acct, options);

    details = yield req.wallet.toDetails(txs);

    for (i = 0; i < details.length; i++) {
      item = details[i];
      result.push(item.toJSON());
    }

    res.send(200, result);
  }));

  // Last Wallet TXs
  this.get('/:id/tx/last', co(function* (req, res) {
    var valid = req.valid();
    var acct = valid.str('account');
    var limit = valid.u32('limit');
    var txs = yield req.wallet.getLast(acct, limit);
    var details = yield req.wallet.toDetails(txs);
    var result = [];
    var i, item;

    for (i = 0; i < details.length; i++) {
      item = details[i];
      result.push(item.toJSON());
    }

    res.send(200, result);
  }));

  // Wallet TX
  this.get('/:id/tx/:hash', co(function* (req, res) {
    var valid = req.valid();
    var hash = valid.hash('hash');
    var tx, details;

    enforce(hash, 'Hash is required.');

    tx = yield req.wallet.getTX(hash);

    if (!tx) {
      res.send(404);
      return;
    }

    details = yield req.wallet.toDetails(tx);

    res.send(200, details.toJSON());
  }));

  // Resend
  this.post('/:id/resend', co(function* (req, res) {
    yield req.wallet.resend();
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

  this.walletdb.on('tx', function(id, tx, details) {
    var json = details.toJSON();
    var channel = 'w:' + id;
    self.to(channel, 'wallet tx', json);
    self.to('!all', 'wallet tx', id, json);
  });

  this.walletdb.on('confirmed', function(id, tx, details) {
    var json = details.toJSON();
    var channel = 'w:' + id;
    self.to(channel, 'wallet confirmed', json);
    self.to('!all', 'wallet confirmed', id, json);
  });

  this.walletdb.on('unconfirmed', function(id, tx, details) {
    var json = details.toJSON();
    var channel = 'w:' + id;
    self.to(channel, 'wallet unconfirmed', json);
    self.to('!all', 'wallet unconfirmed', id, json);
  });

  this.walletdb.on('conflict', function(id, tx, details) {
    var json = details.toJSON();
    var channel = 'w:' + id;
    self.to(channel, 'wallet conflict', json);
    self.to('!all', 'wallet conflict', id, json);
  });

  this.walletdb.on('balance', function(id, balance) {
    var json = balance.toJSON();
    var channel = 'w:' + id;
    self.to(channel, 'wallet balance', json);
    self.to('!all', 'wallet balance', id, json);
  });

  this.walletdb.on('address', function(id, receive) {
    var channel = 'w:' + id;
    var json = [];
    var i, address;

    for (i = 0; i < receive.length; i++) {
      address = receive[i];
      json.push(address.toJSON());
    }

    self.to(channel, 'wallet address', json);
    self.to('!all', 'wallet address', id, json);
  });
};

/**
 * Handle new websocket.
 * @private
 * @param {WebSocket} socket
 */

HTTPServer.prototype.handleSocket = function handleSocket(socket) {
  var self = this;

  socket.hook('wallet auth', function(args) {
    var valid = new Validator([args]);
    var key = valid.str(0);
    var hash;

    if (socket.auth)
      throw new Error('Already authed.');

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
};

/**
 * Handle new auth'd websocket.
 * @private
 * @param {WebSocket} socket
 */

HTTPServer.prototype.handleAuth = function handleAuth(socket) {
  var self = this;

  socket.hook('wallet join', co(function* (args) {
    var valid = new Validator([args]);
    var id = valid.str(0, '');
    var token = valid.buf(1);
    var channel = 'w:' + id;
    var wallet;

    if (!id)
      throw new Error('Invalid parameter.');

    if (!self.options.walletAuth) {
      socket.join(channel);
      return null;
    }

    if (!token)
      throw new Error('Invalid parameter.');

    try {
      wallet = yield self.walletdb.auth(id, token);
    } catch (e) {
      self.logger.info('Wallet auth failure for %s: %s.', id, e.message);
      throw new Error('Bad token.');
    }

    if (!wallet)
      throw new Error('Wallet does not exist.');

    self.logger.info('Successful wallet auth for %s.', id);

    socket.join(channel);

    return null;
  }));

  socket.hook('wallet leave', function(args) {
    var valid = new Validator([args]);
    var id = valid.str(0, '');
    var channel = 'w:' + id;

    if (!id)
      throw new Error('Invalid parameter.');

    socket.leave(channel);

    return null;
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
  this.walletdb = null;
  this.apiKey = base58.encode(crypto.randomBytes(20));
  this.apiHash = hash256(this.apiKey);
  this.serviceHash = this.apiHash;
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
  assert(options.walletdb && typeof options.walletdb === 'object',
    'HTTP Server requires a WalletDB.');

  this.walletdb = options.walletdb;
  this.network = options.walletdb.network;
  this.logger = options.walletdb.logger;
  this.port = this.network.rpcPort + 2;

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
