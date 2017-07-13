/*!
 * server.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const path = require('path');
const HTTPBase = require('../http/base');
const util = require('../utils/util');
const base58 = require('../utils/base58');
const MTX = require('../primitives/mtx');
const Outpoint = require('../primitives/outpoint');
const Script = require('../script/script');
const digest = require('../crypto/digest');
const random = require('../crypto/random');
const ccmp = require('../crypto/ccmp');
const Network = require('../protocol/network');
const Validator = require('../utils/validator');
const common = require('./common');

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
  this.on('request', (req, res) => {
    if (req.method === 'POST' && req.pathname === '/')
      return;

    this.logger.debug('Request for method=%s path=%s (%s).',
      req.method, req.pathname, req.socket.remoteAddress);
  });

  this.on('listening', (address) => {
    this.logger.info('HTTP server listening on %s (port=%d).',
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

  this.hook(async (req, res) => {
    let valid = req.valid();
    let id, token, wallet;

    if (req.path.length === 0)
      return;

    if (req.path[0] === '_admin')
      return;

    if (req.method === 'PUT' && req.path.length === 1)
      return;

    id = valid.str('id');
    token = valid.buf('token');

    if (!this.options.walletAuth) {
      wallet = await this.walletdb.get(id);

      if (!wallet) {
        res.send(404);
        return;
      }

      req.wallet = wallet;

      return;
    }

    try {
      wallet = await this.walletdb.auth(id, token);
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
  });

  // Rescan
  this.post('/_admin/rescan', async (req, res) => {
    let valid = req.valid();
    let height = valid.u32('height');

    res.send(200, { success: true });

    await this.walletdb.rescan(height);
  });

  // Resend
  this.post('/_admin/resend', async (req, res) => {
    await this.walletdb.resend();
    res.send(200, { success: true });
  });

  // Backup WalletDB
  this.post('/_admin/backup', async (req, res) => {
    let valid = req.valid();
    let path = valid.str('path');

    enforce(path, 'Path is required.');

    await this.walletdb.backup(path);

    res.send(200, { success: true });
  });

  // List wallets
  this.get('/_admin/wallets', async (req, res) => {
    let wallets = await this.walletdb.getWallets();
    res.send(200, wallets);
  });

  // Get wallet
  this.get('/:id', (req, res) => {
    res.send(200, req.wallet.toJSON());
  });

  // Get wallet master key
  this.get('/:id/master', (req, res) => {
    res.send(200, req.wallet.master.toJSON(true));
  });

  // Create wallet (compat)
  this.post('/', async (req, res) => {
    let valid = req.valid();
    let wallet;

    wallet = await this.walletdb.create({
      id: valid.str('id'),
      type: valid.str('type'),
      m: valid.u32('m'),
      n: valid.u32('n'),
      passphrase: valid.str('passphrase'),
      master: valid.str('master'),
      mnemonic: valid.str('mnemonic'),
      witness: valid.bool('witness'),
      accountKey: valid.str('accountKey'),
      watchOnly: valid.bool('watchOnly')
    });

    res.send(200, wallet.toJSON());
  });

  // Create wallet
  this.put('/:id', async (req, res) => {
    let valid = req.valid();
    let wallet;

    wallet = await this.walletdb.create({
      id: valid.str('id'),
      type: valid.str('type'),
      m: valid.u32('m'),
      n: valid.u32('n'),
      passphrase: valid.str('passphrase'),
      master: valid.str('master'),
      mnemonic: valid.str('mnemonic'),
      witness: valid.bool('witness'),
      accountKey: valid.str('accountKey'),
      watchOnly: valid.bool('watchOnly')
    });

    res.send(200, wallet.toJSON());
  });

  // List accounts
  this.get('/:id/account', async (req, res) => {
    let accounts = await req.wallet.getAccounts();
    res.send(200, accounts);
  });

  // Get account
  this.get('/:id/account/:account', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let account = await req.wallet.getAccount(acct);

    if (!account) {
      res.send(404);
      return;
    }

    res.send(200, account.toJSON());
  });

  // Create account (compat)
  this.post('/:id/account', async (req, res) => {
    let valid = req.valid();
    let passphrase = valid.str('passphrase');
    let options, account;

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

    account = await req.wallet.createAccount(options, passphrase);

    if (!account) {
      res.send(404);
      return;
    }

    res.send(200, account.toJSON());
  });

  // Create account
  this.put('/:id/account/:account', async (req, res) => {
    let valid = req.valid();
    let passphrase = valid.str('passphrase');
    let options, account;

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

    account = await req.wallet.createAccount(options, passphrase);

    if (!account) {
      res.send(404);
      return;
    }

    res.send(200, account.toJSON());
  });

  // Change passphrase
  this.post('/:id/passphrase', async (req, res) => {
    let valid = req.valid();
    let old = valid.str('old');
    let new_ = valid.str('new');
    enforce(old || new_, 'Passphrase is required.');
    await req.wallet.setPassphrase(old, new_);
    res.send(200, { success: true });
  });

  // Unlock wallet
  this.post('/:id/unlock', async (req, res) => {
    let valid = req.valid();
    let passphrase = valid.str('passphrase');
    let timeout = valid.u32('timeout');
    enforce(passphrase, 'Passphrase is required.');
    await req.wallet.unlock(passphrase, timeout);
    res.send(200, { success: true });
  });

  // Lock wallet
  this.post('/:id/lock', async (req, res) => {
    await req.wallet.lock();
    res.send(200, { success: true });
  });

  // Import key
  this.post('/:id/import', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let pub = valid.str('publicKey');
    let priv = valid.str('privateKey');
    let address = valid.str('address');

    if (pub) {
      await req.wallet.importKey(acct, pub);
      res.send(200, { success: true });
      return;
    }

    if (priv) {
      await req.wallet.importKey(acct, priv);
      res.send(200, { success: true });
      return;
    }

    if (address) {
      await req.wallet.importAddress(acct, address);
      res.send(200, { success: true });
      return;
    }

    enforce(false, 'Key or address is required.');
  });

  // Generate new token
  this.post('/:id/retoken', async (req, res) => {
    let valid = req.valid();
    let passphrase = valid.str('passphrase');
    let token = await req.wallet.retoken(passphrase);
    res.send(200, { token: token.toString('hex') });
  });

  // Send TX
  this.post('/:id/send', async (req, res) => {
    let valid = req.valid();
    let passphrase = valid.str('passphrase');
    let outputs = valid.array('outputs');
    let options, tx, details;

    options = {
      rate: valid.u64('rate'),
      blocks: valid.u32('blocks'),
      maxFee: valid.u64('maxFee'),
      selection: valid.str('selection'),
      smart: valid.bool('smart'),
      subtractFee: valid.bool('subtractFee'),
      depth: valid.u32(['confirmations', 'depth']),
      outputs: []
    };

    for (let output of outputs) {
      let valid = new Validator([output]);
      let script = null;

      if (valid.has('script')) {
        script = valid.buf('script');
        script = Script.fromRaw(script);
      }

      options.outputs.push({
        script: script,
        address: valid.str('address'),
        value: valid.u64('value')
      });
    }

    tx = await req.wallet.send(options, passphrase);

    details = await req.wallet.getDetails(tx.hash('hex'));

    res.send(200, details.toJSON());
  });

  // Create TX
  this.post('/:id/create', async (req, res) => {
    let valid = req.valid();
    let passphrase = valid.str('passphrase');
    let outputs = valid.array('outputs');
    let options, tx;

    options = {
      rate: valid.u64('rate'),
      maxFee: valid.u64('maxFee'),
      selection: valid.str('selection'),
      smart: valid.bool('smart'),
      subtractFee: valid.bool('subtractFee'),
      depth: valid.u32(['confirmations', 'depth']),
      outputs: []
    };

    for (let output of outputs) {
      let valid = new Validator([output]);
      let script = null;

      if (valid.has('script')) {
        script = valid.buf('script');
        script = Script.fromRaw(script);
      }

      options.outputs.push({
        script: script,
        address: valid.str('address'),
        value: valid.u64('value')
      });
    }

    tx = await req.wallet.createTX(options);
    await req.wallet.sign(tx, passphrase);
    res.send(200, tx.getJSON(this.network));
  });

  // Sign TX
  this.post('/:id/sign', async (req, res) => {
    let valid = req.valid();
    let passphrase = valid.str('passphrase');
    let raw = valid.buf('tx');
    let tx;

    enforce(raw, 'TX is required.');

    tx = MTX.fromRaw(raw);

    await req.wallet.sign(tx, passphrase);

    res.send(200, tx.getJSON(this.network));
  });

  // Zap Wallet TXs
  this.post('/:id/zap', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let age = valid.u32('age');
    enforce(age, 'Age is required.');
    await req.wallet.zap(acct, age);
    res.send(200, { success: true });
  });

  // Abandon Wallet TX
  this.del('/:id/tx/:hash', async (req, res) => {
    let valid = req.valid();
    let hash = valid.hash('hash');
    enforce(hash, 'Hash is required.');
    await req.wallet.abandon(hash);
    res.send(200, { success: true });
  });

  // List blocks
  this.get('/:id/block', async (req, res) => {
    let heights = await req.wallet.getBlocks();
    res.send(200, heights);
  });

  // Get Block Record
  this.get('/:id/block/:height', async (req, res) => {
    let valid = req.valid();
    let height = valid.u32('height');
    let block;

    enforce(height != null, 'Height is required.');

    block = await req.wallet.getBlock(height);

    if (!block) {
      res.send(404);
      return;
    }

    res.send(200, block.toJSON());
  });

  // Add key
  this.put('/:id/shared-key', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let key = valid.str('accountKey');
    enforce(key, 'Key is required.');
    await req.wallet.addSharedKey(acct, key);
    res.send(200, { success: true });
  });

  // Remove key
  this.del('/:id/shared-key', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let key = valid.str('accountKey');
    enforce(key, 'Key is required.');
    await req.wallet.removeSharedKey(acct, key);
    res.send(200, { success: true });
  });

  // Get key by address
  this.get('/:id/key/:address', async (req, res) => {
    let valid = req.valid();
    let address = valid.str('address');
    let key;

    enforce(address, 'Address is required.');

    key = await req.wallet.getKey(address);

    if (!key) {
      res.send(404);
      return;
    }

    res.send(200, key.toJSON());
  });

  // Get private key
  this.get('/:id/wif/:address', async (req, res) => {
    let valid = req.valid();
    let address = valid.str('address');
    let passphrase = valid.str('passphrase');
    let key;

    enforce(address, 'Address is required.');

    key = await req.wallet.getPrivateKey(address, passphrase);

    if (!key) {
      res.send(404);
      return;
    }

    res.send(200, { privateKey: key.toSecret() });
  });

  // Create address
  this.post('/:id/address', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let address = await req.wallet.createReceive(acct);
    res.send(200, address.toJSON());
  });

  // Create change address
  this.post('/:id/change', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let address = await req.wallet.createChange(acct);
    res.send(200, address.toJSON());
  });

  // Create nested address
  this.post('/:id/nested', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let address = await req.wallet.createNested(acct);
    res.send(200, address.toJSON());
  });

  // Wallet Balance
  this.get('/:id/balance', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let balance = await req.wallet.getBalance(acct);

    if (!balance) {
      res.send(404);
      return;
    }

    res.send(200, balance.toJSON());
  });

  // Wallet UTXOs
  this.get('/:id/coin', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let coins = await req.wallet.getCoins(acct);
    let result = [];
    let coin;

    common.sortCoins(coins);

    for (coin of coins)
      result.push(coin.getJSON(this.network));

    res.send(200, result);
  });

  // Locked coins
  this.get('/:id/locked', async (req, res) => {
    let locked = this.wallet.getLocked();
    let result = [];
    let outpoint;

    for (outpoint of locked)
      result.push(outpoint.toJSON());

    res.send(200, result);
  });

  // Lock coin
  this.put('/:id/locked/:hash/:index', async (req, res) => {
    let valid = req.valid();
    let hash = valid.hash('hash');
    let index = valid.u32('index');
    let outpoint;

    enforce(hash, 'Hash is required.');
    enforce(index != null, 'Index is required.');

    outpoint = new Outpoint(hash, index);

    this.wallet.lockCoin(outpoint);
  });

  // Unlock coin
  this.del('/:id/locked/:hash/:index', async (req, res) => {
    let valid = req.valid();
    let hash = valid.hash('hash');
    let index = valid.u32('index');
    let outpoint;

    enforce(hash, 'Hash is required.');
    enforce(index != null, 'Index is required.');

    outpoint = new Outpoint(hash, index);

    this.wallet.unlockCoin(outpoint);
  });

  // Wallet Coin
  this.get('/:id/coin/:hash/:index', async (req, res) => {
    let valid = req.valid();
    let hash = valid.hash('hash');
    let index = valid.u32('index');
    let coin;

    enforce(hash, 'Hash is required.');
    enforce(index != null, 'Index is required.');

    coin = await req.wallet.getCoin(hash, index);

    if (!coin) {
      res.send(404);
      return;
    }

    res.send(200, coin.getJSON(this.network));
  });

  // Wallet TXs
  this.get('/:id/tx/history', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let txs = await req.wallet.getHistory(acct);
    let result = [];
    let details;

    common.sortTX(txs);

    details = await req.wallet.toDetails(txs);

    for (let item of details)
      result.push(item.toJSON());

    res.send(200, result);
  });

  // Wallet Pending TXs
  this.get('/:id/tx/unconfirmed', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let txs = await req.wallet.getPending(acct);
    let result = [];
    let details;

    common.sortTX(txs);

    details = await req.wallet.toDetails(txs);

    for (let item of details)
      result.push(item.toJSON());

    res.send(200, result);
  });

  // Wallet TXs within time range
  this.get('/:id/tx/range', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let result = [];
    let options, txs, details;

    options = {
      start: valid.u32('start'),
      end: valid.u32('end'),
      limit: valid.u32('limit'),
      reverse: valid.bool('reverse')
    };

    txs = await req.wallet.getRange(acct, options);

    details = await req.wallet.toDetails(txs);

    for (let item of details)
      result.push(item.toJSON());

    res.send(200, result);
  });

  // Last Wallet TXs
  this.get('/:id/tx/last', async (req, res) => {
    let valid = req.valid();
    let acct = valid.str('account');
    let limit = valid.u32('limit');
    let txs = await req.wallet.getLast(acct, limit);
    let details = await req.wallet.toDetails(txs);
    let result = [];

    for (let item of details)
      result.push(item.toJSON());

    res.send(200, result);
  });

  // Wallet TX
  this.get('/:id/tx/:hash', async (req, res) => {
    let valid = req.valid();
    let hash = valid.hash('hash');
    let tx, details;

    enforce(hash, 'Hash is required.');

    tx = await req.wallet.getTX(hash);

    if (!tx) {
      res.send(404);
      return;
    }

    details = await req.wallet.toDetails(tx);

    res.send(200, details.toJSON());
  });

  // Resend
  this.post('/:id/resend', async (req, res) => {
    await req.wallet.resend();
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

  this.walletdb.on('tx', (id, tx, details) => {
    let json = details.toJSON();
    let channel = 'w:' + id;
    this.to(channel, 'wallet tx', json);
    this.to('!all', 'wallet tx', id, json);
  });

  this.walletdb.on('confirmed', (id, tx, details) => {
    let json = details.toJSON();
    let channel = 'w:' + id;
    this.to(channel, 'wallet confirmed', json);
    this.to('!all', 'wallet confirmed', id, json);
  });

  this.walletdb.on('unconfirmed', (id, tx, details) => {
    let json = details.toJSON();
    let channel = 'w:' + id;
    this.to(channel, 'wallet unconfirmed', json);
    this.to('!all', 'wallet unconfirmed', id, json);
  });

  this.walletdb.on('conflict', (id, tx, details) => {
    let json = details.toJSON();
    let channel = 'w:' + id;
    this.to(channel, 'wallet conflict', json);
    this.to('!all', 'wallet conflict', id, json);
  });

  this.walletdb.on('balance', (id, balance) => {
    let json = balance.toJSON();
    let channel = 'w:' + id;
    this.to(channel, 'wallet balance', json);
    this.to('!all', 'wallet balance', id, json);
  });

  this.walletdb.on('address', (id, receive) => {
    let channel = 'w:' + id;
    let json = [];
    let addr;

    for (addr of receive)
      json.push(addr.toJSON());

    this.to(channel, 'wallet address', json);
    this.to('!all', 'wallet address', id, json);
  });
};

/**
 * Handle new websocket.
 * @private
 * @param {WebSocket} socket
 */

HTTPServer.prototype.handleSocket = function handleSocket(socket) {
  socket.hook('wallet auth', (args) => {
    let valid = new Validator([args]);
    let key = valid.str(0);
    let hash;

    if (socket.auth)
      throw new Error('Already authed.');

    if (!this.options.noAuth) {
      hash = hash256(key);
      if (!ccmp(hash, this.options.apiHash))
        throw new Error('Bad key.');
    }

    socket.auth = true;

    this.logger.info('Successful auth from %s.', socket.host);

    this.handleAuth(socket);

    return null;
  });
};

/**
 * Handle new auth'd websocket.
 * @private
 * @param {WebSocket} socket
 */

HTTPServer.prototype.handleAuth = function handleAuth(socket) {
  socket.hook('wallet join', async (args) => {
    let valid = new Validator([args]);
    let id = valid.str(0, '');
    let token = valid.buf(1);
    let channel = 'w:' + id;
    let wallet;

    if (!id)
      throw new Error('Invalid parameter.');

    if (!this.options.walletAuth) {
      socket.join(channel);
      return null;
    }

    if (!token)
      throw new Error('Invalid parameter.');

    try {
      wallet = await this.walletdb.auth(id, token);
    } catch (e) {
      this.logger.info('Wallet auth failure for %s: %s.', id, e.message);
      throw new Error('Bad token.');
    }

    if (!wallet)
      throw new Error('Wallet does not exist.');

    this.logger.info('Successful wallet auth for %s.', id);

    socket.join(channel);

    return null;
  });

  socket.hook('wallet leave', (args) => {
    let valid = new Validator([args]);
    let id = valid.str(0, '');
    let channel = 'w:' + id;

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
  this.apiKey = base58.encode(random.randomBytes(20));
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
