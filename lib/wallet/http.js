/*!
 * server.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const path = require('path');
const {Server} = require('bweb');
const Validator = require('bval');
const {base58} = require('bstring');
const MTX = require('../primitives/mtx');
const Outpoint = require('../primitives/outpoint');
const Script = require('../script/script');
const sha256 = require('bcrypto/lib/sha256');
const random = require('bcrypto/lib/random');
const ccmp = require('bcrypto/lib/ccmp');
const Network = require('../protocol/network');
const Address = require('../primitives/address');
const KeyRing = require('../primitives/keyring');
const Mnemonic = require('../hd/mnemonic');
const HDPrivateKey = require('../hd/private');
const HDPublicKey = require('../hd/public');
const common = require('./common');

/**
 * HTTP
 * @alias module:wallet.HTTP
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
    this.logger = this.options.logger.context('http');
    this.wdb = this.options.node.wdb;
    this.rpc = this.options.node.rpc;

    this.init();
  }

  /**
   * Initialize http server.
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
      this.logger.info('Wallet HTTP server listening on %s (port=%d).',
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
        realm: 'wallet'
      }));
    }

    this.use(this.bodyParser({
      type: 'json'
    }));

    this.use(async (req, res) => {
      if (!this.options.walletAuth) {
        req.admin = true;
        return;
      }

      const valid = Validator.fromRequest(req);
      const token = valid.buf('token');

      if (token && ccmp(token, this.options.adminToken)) {
        req.admin = true;
        return;
      }

      if (req.method === 'POST' && req.path.length === 0) {
        res.json(403);
        return;
      }
    });

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

    this.hook(async (req, res) => {
      if (req.path.length < 2)
        return;

      if (req.path[0] !== 'wallet')
        return;

      if (req.method === 'PUT' && req.path.length === 2)
        return;

      const valid = Validator.fromRequest(req);
      const id = valid.str('id');
      const token = valid.buf('token');

      if (!id) {
        res.json(403);
        return;
      }

      if (req.admin || !this.options.walletAuth) {
        const wallet = await this.wdb.get(id);

        if (!wallet) {
          res.json(404);
          return;
        }

        req.wallet = wallet;

        return;
      }

      if (!token) {
        res.json(403);
        return;
      }

      let wallet;
      try {
        wallet = await this.wdb.auth(id, token);
      } catch (err) {
        this.logger.info('Auth failure for %s: %s.', id, err.message);
        res.json(403);
        return;
      }

      if (!wallet) {
        res.json(404);
        return;
      }

      req.wallet = wallet;

      this.logger.info('Successful auth for %s.', id);
    });

    // Rescan
    this.post('/rescan', async (req, res) => {
      if (!req.admin) {
        res.json(403);
        return;
      }

      const valid = Validator.fromRequest(req);
      const height = valid.u32('height');

      res.json(200, { success: true });

      await this.wdb.rescan(height);
    });

    // Resend
    this.post('/resend', async (req, res) => {
      if (!req.admin) {
        res.json(403);
        return;
      }

      await this.wdb.resend();

      res.json(200, { success: true });
    });

    // Backup WalletDB
    this.post('/backup', async (req, res) => {
      if (!req.admin) {
        res.json(403);
        return;
      }

      const valid = Validator.fromRequest(req);
      const path = valid.str('path');

      enforce(path, 'Path is required.');

      await this.wdb.backup(path);

      res.json(200, { success: true });
    });

    // List wallets
    this.get('/wallet', async (req, res) => {
      if (!req.admin) {
        res.json(403);
        return;
      }

      const wallets = await this.wdb.getWallets();
      res.json(200, wallets);
    });

    // Get wallet
    this.get('/wallet/:id', async (req, res) => {
      const balance = await req.wallet.getBalance();
      res.json(200, req.wallet.toJSON(false, balance));
    });

    // Get wallet master key
    this.get('/wallet/:id/master', (req, res) => {
      if (!req.admin) {
        res.json(403);
        return;
      }

      res.json(200, req.wallet.master.toJSON(this.network, true));
    });

    // Create wallet
    this.put('/wallet/:id', async (req, res) => {
      const valid = Validator.fromRequest(req);

      let master = valid.str('master');
      let mnemonic = valid.str('mnemonic');
      let accountKey = valid.str('accountKey');

      if (master)
        master = HDPrivateKey.fromBase58(master, this.network);

      if (mnemonic)
        mnemonic = Mnemonic.fromPhrase(mnemonic);

      if (accountKey)
        accountKey = HDPublicKey.fromBase58(accountKey, this.network);

      const wallet = await this.wdb.create({
        id: valid.str('id'),
        type: valid.str('type'),
        m: valid.u32('m'),
        n: valid.u32('n'),
        passphrase: valid.str('passphrase'),
        master: master,
        mnemonic: mnemonic,
        witness: valid.bool('witness'),
        accountKey: accountKey,
        watchOnly: valid.bool('watchOnly')
      });

      const balance = await wallet.getBalance();

      res.json(200, wallet.toJSON(false, balance));
    });

    // List accounts
    this.get('/wallet/:id/account', async (req, res) => {
      const accounts = await req.wallet.getAccounts();
      res.json(200, accounts);
    });

    // Get account
    this.get('/wallet/:id/account/:account', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');
      const account = await req.wallet.getAccount(acct);

      if (!account) {
        res.json(404);
        return;
      }

      const balance = await req.wallet.getBalance(account.accountIndex);

      res.json(200, account.toJSON(balance));
    });

    // Create account
    this.put('/wallet/:id/account/:account', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const passphrase = valid.str('passphrase');

      let accountKey = valid.get('accountKey');

      if (accountKey)
        accountKey = HDPublicKey.fromBase58(accountKey, this.network);

      const options = {
        name: valid.str('account'),
        witness: valid.bool('witness'),
        watchOnly: valid.bool('watchOnly'),
        type: valid.str('type'),
        m: valid.u32('m'),
        n: valid.u32('n'),
        accountKey: accountKey,
        lookahead: valid.u32('lookahead')
      };

      const account = await req.wallet.createAccount(options, passphrase);
      const balance = await req.wallet.getBalance(account.accountIndex);

      res.json(200, account.toJSON(balance));
    });

    // Change passphrase
    this.post('/wallet/:id/passphrase', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const passphrase = valid.str('passphrase');
      const old = valid.str('old');

      enforce(passphrase, 'Passphrase is required.');

      await req.wallet.setPassphrase(passphrase, old);

      res.json(200, { success: true });
    });

    // Unlock wallet
    this.post('/wallet/:id/unlock', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const passphrase = valid.str('passphrase');
      const timeout = valid.u32('timeout');

      enforce(passphrase, 'Passphrase is required.');

      await req.wallet.unlock(passphrase, timeout);

      res.json(200, { success: true });
    });

    // Lock wallet
    this.post('/wallet/:id/lock', async (req, res) => {
      await req.wallet.lock();
      res.json(200, { success: true });
    });

    // Import key
    this.post('/wallet/:id/import', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');
      const passphrase = valid.str('passphrase');
      const pub = valid.buf('publicKey');
      const priv = valid.str('privateKey');
      const b58 = valid.str('address');

      if (pub) {
        const key = KeyRing.fromPublic(pub);
        await req.wallet.importKey(acct, key);
        res.json(200, { success: true });
        return;
      }

      if (priv) {
        const key = KeyRing.fromSecret(priv, this.network);
        await req.wallet.importKey(acct, key, passphrase);
        res.json(200, { success: true });
        return;
      }

      if (b58) {
        const addr = Address.fromString(b58, this.network);
        await req.wallet.importAddress(acct, addr);
        res.json(200, { success: true });
        return;
      }

      enforce(false, 'Key or address is required.');
    });

    // Generate new token
    this.post('/wallet/:id/retoken', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const passphrase = valid.str('passphrase');
      const token = await req.wallet.retoken(passphrase);

      res.json(200, {
        token: token.toString('hex')
      });
    });

    // Send TX
    this.post('/wallet/:id/send', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const passphrase = valid.str('passphrase');
      const outputs = valid.array('outputs', []);

      const options = {
        rate: valid.u64('rate'),
        blocks: valid.u32('blocks'),
        maxFee: valid.u64('maxFee'),
        selection: valid.str('selection'),
        smart: valid.bool('smart'),
        subtractFee: valid.bool('subtractFee'),
        subtractIndex: valid.i32('subtractIndex'),
        depth: valid.u32(['confirmations', 'depth']),
        outputs: []
      };

      for (const output of outputs) {
        const valid = new Validator(output);

        let addr = valid.str('address');
        let script = valid.buf('script');

        if (addr)
          addr = Address.fromString(addr, this.network);

        if (script)
          script = Script.fromRaw(script);

        options.outputs.push({
          address: addr,
          script: script,
          value: valid.u64('value')
        });
      }

      const tx = await req.wallet.send(options, passphrase);

      const details = await req.wallet.getDetails(tx.hash('hex'));

      res.json(200, details.toJSON(this.network, this.wdb.height));
    });

    // Create TX
    this.post('/wallet/:id/create', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const passphrase = valid.str('passphrase');
      const outputs = valid.array('outputs', []);

      const options = {
        rate: valid.u64('rate'),
        maxFee: valid.u64('maxFee'),
        selection: valid.str('selection'),
        smart: valid.bool('smart'),
        subtractFee: valid.bool('subtractFee'),
        subtractIndex: valid.i32('subtractIndex'),
        depth: valid.u32(['confirmations', 'depth']),
        outputs: []
      };

      for (const output of outputs) {
        const valid = new Validator(output);

        let addr = valid.str('address');
        let script = valid.buf('script');

        if (addr)
          addr = Address.fromString(addr, this.network);

        if (script)
          script = Script.fromRaw(script);

        options.outputs.push({
          address: addr,
          script: script,
          value: valid.u64('value')
        });
      }

      const tx = await req.wallet.createTX(options);

      await req.wallet.sign(tx, passphrase);

      res.json(200, tx.getJSON(this.network));
    });

    // Sign TX
    this.post('/wallet/:id/sign', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const passphrase = valid.str('passphrase');
      const raw = valid.buf('tx');

      enforce(raw, 'TX is required.');

      const tx = MTX.fromRaw(raw);
      tx.view = await req.wallet.getCoinView(tx);

      await req.wallet.sign(tx, passphrase);

      res.json(200, tx.getJSON(this.network));
    });

    // Zap Wallet TXs
    this.post('/wallet/:id/zap', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');
      const age = valid.u32('age');

      enforce(age, 'Age is required.');

      await req.wallet.zap(acct, age);

      res.json(200, { success: true });
    });

    // Abandon Wallet TX
    this.del('/wallet/:id/tx/:hash', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const hash = valid.rhash('hash');

      enforce(hash, 'Hash is required.');

      await req.wallet.abandon(hash);

      res.json(200, { success: true });
    });

    // List blocks
    this.get('/wallet/:id/block', async (req, res) => {
      const heights = await req.wallet.getBlocks();
      res.json(200, heights);
    });

    // Get Block Record
    this.get('/wallet/:id/block/:height', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const height = valid.u32('height');

      enforce(height != null, 'Height is required.');

      const block = await req.wallet.getBlock(height);

      if (!block) {
        res.json(404);
        return;
      }

      res.json(200, block.toJSON());
    });

    // Add key
    this.put('/wallet/:id/shared-key', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');
      const b58 = valid.str('accountKey');

      enforce(b58, 'Key is required.');

      const key = HDPublicKey.fromBase58(b58, this.network);

      const added = await req.wallet.addSharedKey(acct, key);

      res.json(200, {
        success: true,
        addedKey: added
      });
    });

    // Remove key
    this.del('/wallet/:id/shared-key', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');
      const b58 = valid.str('accountKey');

      enforce(b58, 'Key is required.');

      const key = HDPublicKey.fromBase58(b58, this.network);

      const removed = await req.wallet.removeSharedKey(acct, key);

      res.json(200, {
        success: true,
        removedKey: removed
      });
    });

    // Get key by address
    this.get('/wallet/:id/key/:address', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const b58 = valid.str('address');

      enforce(b58, 'Address is required.');

      const addr = Address.fromString(b58, this.network);
      const key = await req.wallet.getKey(addr);

      if (!key) {
        res.json(404);
        return;
      }

      res.json(200, key.toJSON(this.network));
    });

    // Get private key
    this.get('/wallet/:id/wif/:address', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const b58 = valid.str('address');
      const passphrase = valid.str('passphrase');

      enforce(b58, 'Address is required.');

      const addr = Address.fromString(b58, this.network);
      const key = await req.wallet.getPrivateKey(addr, passphrase);

      if (!key) {
        res.json(404);
        return;
      }

      res.json(200, { privateKey: key.toSecret(this.network) });
    });

    // Create address
    this.post('/wallet/:id/address', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');
      const addr = await req.wallet.createReceive(acct);

      res.json(200, addr.toJSON(this.network));
    });

    // Create change address
    this.post('/wallet/:id/change', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');
      const addr = await req.wallet.createChange(acct);

      res.json(200, addr.toJSON(this.network));
    });

    // Create nested address
    this.post('/wallet/:id/nested', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');
      const addr = await req.wallet.createNested(acct);

      res.json(200, addr.toJSON(this.network));
    });

    // Wallet Balance
    this.get('/wallet/:id/balance', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');
      const balance = await req.wallet.getBalance(acct);

      if (!balance) {
        res.json(404);
        return;
      }

      res.json(200, balance.toJSON());
    });

    // Wallet UTXOs
    this.get('/wallet/:id/coin', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');
      const coins = await req.wallet.getCoins(acct);
      const result = [];

      common.sortCoins(coins);

      for (const coin of coins)
        result.push(coin.getJSON(this.network));

      res.json(200, result);
    });

    // Locked coins
    this.get('/wallet/:id/locked', async (req, res) => {
      const locked = req.wallet.getLocked();
      const result = [];

      for (const outpoint of locked)
        result.push(outpoint.toJSON());

      res.json(200, result);
    });

    // Lock coin
    this.put('/wallet/:id/locked/:hash/:index', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const hash = valid.rhash('hash');
      const index = valid.u32('index');

      enforce(hash, 'Hash is required.');
      enforce(index != null, 'Index is required.');

      const outpoint = new Outpoint(hash, index);

      req.wallet.lockCoin(outpoint);

      res.json(200, { success: true });
    });

    // Unlock coin
    this.del('/wallet/:id/locked/:hash/:index', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const hash = valid.rhash('hash');
      const index = valid.u32('index');

      enforce(hash, 'Hash is required.');
      enforce(index != null, 'Index is required.');

      const outpoint = new Outpoint(hash, index);

      req.wallet.unlockCoin(outpoint);

      res.json(200, { success: true });
    });

    // Wallet Coin
    this.get('/wallet/:id/coin/:hash/:index', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const hash = valid.rhash('hash');
      const index = valid.u32('index');

      enforce(hash, 'Hash is required.');
      enforce(index != null, 'Index is required.');

      const coin = await req.wallet.getCoin(hash, index);

      if (!coin) {
        res.json(404);
        return;
      }

      res.json(200, coin.getJSON(this.network));
    });

    // Wallet TXs
    this.get('/wallet/:id/tx/history', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');
      const txs = await req.wallet.getHistory(acct);

      common.sortTX(txs);

      const details = await req.wallet.toDetails(txs);

      const result = [];

      for (const item of details)
        result.push(item.toJSON(this.network, this.wdb.height));

      res.json(200, result);
    });

    // Wallet Pending TXs
    this.get('/wallet/:id/tx/unconfirmed', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');
      const txs = await req.wallet.getPending(acct);

      common.sortTX(txs);

      const details = await req.wallet.toDetails(txs);
      const result = [];

      for (const item of details)
        result.push(item.toJSON(this.network, this.wdb.height));

      res.json(200, result);
    });

    // Wallet TXs within time range
    this.get('/wallet/:id/tx/range', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');

      const options = {
        start: valid.u32('start'),
        end: valid.u32('end'),
        limit: valid.u32('limit'),
        reverse: valid.bool('reverse')
      };

      const txs = await req.wallet.getRange(acct, options);
      const details = await req.wallet.toDetails(txs);
      const result = [];

      for (const item of details)
        result.push(item.toJSON(this.network, this.wdb.height));

      res.json(200, result);
    });

    // Last Wallet TXs
    this.get('/wallet/:id/tx/last', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account');
      const limit = valid.u32('limit');
      const txs = await req.wallet.getLast(acct, limit);
      const details = await req.wallet.toDetails(txs);
      const result = [];

      for (const item of details)
        result.push(item.toJSON(this.network, this.wdb.height));

      res.json(200, result);
    });

    // Wallet TX
    this.get('/wallet/:id/tx/:hash', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const hash = valid.rhash('hash');

      enforce(hash, 'Hash is required.');

      const tx = await req.wallet.getTX(hash);

      if (!tx) {
        res.json(404);
        return;
      }

      const details = await req.wallet.toDetails(tx);

      res.json(200, details.toJSON(this.network, this.wdb.height));
    });

    // Resend
    this.post('/wallet/:id/resend', async (req, res) => {
      await req.wallet.resend();
      res.json(200, { success: true });
    });
  }

  /**
   * Initialize websockets.
   * @private
   */

  initSockets() {
    const handleTX = (event, wallet, tx, details) => {
      const name = `w:${wallet.id}`;

      if (!this.channel(name) && !this.channel('w:*'))
        return;

      const json = details.toJSON(this.network, this.wdb.height);

      if (this.channel(name))
        this.to(name, event, wallet.id, json);

      if (this.channel('w:*'))
        this.to('w:*', event, wallet.id, json);
    };

    this.wdb.on('tx', (wallet, tx, details) => {
      handleTX('tx', wallet, tx, details);
    });

    this.wdb.on('confirmed', (wallet, tx, details) => {
      handleTX('confirmed', wallet, tx, details);
    });

    this.wdb.on('unconfirmed', (wallet, tx, details) => {
      handleTX('unconfirmed', wallet, tx, details);
    });

    this.wdb.on('conflict', (wallet, tx, details) => {
      handleTX('conflict', wallet, tx, details);
    });

    this.wdb.on('balance', (wallet, balance) => {
      const name = `w:${wallet.id}`;

      if (!this.channel(name) && !this.channel('w:*'))
        return;

      const json = balance.toJSON();

      if (this.channel(name))
        this.to(name, 'balance', wallet.id, json);

      if (this.channel('w:*'))
        this.to('w:*', 'balance', wallet.id, json);
    });

    this.wdb.on('address', (wallet, receive) => {
      const name = `w:${wallet.id}`;

      if (!this.channel(name) && !this.channel('w:*'))
        return;

      const json = [];

      for (const addr of receive)
        json.push(addr.toJSON(this.network));

      if (this.channel(name))
        this.to(name, 'address', wallet.id, json);

      if (this.channel('w:*'))
        this.to('w:*', 'address', wallet.id, json);
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

        const data = Buffer.from(key, 'utf8');
        const hash = sha256.digest(data);

        if (!ccmp(hash, this.options.apiHash))
          throw new Error('Invalid API key.');
      }

      socket.join('auth');

      this.logger.info('Successful auth from %s.', socket.host);

      this.handleAuth(socket);

      return null;
    });
  }

  /**
   * Handle new auth'd websocket.
   * @private
   * @param {WebSocket} socket
   */

  handleAuth(socket) {
    socket.hook('join', async (...args) => {
      const valid = new Validator(args);
      const id = valid.str(0, '');
      const token = valid.buf(1);

      if (!id)
        throw new Error('Invalid parameter.');

      if (!this.options.walletAuth) {
        socket.join('admin');
      } else if (token) {
        if (ccmp(token, this.options.adminToken))
          socket.join('admin');
      }

      if (socket.channel('admin') || !this.options.walletAuth) {
        socket.join(`w:${id}`);
        return null;
      }

      if (id === '*')
        throw new Error('Bad token.');

      if (!token)
        throw new Error('Invalid parameter.');

      let wallet;
      try {
        wallet = await this.wdb.auth(id, token);
      } catch (e) {
        this.logger.info('Wallet auth failure for %s: %s.', id, e.message);
        throw new Error('Bad token.');
      }

      if (!wallet)
        throw new Error('Wallet does not exist.');

      this.logger.info('Successful wallet auth for %s.', id);

      socket.join(`w:${id}`);

      return null;
    });

    socket.hook('leave', (...args) => {
      const valid = new Validator(args);
      const id = valid.str(0, '');

      if (!id)
        throw new Error('Invalid parameter.');

      socket.leave(`w:${id}`);

      return null;
    });
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
    this.adminToken = random.randomBytes(32);
    this.serviceHash = this.apiHash;
    this.noAuth = false;
    this.cors = false;
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

  fromOptions(options) {
    assert(options);
    assert(options.node && typeof options.node === 'object',
      'HTTP Server requires a WalletDB.');

    this.node = options.node;
    this.network = options.node.network;
    this.logger = options.node.logger;
    this.port = this.network.walletPort;

    if (options.logger != null) {
      assert(typeof options.logger === 'object');
      this.logger = options.logger;
    }

    if (options.apiKey != null) {
      assert(typeof options.apiKey === 'string',
        'API key must be a string.');
      assert(options.apiKey.length <= 255,
        'API key must be under 255 bytes.');
      this.apiKey = options.apiKey;
      this.apiHash = sha256.digest(Buffer.from(this.apiKey, 'ascii'));
    }

    if (options.adminToken != null) {
      if (typeof options.adminToken === 'string') {
        assert(options.adminToken.length === 64,
          'Admin token must be a 32 byte hex string.');
        const token = Buffer.from(options.adminToken, 'hex');
        assert(token.length === 32,
          'Admin token must be a 32 byte hex string.');
        this.adminToken = token;
      } else {
        assert(Buffer.isBuffer(options.adminToken),
          'Admin token must be a hex string or buffer.');
        assert(options.adminToken.length === 32,
          'Admin token must be 32 bytes.');
        this.adminToken = options.adminToken;
      }
    }

    if (options.noAuth != null) {
      assert(typeof options.noAuth === 'boolean');
      this.noAuth = options.noAuth;
    }

    if (options.cors != null) {
      assert(typeof options.cors === 'boolean');
      this.cors = options.cors;
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
