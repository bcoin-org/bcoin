/*!
 * server.js - http server for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

const assert = require('bsert');
const fs = require('fs');
const Path = require('path');
const EventEmitter = require('events');
const bsock = require('bsock');
const Request = require('./request');
const Response = require('./response');
const Router = require('./router');
const Hook = require('./hook');
const RPC = require('./rpc');
const middleware = require('./middleware');

/**
 * HTTP Server
 * @extends EventEmitter
 */

class Server extends EventEmitter {
  /**
   * Create an http server.
   * @constructor
   * @param {Object?} options
   */

  constructor(options) {
    super();

    this.options = options || {};
    this.config = new ServerOptions(options);
    this.config.load();

    const http = this.config.getBackend();
    const opt = this.config.toHTTP();

    this.http = http.createServer(opt);
    this.io = bsock.server();
    this.rpc = new RPC();
    this.routes = new Router();
    this.mounts = [];
    this.stack = [];
    this.opened = false;
    this.mounted = false;
    this.parent = null;
    this.bound = false;
    this._reject = null;
  }

  /**
   * Bind to events.
   * @private
   */

  _bind() {
    if (this.bound)
      return;

    this.bound = true;

    this.http.on('close', () => {
      this.emit('close');
    });

    this.http.on('connection', (socket) => {
      socket.on('error', (err) => {
        if (err.message === 'Parse Error') {
          let msg = 'HttpParser execute failure';
          msg += ` (parsed=${err.bytesParsed || -1}`;
          msg += ` code=${err.code})`;
          err = new Error(msg);
        }

        this.emit('error', err);

        try {
          socket.destroy();
        } catch (e) {
          this.emit('error', e);
        }
      });
    });

    this.http.on('error', (err) => {
      const reject = this._reject;

      if (reject) {
        this._reject = null;
        reject(err);
        return;
      }

      this.emit('error', err);
    });

    this.http.on('listening', () => {
      this.emit('listening', this.address());
    });

    this.http.on('request', async (hreq, hres) => {
      let req = null;
      let res = null;

      try {
        hreq.on('error', e => this.emit('error', e));
        hreq.pause();
        req = new Request(hreq, hres, hreq.url);
        res = new Response(hreq, hres);
      } catch (e) {
        this.emit('error', e);
        try {
          hres.destroy();
        } catch (e) {
          this.emit('error', e);
        }
        return;
      }

      try {
        await this._handleRequest(req, res);
      } catch (e) {
        await this._handleError(e, req, res);
      }
    });

    if (this.config.sockets)
      this.io.attach(this.http);

    this.io.on('error', (err) => {
      this.emit('error', err);
    });

    this.io.on('socket', (socket) => {
      socket.on('error', (err) => {
        this.emit('error', err);
      });

      this.handleSocket(socket);
      this.emit('socket', socket);
    });

    this.rpc.on('error', (err) => {
      this.emit('error', err);
    });

    this.rpc.on('call', (cmd, query) => {
      this.handleCall(cmd, query);
      this.emit('call', cmd, query);
    });
  }

  /**
   * Handle an error.
   * @private
   * @param {Error} err
   * @param {Request} req
   * @param {Response} res
   * @returns {Promise}
   */

  async _handleError(err, req, res) {
    const code = err.statusCode || 500;

    if (code === 500)
      this.emit('error', err);

    if (res.sent)
      return;

    if (!this.onError) {
      res.send(code, `HTTP Error: ${code}.`);
      return;
    }

    try {
      await this.onError(err, req, res);
    } catch (e) {
      this.emit('error', e);
      res.send(500, 'Internal Server Error.');
    }
  }

  /**
   * Handle a request.
   * @private
   * @param {Request} req
   * @param {Response} res
   * @returns {Promise}
   */

  async _handleRequest(req, res) {
    if (await this._handleMounts(req, res))
      return undefined;

    this.emit('request', req, res);

    if (await this._handleStack(req, res))
      return undefined;

    const err = new Error('Not found.');
    err.statusCode = 404;

    return this._handleError(err, req, res);
  }

  /**
   * Handle mount stack.
   * @private
   * @param {Request} req
   * @param {Response} res
   * @returns {Promise}
   */

  async _handleMounts(req, res) {
    const url = req.url;

    for (const hook of this.mounts) {
      const server = hook.handler;

      if (!hook.isPrefix(req.pathname))
        continue;

      const uri = url.substring(hook.path.length);

      req.navigate(uri);

      try {
        await server._handleRequest(req, res);
      } catch (e) {
        try {
          await server._handleError(e, req, res);
        } finally {
          req.navigate(url);
        }
        return true;
      }

      req.navigate(url);

      return true;
    }

    return false;
  }

  /**
   * Handle middleware stack.
   * @private
   * @param {Request} req
   * @param {Response} res
   * @returns {Promise}
   */

  async _handleStack(req, res) {
    const url = req.url;

    let err = null;

    for (const hook of this.stack) {
      if (!hook.isPrefix(req.pathname))
        continue;

      if (hook.path !== '/') {
        const uri = url.substring(hook.path.length);
        req.navigate(uri);
      }

      if (err) {
        if (hook.arity !== 3)
          continue;

        try {
          await hook.handler(err, req, res);
          if (res.sent)
            return true;
        } finally {
          if (hook.path !== '/')
            req.navigate(url);
        }

        continue;
      }

      if (hook.arity !== 2)
        continue;

      try {
        await hook.handler(req, res);
        if (res.sent)
          return true;
      } catch (e) {
        err = e;
      } finally {
        if (hook.path !== '/')
          req.navigate(url);
      }
    }

    if (err)
      throw err;

    return false;
  }

  /**
   * Handle socket (abstract).
   * @param {Object} socket
   */

  handleSocket(socket) {}

  /**
   * Handle call (abstract).
   * @param {Object} cmd
   * @param {Object} query
   */

  handleCall(cmd, query) {}

  /**
   * Open the server.
   * @returns {Promise}
   */

  async open() {
    assert(!this.opened, 'Already opened.');

    this.opened = true;

    this._bind();

    if (this.mounted)
      return this.parent.address();

    const {port, host} = this.config;

    return new Promise((resolve, reject) => {
      this._reject = reject;

      const cb = () => {
        this._reject = null;
        resolve(this.address());
      };

      try {
        this.http.listen(port, host, cb);
      } catch (e) {
        this._reject = null;
        reject(e);
      }
    });
  }

  /**
   * Close the server.
   * @returns {Promise}
   */

  async close() {
    assert(this.opened, 'Not open.');

    this.opened = false;

    if (this.mounted)
      return undefined;

    return new Promise((resolve, reject) => {
      this._reject = reject;

      const cb = (err) => {
        this._reject = null;

        if (err) {
          reject(err);
          return;
        }

        resolve();
      };

      try {
        this.io.close();
        this.http.close(cb);
      } catch (e) {
        this._reject = null;
        reject(e);
      }
    });
  }

  /**
   * Setup error handler.
   * @param {Function} handler
   */

  error(handler) {
    assert(typeof handler === 'function');
    this.onError = handler;
  }

  /**
   * Mount a server.
   * @param {String} path
   * @param {Server} server
   */

  mount(path, server) {
    assert(typeof path === 'string');
    assert(server && typeof server === 'object');
    assert(!server.opened);
    assert(!server.mounted);

    if (server.config.sockets)
      this.io.mount(server.io);

    this.rpc.mount(server.rpc);

    server.parent = this;
    server.mounted = true;

    this.mounts.push(new Hook(path, server));
  }

  /**
   * Attach a server.
   * @param {String} path
   * @param {Server} server
   */

  attach(path, server) {
    this._bind();
    server.mount(path, this);
  }

  /**
   * Add a middleware to the stack.
   * @param {String?} path
   * @param {Function} handler
   */

  use(path, handler) {
    if (!handler) {
      handler = path;
      path = '/';
    }
    this.stack.push(new Hook(path, handler));
  }

  /**
   * Add a hook to the stack.
   * @param {String?} path
   * @param {Function} handler
   */

  hook(path, handler) {
    this.routes.hook(path, handler);
  }

  /**
   * Add a GET route.
   * @param {String} path
   * @param {Function} handler
   */

  get(path, handler) {
    this.routes.get(path, handler);
  }

  /**
   * Add a POST route.
   * @param {String} path
   * @param {Function} handler
   */

  post(path, handler) {
    this.routes.post(path, handler);
  }

  /**
   * Add a PUT route.
   * @param {String} path
   * @param {Function} handler
   */

  put(path, handler) {
    this.routes.put(path, handler);
  }

  /**
   * Add a DELETE route.
   * @param {String} path
   * @param {Function} handler
   */

  del(path, handler) {
    this.routes.del(path, handler);
  }

  /**
   * Add a PATCH route.
   * @param {String} path
   * @param {Function} handler
   */

  patch(path, handler) {
    this.routes.patch(path, handler);
  }

  /**
   * Get a channel.
   * @param {String} name
   * @returns {Set|null}
   */

  channel(name) {
    return this.io.channel(name);
  }

  /**
   * Join a channel.
   * @param {Object} socket
   * @param {String} name
   */

  join(socket, name) {
    return this.io.join(socket, name);
  }

  /**
   * Leave a channel.
   * @param {Object} socket
   * @param {String} name
   */

  leave(socket, name) {
    return this.io.leave(socket, name);
  }

  /**
   * Emit event to channel.
   */

  to(...args) {
    return this.io.to(...args);
  }

  /**
   * Emit event to all sockets.
   */

  all(...args) {
    return this.io.all(...args);
  }

  /**
   * Execute an RPC call.
   * @private
   * @param {Object} json
   * @param {Boolean} help
   * @returns {Promise}
   */

  execute(json, help) {
    return this.rpc.execute(json, help);
  }

  /**
   * Add an RPC call.
   * @param {String} name
   * @param {Function} func
   * @param {Object?} ctx
   */

  add(name, func, ctx) {
    return this.rpc.add(name, func, ctx);
  }

  /**
   * Get server address.
   * @returns {Object}
   */

  address() {
    return this.http.address();
  }

  /**
   * Router middleware.
   * @returns {Function}
   */

  router(routes) {
    if (!routes)
      routes = this.routes;

    return middleware.router(routes);
  }

  /**
   * CORS middleware.
   * @returns {Function}
   */

  cors() {
    return middleware.cors();
  }

  /**
   * Basic auth middleware.
   * @param {Object} options
   * @returns {Function}
   */

  basicAuth(options) {
    return middleware.basicAuth(options);
  }

  /**
   * Body parser middleware.
   * @param {Object} options
   * @returns {Function}
   */

  bodyParser(options) {
    return middleware.bodyParser(options);
  }

  /**
   * JSON rpc middleware.
   * @param {Object} rpc
   * @returns {Function}
   */

  jsonRPC(rpc) {
    if (rpc == null)
      rpc = this.rpc;

    return middleware.jsonRPC(rpc);
  }

  /**
   * Static file middleware.
   * @param {String} prefix
   * @returns {Function}
   */

  fileServer(prefix) {
    return middleware.fileServer(prefix);
  }

  /**
   * Cookie parsing middleware.
   * @returns {Function}
   */

  cookieParser() {
    return middleware.cookieParser();
  }
}

/**
 * HTTP Server Options
 */

class ServerOptions {
  /**
   * Create http server options.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.host = '127.0.0.1';
    this.port = 8080;

    this.ssl = false;
    this.keyFile = null;
    this.certFile = null;
    this.key = null;
    this.cert = null;
    this.ca = null;

    this.sockets = true;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from object.
   * @private
   * @param {Object} options
   * @returns {ServerOptions}
   */

  fromOptions(options) {
    assert(options);

    if (options.host != null) {
      assert(typeof options.host === 'string');
      this.host = options.host;
    }

    if (options.port != null) {
      assert((options.port & 0xffff) === options.port,
        'Port must be a number.');
      this.port = options.port;
    }

    if (options.prefix != null) {
      assert(typeof options.prefix === 'string');
      this.keyFile = Path.join(options.prefix, 'key.pem');
      this.certFile = Path.join(options.prefix, 'cert.pem');
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

    if (options.key != null) {
      assert(typeof options.key === 'string' || Buffer.isBuffer(options.key));
      this.key = options.key;
    }

    if (options.cert != null) {
      assert(typeof options.cert === 'string' || Buffer.isBuffer(options.cert));
      this.cert = options.cert;
    }

    if (options.ca != null) {
      assert(Array.isArray(options.ca));
      this.ca = options.ca;
    }

    if (options.sockets != null) {
      assert(typeof options.sockets === 'boolean');
      this.sockets = options.sockets;
    }

    if (this.ssl) {
      assert(this.key || this.keyFile, 'SSL specified with no provided key.');
      assert(this.cert || this.certFile,
        'SSL specified with no provided cert.');
    }

    return this;
  }

  /**
   * Instantiate http server options from object.
   * @param {Object} options
   * @returns {ServerOptions}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Load key and cert file.
   * @private
   */

  load() {
    if (!this.ssl)
      return;

    if (this.keyFile)
      this.key = fs.readFileSync(this.keyFile);

    if (this.certFile)
      this.cert = fs.readFileSync(this.certFile);
  }

  /**
   * Get HTTP server backend.
   * @private
   * @returns {Object}
   */

  getBackend() {
    return this.ssl ? require('https') : require('http');
  }

  /**
   * Get HTTP server options.
   * @private
   * @returns {Object}
   */

  toHTTP() {
    if (!this.ssl)
      return undefined;

    return {
      key: this.key,
      cert: this.cert,
      ca: this.ca
    };
  }
}

/*
 * Expose
 */

module.exports = Server;
