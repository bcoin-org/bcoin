/*!
 * http.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const path = require('path');
const EventEmitter = require('events');
const URL = require('url');
const {StringDecoder} = require('string_decoder');
const AsyncObject = require('../utils/asyncobject');
const util = require('../utils/util');
const co = require('../utils/co');
const Validator = require('../utils/validator');
const {List, ListItem} = require('../utils/list');
const fs = require('../utils/fs');
const digest = require('../crypto/digest');
const ccmp = require('../crypto/ccmp');

/**
 * HTTPBase
 * @alias module:http.Base
 * @constructor
 * @param {Object?} options
 * @emits HTTPBase#socket
 */

function HTTPBase(options) {
  if (!(this instanceof HTTPBase))
    return new HTTPBase(options);

  AsyncObject.call(this);

  this.config = new HTTPBaseOptions(options);
  this.config.load();

  this.server = null;
  this.io = null;
  this.sockets = new List();
  this.channels = new Map();
  this.routes = new Routes();
  this.mounts = [];
  this.stack = [];
  this.hooks = [];

  this._init();
}

util.inherits(HTTPBase, AsyncObject);

/**
 * Initialize server.
 * @private
 */

HTTPBase.prototype._init = function _init() {
  let backend = this.config.getBackend();
  let options = this.config.toHTTP();

  this.server = backend.createServer(options);

  this._initRouter();
  this._initSockets();

  this.server.on('connection', (socket) => {
    socket.on('error', (err) => {
      if (err.message === 'Parse Error') {
        let msg = 'http_parser.execute failure';
        msg += ` (parsed=${err.bytesParsed || -1}`;
        msg += ` code=${err.code})`;
        err = new Error(msg);
      }

      this.emit('error', err);

      try {
        socket.destroy();
      } catch (e) {
        ;
      }
    });
  });

  this.server.on('error', (err) => {
    this.emit('error', err);
  });
};

/**
 * Initialize router.
 * @private
 */

HTTPBase.prototype._initRouter = function _initRouter() {
  this.server.on('request', async (hreq, hres) => {
    let req = new Request(hreq, hres, hreq.url);
    let res = new Response(hreq, hres);

    req.on('error', () => {});

    try {
      req.pause();
      await this.handleRequest(req, res);
    } catch (e) {
      res.error(e.statusCode || 500, e);
      this.emit('error', e);
    }
  });
};

/**
 * Handle a request.
 * @private
 * @param {ServerRequest} req
 * @param {ServerResponse} res
 * @returns {Promise}
 */

HTTPBase.prototype.handleRequest = async function handleRequest(req, res) {
  let routes;

  if (await this.handleMounts(req, res))
    return;

  this.emit('request', req, res);

  if (await this.handleStack(req, res))
    return;

  routes = this.routes.getHandlers(req.method);

  if (!routes)
    throw new Error(`No routes found for method: ${req.method}.`);

  for (let route of routes) {
    let params = route.match(req.pathname);

    if (!params)
      continue;

    req.params = params;

    if (await this.handleHooks(req, res))
      return;

    if (await route.call(req, res))
      return;
  }

  throw new Error(`No routes found for path: ${req.pathname}.`);
};

/**
 * CORS middleware.
 * @returns {Function}
 */

HTTPBase.prototype.cors = function cors() {
  return async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET,HEAD,PUT,PATCH,POST,DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization');

    if (req.method === 'OPTIONS') {
      res.setStatus(200);
      res.end();
      return;
    }
  };
};

/**
 * Basic auth middleware.
 * @param {Object} options
 * @returns {Function}
 */

HTTPBase.prototype.basicAuth = function basicAuth(options) {
  let user = options.username;
  let pass = options.password;
  let realm = options.realm;

  if (user) {
    if (typeof user === 'string')
      user = Buffer.from(user, 'utf8');
    assert(Buffer.isBuffer(user));
    user = digest.hash256(user);
  }

  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  assert(Buffer.isBuffer(pass));
  pass = digest.hash256(pass);

  if (!realm)
    realm = 'server';

  assert(typeof realm === 'string');

  function fail(res) {
    res.setHeader('WWW-Authenticate', `Basic realm="${realm}"`);
    res.setStatus(401);
    res.end();
  }

  return async (req, res) => {
    let auth = req.headers['authorization'];
    let parts, username, password, hash;

    if (!auth)
      return fail(res);

    parts = auth.split(' ');

    if (parts.length !== 2)
      return fail(res);

    if (parts[0] !== 'Basic')
      return fail(res);

    auth = Buffer.from(parts[1], 'base64').toString('utf8');
    parts = auth.split(':');

    username = parts.shift();
    password = parts.join(':');

    if (user) {
      hash = Buffer.from(username, 'utf8');
      hash = digest.hash256(hash);

      if (!ccmp(hash, user))
        return fail(res);
    }

    hash = Buffer.from(password, 'utf8');
    hash = digest.hash256(hash);

    if (!ccmp(hash, pass))
      return fail(res);

    req.username = username;
  };
};

/**
 * Body parser middleware.
 * @param {Object} options
 * @returns {Function}
 */

HTTPBase.prototype.bodyParser = function bodyParser(options) {
  let opt = new BodyParserOptions(options);

  return async (req, res) => {
    if (req.hasBody)
      return;

    try {
      req.resume();
      req.body = await this.parseBody(req, opt);
    } finally {
      req.pause();
    }

    req.hasBody = true;
  };
};

/**
 * Parse request body.
 * @private
 * @param {ServerRequest} req
 * @param {Object} options
 * @returns {Promise}
 */

HTTPBase.prototype.parseBody = async function parseBody(req, options) {
  let body = Object.create(null);
  let type = req.contentType;
  let data;

  if (req.method === 'GET')
    return body;

  data = await this.readBody(req, 'utf8', options);

  if (!data)
    return body;

  if (options.contentType)
    type = options.contentType;

  switch (type) {
    case 'json':
      body = JSON.parse(data);
      break;
    case 'form':
      body = parsePairs(data, options.keyLimit);
      break;
    default:
      break;
  }

  return body;
};

/**
 * Read and buffer request body.
 * @param {ServerRequest} req
 * @param {String} enc
 * @param {Object} options
 * @returns {Promise}
 */

HTTPBase.prototype.readBody = function readBody(req, enc, options) {
  return new Promise((resolve, reject) => {
    return this._readBody(req, enc, options, resolve, reject);
  });
};

/**
 * Read and buffer request body.
 * @private
 * @param {ServerRequest} req
 * @param {String} enc
 * @param {Object} options
 * @param {Function} resolve
 * @param {Function} reject
 */

HTTPBase.prototype._readBody = function _readBody(req, enc, options, resolve, reject) {
  let decode = new StringDecoder(enc);
  let hasData = false;
  let total = 0;
  let body = '';

  let timer = setTimeout(() => {
    timer = null;
    cleanup();
    reject(new Error('Request body timed out.'));
  }, options.timeout);

  let cleanup = () => {
    req.removeListener('data', onData);
    req.removeListener('error', onError);
    req.removeListener('end', onEnd);

    if (timer != null) {
      timer = null;
      clearTimeout(timer);
    }
  };

  let onData = (data) => {
    total += data.length;
    hasData = true;

    if (total > options.bodyLimit) {
      reject(new Error('Request body overflow.'));
      return;
    }

    body += decode.write(data);
  };

  let onError = (err) => {
    cleanup();
    reject(err);
  };

  let onEnd = () => {
    cleanup();

    if (hasData) {
      resolve(body);
      return;
    }

    resolve(null);
  };

  req.on('data', onData);
  req.on('error', onError);
  req.on('end', onEnd);
};

/**
 * JSON rpc middleware.
 * @param {RPCBase} rpc
 * @returns {Function}
 */

HTTPBase.prototype.jsonRPC = function jsonRPC(rpc) {
  return async (req, res) => {
    let json;

    if (req.method !== 'POST')
      return;

    if (req.pathname !== '/')
      return;

    if (typeof req.body.method !== 'string')
      return;

    json = await rpc.call(req.body, req.query);

    json = JSON.stringify(json);
    json += '\n';

    res.setHeader('X-Long-Polling', '/?longpoll=1');

    res.send(200, json, 'json');
  };
};

/**
 * Handle mount stack.
 * @private
 * @param {HTTPRequest} req
 * @param {HTTPResponse} res
 * @returns {Promise}
 */

HTTPBase.prototype.handleMounts = async function handleMounts(req, res) {
  let url = req.url;

  for (let route of this.mounts) {
    let server = route.handler;

    if (!route.hasPrefix(req.pathname))
      continue;

    assert(url.indexOf(route.path) === 0);

    url = url.substring(route.path.length);
    req = req.rewrite(url);

    await server.handleRequest(req, res);

    return true;
  }

  return false;
};

/**
 * Handle middleware stack.
 * @private
 * @param {HTTPRequest} req
 * @param {HTTPResponse} res
 * @returns {Promise}
 */

HTTPBase.prototype.handleStack = async function handleStack(req, res) {
  for (let route of this.stack) {
    if (!route.hasPrefix(req.pathname))
      continue;

    if (await route.call(req, res))
      return true;
  }

  return false;
};

/**
 * Handle hook stack.
 * @private
 * @param {HTTPRequest} req
 * @param {HTTPResponse} res
 * @returns {Promise}
 */

HTTPBase.prototype.handleHooks = async function handleHooks(req, res) {
  for (let route of this.hooks) {
    if (!route.hasPrefix(req.pathname))
      continue;

    if (await route.call(req, res))
      return true;
  }

  return false;
};

/**
 * Initialize websockets.
 * @private
 */

HTTPBase.prototype._initSockets = function _initSockets() {
  let IOServer;

  if (!this.config.sockets)
    return;

  try {
    IOServer = require('socket.io');
  } catch (e) {
    ;
  }

  if (!IOServer)
    return;

  this.io = new IOServer({
    transports: ['websocket'],
    serveClient: false
  });

  this.io.attach(this.server);

  this.io.on('connection', (ws) => {
    this.addSocket(ws);
  });
};

/**
 * Broadcast event to channel.
 * @param {String} name
 * @param {String} type
 * @param {...Object} args
 */

HTTPBase.prototype.to = function to(name, ...args) {
  let list = this.channels.get(name);

  if (!list)
    return;

  assert(list.size > 0);

  for (let item = list.head; item; item = item.next) {
    let socket = item.value;
    socket.emit(...args);
  }
};

/**
 * Broadcast event to all connections.
 * @param {String} channel
 * @param {String} type
 * @param {...Object} args
 */

HTTPBase.prototype.all = function all() {
  let list = this.sockets;

  for (let socket = list.head; socket; socket = socket.next)
    socket.emit.apply(socket, arguments);
};

/**
 * Add and initialize a websocket.
 * @private
 * @param {SocketIO.Socket} ws
 */

HTTPBase.prototype.addSocket = function addSocket(ws) {
  let socket = new WebSocket(ws, this);

  socket.on('error', (err) => {
    this.emit('error', err);
  });

  socket.on('close', () => {
    this.removeSocket(socket);
  });

  socket.on('join channel', (name) => {
    this.joinChannel(socket, name);
  });

  socket.on('leave channel', (name) => {
    this.leaveChannel(socket, name);
  });

  this.sockets.push(socket);

  for (let route of this.mounts)
    route.handler.addSocket(ws);

  this.emit('socket', socket);
};

/**
 * Remove a socket from lists.
 * @private
 * @param {WebSocket} socket
 */

HTTPBase.prototype.removeSocket = function removeSocket(socket) {
  for (let key of socket.channels.keys())
    this.leaveChannel(socket, key);

  assert(this.sockets.remove(socket));
};

/**
 * Add a socket to channel list.
 * @private
 * @param {WebSocket} socket
 * @param {String} name
 */

HTTPBase.prototype.joinChannel = function joinChannel(socket, name) {
  let list = this.channels.get(name);
  let item = socket.channels.get(name);

  if (item)
    return;

  if (!list) {
    list = new List();
    this.channels.set(name, list);
  }

  item = new ListItem(socket);
  list.push(item);

  socket.channels.set(name, item);
};

/**
 * Remove a socket from channel list.
 * @private
 * @param {WebSocket} socket
 * @param {String} name
 */

HTTPBase.prototype.leaveChannel = function leaveChannel(socket, name) {
  let list = this.channels.get(name);
  let item = socket.channels.get(name);

  if (!item)
    return;

  assert(list);
  assert(list.remove(item));

  if (list.size === 0)
    this.channels.delete(name);

  socket.channels.delete(name);
};

/**
 * Get channel list.
 * @private
 * @param {String} name
 */

HTTPBase.prototype.channel = function channel(name) {
  let list = this.channels.get(name);

  if (!list)
    return;

  assert(list.size > 0);

  return list;
};

/**
 * Open the server.
 * @alias HTTPBase#open
 * @returns {Promise}
 */

HTTPBase.prototype._open = function open() {
  return this.listen(this.config.port, this.config.host);
};

/**
 * Close the server.
 * @alias HTTPBase#close
 * @returns {Promise}
 */

HTTPBase.prototype._close = function close() {
  return new Promise((resolve, reject) => {
    if (this.io) {
      this.server.once('close', resolve);
      this.io.close();
      return;
    }

    this.server.close((err) => {
      if (err) {
        reject(err);
        return;
      }
      resolve();
    });
  });
};

/**
 * Mount a server.
 * @param {String?} path
 * @param {HTTPBase} server
 * @param {Object?} ctx
 */

HTTPBase.prototype.mount = function mount(path, server, ctx) {
  if (!server) {
    server = path;
    path = null;
  }
  this.mounts.push(new Route(ctx || this, path, server));
};

/**
 * Add a middleware to the stack.
 * @param {String?} path
 * @param {Function} handler
 * @param {Object?} ctx
 */

HTTPBase.prototype.use = function use(path, handler, ctx) {
  if (!handler) {
    handler = path;
    path = null;
  }
  this.stack.push(new Route(ctx || this, path, handler));
};

/**
 * Add a hook to the stack.
 * @param {String?} path
 * @param {Function} handler
 * @param {Object?} ctx
 */

HTTPBase.prototype.hook = function hook(path, handler, ctx) {
  if (!handler) {
    handler = path;
    path = null;
  }
  this.hooks.push(new Route(ctx || this, path, handler));
};

/**
 * Add a GET route.
 * @param {String} path
 * @param {Function} handler
 * @param {Object?} ctx
 */

HTTPBase.prototype.get = function get(path, handler, ctx) {
  this.routes.get.push(new Route(ctx || this, path, handler));
};

/**
 * Add a POST route.
 * @param {String} path
 * @param {Function} handler
 * @param {Object?} ctx
 */

HTTPBase.prototype.post = function post(path, handler, ctx) {
  this.routes.post.push(new Route(ctx || this, path, handler));
};

/**
 * Add a PUT route.
 * @param {String} path
 * @param {Function} handler
 * @param {Object?} ctx
 */

HTTPBase.prototype.put = function put(path, handler, ctx) {
  this.routes.put.push(new Route(ctx || this, path, handler));
};

/**
 * Add a DELETE route.
 * @param {String} path
 * @param {Function} handler
 * @param {Object?} ctx
 */

HTTPBase.prototype.del = function del(path, handler, ctx) {
  this.routes.del.push(new Route(ctx || this, path, handler));
};

/**
 * Get server address.
 * @returns {Object}
 */

HTTPBase.prototype.address = function address() {
  return this.server.address();
};

/**
 * Listen on port and host.
 * @param {Number} port
 * @param {String} host
 * @returns {Promise}
 */

HTTPBase.prototype.listen = function listen(port, host) {
  return new Promise((resolve, reject) => {
    let addr;
    this.server.listen(port, host, (err) => {
      if (err)
        return reject(err);

      addr = this.address();

      this.emit('listening', addr);

      resolve(addr);
    });
  });
};

/**
 * HTTP Base Options
 * @alias module:http.HTTPBaseOptions
 * @constructor
 * @param {Object} options
 */

function HTTPBaseOptions(options) {
  if (!(this instanceof HTTPBaseOptions))
    return new HTTPBaseOptions(options);

  this.host = '127.0.0.1';
  this.port = 8080;
  this.sockets = true;

  this.ssl = false;
  this.keyFile = null;
  this.certFile = null;
  this.key = null;
  this.cert = null;
  this.ca = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from object.
 * @private
 * @param {Object} options
 * @returns {HTTPBaseOptions}
 */

HTTPBaseOptions.prototype.fromOptions = function fromOptions(options) {
  assert(options);

  if (options.host != null) {
    assert(typeof options.host === 'string');
    this.host = options.host;
  }

  if (options.port != null) {
    assert(typeof options.port === 'number', 'Port must be a number.');
    assert(options.port > 0 && options.port <= 0xffff);
    this.port = options.port;
  }

  if (options.sockets != null) {
    assert(typeof options.sockets === 'boolean');
    this.sockets = options.sockets;
  }

  if (options.prefix != null) {
    assert(typeof options.prefix === 'string');
    this.prefix = options.prefix;
    this.keyFile = path.join(this.prefix, 'key.pem');
    this.certFile = path.join(this.prefix, 'cert.pem');
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

  if (this.ssl) {
    assert(this.key || this.keyFile, 'SSL specified with no provided key.');
    assert(this.cert || this.certFile, 'SSL specified with no provided cert.');
  }

  return this;
};

/**
 * Load key and cert file.
 * @private
 */

HTTPBaseOptions.prototype.load = function load() {
  if (!this.ssl)
    return;

  if (this.keyFile)
    this.key = fs.readFileSync(this.keyFile);

  if (this.certFile)
    this.cert = fs.readFileSync(this.certFile);
};

/**
 * Instantiate http server options from object.
 * @param {Object} options
 * @returns {HTTPBaseOptions}
 */

HTTPBaseOptions.fromOptions = function fromOptions(options) {
  return new HTTPBaseOptions().fromOptions(options);
};

/**
 * Get HTTP server backend.
 * @private
 * @returns {Object}
 */

HTTPBaseOptions.prototype.getBackend = function getBackend() {
  return this.ssl ? require('https') : require('http');
};

/**
 * Get HTTP server options.
 * @private
 * @returns {Object}
 */

HTTPBaseOptions.prototype.toHTTP = function toHTTP() {
  if (!this.ssl)
    return undefined;

  return {
    key: this.key,
    cert: this.cert,
    ca: this.ca
  };
};

/**
 * HTTP Base Options
 * @alias module:http.BodyParserOptions
 * @constructor
 * @param {Object} options
 */

function BodyParserOptions(options) {
  if (!(this instanceof BodyParserOptions))
    return new BodyParserOptions(options);

  this.keyLimit = 100;
  this.bodyLimit = 20 << 20;
  this.contentType = null;
  this.timeout = 10 * 1000;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from object.
 * @private
 * @param {Object} options
 * @returns {BodyParserOptions}
 */

BodyParserOptions.prototype.fromOptions = function fromOptions(options) {
  assert(options);

  if (options.keyLimit != null) {
    assert(typeof options.keyLimit === 'number');
    this.keyLimit = options.keyLimit;
  }

  if (options.bodyLimit != null) {
    assert(typeof options.bodyLimit === 'number');
    this.bodyLimit = options.bodyLimit;
  }

  if (options.contentType != null) {
    assert(typeof options.contentType === 'string');
    this.contentType = options.contentType;
  }

  return this;
};

/**
 * Route
 * @constructor
 * @ignore
 */

function Route(ctx, path, handler) {
  if (!(this instanceof Route))
    return new Route(ctx, path, handler);

  this.ctx = null;
  this.path = null;
  this.handler = null;

  this.regex = /^/;
  this.map = [];
  this.compiled = false;

  if (ctx) {
    assert(typeof ctx === 'object');
    this.ctx = ctx;
  }

  if (path) {
    if (path instanceof RegExp) {
      this.regex = path;
    } else {
      assert(typeof path === 'string');
      assert(path.length > 0);
      this.path = path;
    }
  }

  assert(handler);
  assert(typeof handler === 'function' || typeof handler === 'object');

  this.handler = handler;
}

Route.prototype.compile = function compile() {
  let path = this.path;
  let map = this.map;

  if (this.compiled)
    return;

  this.compiled = true;

  if (!path)
    return;

  path = path.replace(/(\/[^\/]+)\?/g, '(?:$1)?');
  path = path.replace(/\.(?!\+)/g, '\\.');
  path = path.replace(/\*/g, '.*?');
  path = path.replace(/%/g, '\\');

  path = path.replace(/:(\w+)/g, (str, name) => {
    map.push(name);
    return '([^/]+)';
  });

  this.regex = new RegExp('^' + path + '$');
};

Route.prototype.match = function _match(pathname) {
  let match, params;

  this.compile();

  assert(this.regex);

  match = this.regex.exec(pathname);

  if (!match)
    return;

  params = Object.create(null);

  for (let i = 1; i < match.length; i++) {
    let item = match[i];
    let key = this.map[i - 1];

    if (key)
      params[key] = item;

    params[i - 1] = item;
  }

  return params;
};

Route.prototype.hasPrefix = function hasPrefix(pathname) {
  if (!this.path)
    return true;

  return pathname.indexOf(this.path) === 0;
};

Route.prototype.call = async function call(req, res) {
  await this.handler.call(this.ctx, req, res);
  return res.sent;
};

/**
 * Routes
 * @constructor
 * @ignore
 */

function Routes() {
  if (!(this instanceof Routes))
    return new Routes();

  this.get = [];
  this.post = [];
  this.put = [];
  this.del = [];
}

Routes.prototype.getHandlers = function getHandlers(method) {
  if (!method)
    return;

  method = method.toUpperCase();

  switch (method) {
    case 'GET':
      return this.get;
    case 'POST':
      return this.post;
    case 'PUT':
      return this.put;
    case 'DELETE':
      return this.del;
    default:
      return;
  }
};

/**
 * Request
 * @constructor
 * @ignore
 */

function Request(req, res, url) {
  if (!(this instanceof Request))
    return new Request(req, res, url);

  EventEmitter.call(this);

  this.req = null;
  this.res = null;
  this.socket = null;
  this.method = 'GET';
  this.headers = Object.create(null);
  this.contentType = 'bin';
  this.url = '/';
  this.pathname = '';
  this.path = [];
  this.trailing = false;
  this.query = Object.create(null);
  this.params = Object.create(null);
  this.body = Object.create(null);
  this.hasBody = false;
  this.username = null;
  this.readable = true;
  this.writable = false;

  if (req)
    this.init(req, res, url);
}

util.inherits(Request, EventEmitter);

Request.prototype.init = function init(req, res, url) {
  assert(req);
  assert(res);

  this.req = req;
  this.res = res;
  this.socket = req.socket;
  this.method = req.method;
  this.headers = req.headers;
  this.contentType = parseType(req.headers['content-type']);

  req.on('error', (err) => {
    this.emit('error', err);
  });

  req.on('data', (data) => {
    this.emit('data', data);
  });

  req.on('end', () => {
    this.emit('end');
  });

  if (url != null)
    this.parse(url);
};

Request.prototype.parse = function parse(url) {
  let uri = URL.parse(url);
  let pathname = uri.pathname;
  let query = Object.create(null);
  let trailing = false;
  let path, parts;

  if (pathname) {
    pathname = pathname.replace(/\/{2,}/g, '/');

    if (pathname[0] !== '/')
      pathname = '/' + pathname;

    if (pathname.length > 1) {
      if (pathname[pathname.length - 1] === '/') {
        pathname = pathname.slice(0, -1);
        trailing = true;
      }
    }

    pathname = unescape(pathname);
  } else {
    pathname = '/';
  }

  assert(pathname.length > 0);
  assert(pathname[0] === '/');

  if (pathname.length > 1)
    assert(pathname[pathname.length - 1] !== '/');

  path = pathname;

  if (path[0] === '/')
    path = path.substring(1);

  parts = path.split('/');

  if (parts.length === 1) {
    if (parts[0].length === 0)
      parts = [];
  }

  url = pathname;

  if (uri.search && uri.search.length > 1) {
    assert(uri.search[0] === '?');
    url += uri.search;
  }

  if (uri.hash && uri.hash.length > 1) {
    assert(uri.hash[0] === '#');
    url += uri.hash;
  }

  if (uri.query)
    query = parsePairs(uri.query, 100);

  this.url = url;
  this.pathname = pathname;
  this.path = parts;
  this.query = query;
  this.trailing = trailing;
};

Request.prototype.rewrite = function rewrite(url) {
  let req = new Request();
  req.init(this.req, this.res, url);
  req.body = this.body;
  req.hasBody = this.hasBody;
  return req;
};

Request.prototype.valid = function valid() {
  return new Validator([this.query, this.params, this.body]);
};

Request.prototype.pipe = function pipe(dest) {
  return this.req.pipe(dest);
};

Request.prototype.pause = function pause() {
  return this.req.pause();
};

Request.prototype.resume = function resume() {
  return this.req.resume();
};

Request.prototype.destroy = function destroy() {
  return this.req.destroy();
};

/**
 * Response
 * @constructor
 * @ignore
 */

function Response(req, res) {
  if (!(this instanceof Response))
    return new Response(req, res);

  EventEmitter.call(this);

  this.req = req;
  this.res = res;
  this.sent = false;
  this.readable = false;
  this.writable = true;
  this.statusCode = 200;
  this.res.statusCode = 200;

  if (req)
    this.init(req, res);
}

util.inherits(Response, EventEmitter);

Response.prototype.init = function init(req, res) {
  assert(req);
  assert(res);

  res.on('error', (err) => {
    this.emit('error', err);
  });

  res.on('drain', () => {
    this.emit('drain');
  });

  res.on('close', () => {
    this.emit('close');
  });
};

Response.prototype.setStatus = function setStatus(code) {
  this.statusCode = code;
  this.res.statusCode = code;
};

Response.prototype.setType = function setType(type) {
  this.setHeader('Content-Type', getType(type));
};

Response.prototype.hasType = function hasType() {
  return this.getHeader('Content-Type') != null;
};

Response.prototype.destroy = function destroy() {
  return this.res.destroy();
};

Response.prototype.setHeader = function setHeader(key, value) {
  return this.res.setHeader(key, value);
};

Response.prototype.getHeader = function getHeader(key) {
  return this.res.getHeader(key);
};

Response.prototype.writeHead = function writeHead(code, headers) {
  return this.res.writeHead(code, headers);
};

Response.prototype.write = function write(data, enc) {
  return this.res.write(data, enc);
};

Response.prototype.end = function end(data, enc) {
  this.sent = true;
  return this.res.end(data, enc);
};

Response.prototype.error = function error(code, err) {
  if (this.sent)
    return;

  if (!code)
    code = 400;

  this.send(code, {
    error: {
      type: err.type || 'Error',
      message: err.message,
      code: err.code
    }
  });

  try {
    this.req.destroy();
    this.req.socket.destroy();
  } catch (e) {
    ;
  }
};

Response.prototype.redirect = function redirect(code, url) {
  if (!url) {
    url = code;
    code = 301;
  }

  this.setStatus(code);
  this.setHeader('Location', url);
  this.end();
};

Response.prototype.send = function send(code, msg, type) {
  if (this.sent)
    return;

  assert(typeof code === 'number', 'Code must be a number.');

  if (msg == null) {
    msg = {
      error: {
        type: 'Error',
        message: 'No message.'
      }
    };
  }

  if (msg && typeof msg === 'object' && !Buffer.isBuffer(msg)) {
    msg = JSON.stringify(msg, null, 2) + '\n';
    if (!type)
      type = 'json';
    assert(type === 'json', 'Bad type passed with json object.');
  }

  if (!type && !this.hasType())
    type = typeof msg === 'string' ? 'txt' : 'bin';

  this.setStatus(code);

  if (type)
    this.setType(type);

  if (typeof msg === 'string') {
    let len = Buffer.byteLength(msg, 'utf8');
    this.setHeader('Content-Length', len + '');
    try {
      this.write(msg, 'utf8');
      this.end();
    } catch (e) {
      ;
    }
    return;
  }

  if (Buffer.isBuffer(msg)) {
    this.setHeader('Content-Length', msg.length + '');
    try {
      this.write(msg);
      this.end();
    } catch (e) {
      ;
    }
    return;
  }

  assert(false, 'Bad object passed to send.');
};

/**
 * WebSocket
 * @constructor
 * @ignore
 * @param {SocketIO.Socket}
 */

function WebSocket(socket, ctx) {
  if (!(this instanceof WebSocket))
    return new WebSocket(socket, ctx);

  EventEmitter.call(this);

  this.context = ctx;
  this.socket = socket;
  this.remoteAddress = socket.conn.remoteAddress;
  this.hooks = {};
  this.channels = new Map();
  this.auth = false;
  this.filter = null;
  this.prev = null;
  this.next = null;

  this.init();
}

util.inherits(WebSocket, EventEmitter);

WebSocket.prototype.init = function init() {
  let socket = this.socket;
  let onevent = socket.onevent.bind(socket);

  socket.onevent = (packet) => {
    let result = onevent(packet);
    this.onevent(packet);
    return result;
  };

  socket.on('error', (err) => {
    this.dispatch('error', err);
  });

  socket.on('disconnect', () => {
    this.dispatch('close');
  });
};

WebSocket.prototype.onevent = async function onevent(packet) {
  let args = (packet.data || []).slice();
  let type = args.shift() || '';
  let ack, result;

  if (typeof args[args.length - 1] === 'function')
    ack = args.pop();
  else
    ack = this.socket.ack(packet.id);

  try {
    result = await this.fire(type, args);
  } catch (e) {
    ack({
      type: e.type || 'Error',
      message: e.message,
      code: e.code
    });
    return;
  }

  if (result === undefined)
    return;

  ack(null, result);
};

WebSocket.prototype.hook = function hook(type, handler) {
  assert(!this.hooks[type], 'Event already added.');
  this.hooks[type] = handler;
};

WebSocket.prototype.fire = async function fire(type, args) {
  let handler = this.hooks[type];

  if (!handler)
    return;

  return await handler.call(this.context, args);
};

WebSocket.prototype.join = function join(name) {
  this.dispatch('join channel', name);
};

WebSocket.prototype.leave = function leave(name) {
  this.dispatch('leave channel', name);
};

WebSocket.prototype.dispatch = function dispatch() {
  let emit = EventEmitter.prototype.emit;
  return emit.apply(this, arguments);
};

WebSocket.prototype.emit = function emit() {
  return this.socket.emit.apply(this.socket, arguments);
};

WebSocket.prototype.call = function call(...args) {
  let socket = this.socket;
  return new Promise((resolve, reject) => {
    args.push(co.wrap(resolve, reject));
    socket.emit(...args);
  });
};

WebSocket.prototype.destroy = function destroy() {
  return this.socket.disconnect();
};

/*
 * Helpers
 */

function parsePairs(str, limit) {
  let parts = str.split('&');
  let data = Object.create(null);

  if (parts.length > limit)
    return data;

  assert(!limit || parts.length <= limit, 'Too many keys in querystring.');

  for (let pair of parts) {
    let index = pair.indexOf('=');
    let key, value;

    if (index === -1) {
      key = pair;
      value = '';
    } else {
      key = pair.substring(0, index);
      value = pair.substring(index + 1);
    }

    key = unescape(key);

    if (key.length === 0)
      continue;

    value = unescape(value);

    if (value.length === 0)
      continue;

    data[key] = value;
  }

  return data;
}

function unescape(str) {
  str = decodeURIComponent(str);
  str = str.replace(/\+/g, ' ');
  str = str.replace(/\0/g, '');
  return str;
}

function getType(type) {
  switch (type) {
    case 'json':
      return 'application/json';
    case 'form':
      return 'application/x-www-form-urlencoded; charset=utf-8';
    case 'html':
      return 'text/html; charset=utf-8';
    case 'xml':
      return 'application/xml; charset=utf-8';
    case 'js':
      return 'application/javascript; charset=utf-8';
    case 'css':
      return 'text/css; charset=utf-8';
    case 'txt':
      return 'text/plain; charset=utf-8';
    case 'bin':
      return 'application/octet-stream';
    default:
      return type;
  }
}

function parseType(type) {
  type = type || '';
  type = type.split(';')[0];
  type = type.toLowerCase();
  type = type.trim();

  switch (type) {
    case 'text/x-json':
    case 'application/json':
      return 'json';
    case 'application/x-www-form-urlencoded':
      return 'form';
    case 'text/html':
    case 'application/xhtml+xml':
      return 'html';
    case 'text/javascript':
    case 'application/javascript':
      return 'js';
    case 'text/css':
      return 'css';
    case 'text/plain':
      return 'txt';
    case 'application/octet-stream':
      return 'bin';
    default:
      return 'bin';
  }
}

/*
 * Expose
 */

module.exports = HTTPBase;
