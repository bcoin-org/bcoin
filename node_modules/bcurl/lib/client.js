/*!
 * client.js - http client for bcurl
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcurl
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const URL = require('url');
const bsock = require('bsock');
const brq = require('brq');

/**
 * HTTP Client
 */

class Client extends EventEmitter {
  /**
   * Create an HTTP client.
   * @constructor
   * @param {Object?} options
   */

  constructor(options) {
    super();

    const opt = new ClientOptions(options);

    this.ssl = opt.ssl;
    this.host = opt.host;
    this.port = opt.port;
    this.path = opt.path;
    this.headers = opt.headers;
    this.username = opt.username;
    this.password = opt.password;
    this.id = opt.id;
    this.token = opt.token;
    this.timeout = opt.timeout;
    this.limit = opt.limit;
    this.sequence = 0;
    this.opened = false;
    this.socket = bsock.socket();
  }

  /**
   * Clone client.
   * @returns {Client}
   */

  clone() {
    const copy = new this.constructor();
    copy.ssl = this.ssl;
    copy.host = this.host;
    copy.port = this.port;
    copy.path = this.path;
    copy.headers = this.headers;
    copy.username = this.username;
    copy.password = this.password;
    copy.id = this.id;
    copy.token = this.token;
    copy.sequence = this.sequence;
    copy.timeout = this.timeout;
    copy.limit = this.limit;
    copy.opened = this.opened;
    copy.socket = this.socket;
    return copy;
  }

  /**
   * Open client.
   * @returns {Promise}
   */

  async open() {
    const {port, host, ssl} = this;

    assert(!this.opened, 'Already opened.');
    this.opened = true;

    this.socket.on('connect', async () => {
      try {
        await this.auth();
      } catch (e) {
        this.emit('error', e);
        return;
      }
      this.emit('connect');
    });

    this.socket.on('error', (err) => {
      this.emit('error', err);
    });

    this.socket.on('disconnect', () => {
      this.emit('disconnect');
    });

    this.socket.connect(port, host, ssl);
  }

  /**
   * Close client.
   * @returns {Promise}
   */

  async close() {
    assert(this.opened, 'Not opened.');
    this.opened = false;
    this.socket.destroy();
    this.socket = bsock.socket();
  }

  /**
   * Auth (abstract).
   */

  async auth() {}

  /**
   * Add a hook.
   */

  hook(...args) {
    return this.socket.hook(...args);
  }

  /**
   * Call a hook.
   * @returns {Promise}
   */

  async call(...args) {
    return this.socket.call(...args);
  }

  /**
   * Add an event listener.
   */

  bind(...args) {
    return this.socket.bind(...args);
  }

  /**
   * Fire an event.
   */

  fire(...args) {
    return this.socket.fire(...args);
  }

  /**
   * Make an http request to endpoint.
   * @param {String} method
   * @param {String} endpoint - Path.
   * @param {Object} params - Body or query depending on method.
   * @returns {Promise}
   */

  async request(method, endpoint, params) {
    assert(typeof method === 'string');
    assert(typeof endpoint === 'string');

    let query = null;

    if (params == null)
      params = {};

    assert(params && typeof params === 'object');

    if (this.token)
      params.token = this.token;

    if (method === 'GET') {
      query = params;
      params = null;
    }

    const res = await brq({
      method: method,
      ssl: this.ssl,
      host: this.host,
      port: this.port,
      path: this.path + endpoint,
      username: this.username,
      password: this.password,
      headers: this.headers,
      timeout: this.timeout,
      limit: this.limit,
      query: query,
      pool: true,
      json: params
    });

    if (res.statusCode === 404)
      return null;

    if (res.statusCode === 401)
      throw new Error('Unauthorized (bad API key).');

    if (res.type !== 'json')
      throw new Error('Bad response (wrong content-type).');

    const json = res.json();

    if (!json)
      throw new Error('Bad response (no body).');

    if (json.error) {
      const {error} = json;
      const err = new Error(error.message);
      err.type = String(error.type);
      err.code = error.code;
      throw err;
    }

    if (res.statusCode !== 200)
      throw new Error(`Status code: ${res.statusCode}.`);

    return json;
  }

  /**
   * Make a GET http request to endpoint.
   * @param {String} endpoint - Path.
   * @param {Object} params - Querystring.
   * @returns {Promise}
   */

  get(endpoint, params) {
    return this.request('GET', endpoint, params);
  }

  /**
   * Make a POST http request to endpoint.
   * @param {String} endpoint - Path.
   * @param {Object} params - Body.
   * @returns {Promise}
   */

  post(endpoint, params) {
    return this.request('POST', endpoint, params);
  }

  /**
   * Make a PUT http request to endpoint.
   * @param {String} endpoint - Path.
   * @param {Object} params - Body.
   * @returns {Promise}
   */

  put(endpoint, params) {
    return this.request('PUT', endpoint, params);
  }

  /**
   * Make a DELETE http request to endpoint.
   * @param {String} endpoint - Path.
   * @param {Object} params - Body.
   * @returns {Promise}
   */

  del(endpoint, params) {
    return this.request('DELETE', endpoint, params);
  }

  /**
   * Make a json rpc request.
   * @param {String} endpoint - Path.
   * @param {String} method - RPC method name.
   * @param {Array} params - RPC parameters.
   * @returns {Promise} - Returns Object?.
   */

  async execute(endpoint, method, params) {
    assert(typeof endpoint === 'string');
    assert(typeof method === 'string');

    if (params == null)
      params = null;

    this.sequence += 1;

    const res = await brq({
      method: 'POST',
      ssl: this.ssl,
      host: this.host,
      port: this.port,
      path: this.path + endpoint,
      username: this.username,
      password: this.password,
      headers: this.headers,
      timeout: this.timeout,
      limit: this.limit,
      pool: true,
      query: this.token
        ? { token: this.token }
        : undefined,
      json: {
        method: method,
        params: params,
        id: this.sequence
      }
    });

    if (res.statusCode === 401)
      throw new RPCError('Unauthorized (bad API key).', -1);

    if (res.type !== 'json')
      throw new Error('Bad response (wrong content-type).');

    const json = res.json();

    if (!json)
      throw new Error('No body for JSON-RPC response.');

    if (json.error) {
      const {message, code} = json.error;
      throw new RPCError(message, code);
    }

    if (res.statusCode !== 200)
      throw new Error(`Status code: ${res.statusCode}.`);

    return json.result;
  }
}

/**
 * Client Options
 */

class ClientOptions {
  constructor(options) {
    this.ssl = false;
    this.host = 'localhost';
    this.port = 80;
    this.path = '/';
    this.headers = null;
    this.username = null;
    this.password = null;
    this.id = null;
    this.token = null;
    this.timeout = 5000;
    this.limit = null;

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    if (typeof options === 'string')
      options = { url: options };

    assert(options && typeof options === 'object');

    if (options.ssl != null) {
      assert(typeof options.ssl === 'boolean');
      this.ssl = options.ssl;
      this.port = 443;
    }

    if (options.host != null) {
      assert(typeof options.host === 'string');
      this.host = options.host;
    }

    if (options.port != null) {
      assert((options.port & 0xffff) === options.port);
      assert(options.port !== 0);
      this.port = options.port;
    }

    if (options.path != null) {
      assert(typeof options.path === 'string');
      this.path = options.path;
    }

    if (options.headers != null) {
      assert(typeof options.headers === 'object');
      this.headers = options.headers;
    }

    if (options.apiKey != null) {
      assert(typeof options.apiKey === 'string');
      this.password = options.apiKey;
    }

    if (options.key != null) {
      assert(typeof options.key === 'string');
      this.password = options.key;
    }

    if (options.username != null) {
      assert(typeof options.username === 'string');
      this.username = options.username;
    }

    if (options.password != null) {
      assert(typeof options.password === 'string');
      this.password = options.password;
    }

    if (options.url != null) {
      assert(typeof options.url === 'string');

      let url = options.url;

      if (url.indexOf('://') === -1)
        url = `http://${url}`;

      const data = URL.parse(url);

      if (data.protocol !== 'http:'
          && data.protocol !== 'https:') {
        throw new Error('Malformed URL.');
      }

      if (!data.hostname)
        throw new Error('Malformed URL.');

      if (data.protocol === 'https:') {
        this.ssl = true;
        this.port = 443;
      }

      this.host = data.hostname;

      if (data.port) {
        const port = parseInt(data.port, 10);
        assert((port & 0xffff) === port);
        assert(port !== 0);
        this.port = port;
      }

      this.path = data.pathname;

      if (data.auth) {
        const parts = data.auth.split(':');
        this.username = parts.shift();
        this.password = parts.join(':');
      }
    }

    if (options.id != null) {
      assert(typeof options.id === 'string');
      this.id = options.id;
    }

    if (options.token != null) {
      assert(typeof options.token === 'string');
      this.token = options.token;
    }

    if (options.timeout != null) {
      assert(typeof options.timeout === 'number');
      this.timeout = options.timeout;
    }

    if (options.limit != null) {
      assert(typeof options.limit === 'number');
      this.limit = options.limit;
    }

    return this;
  }
}

/**
 * RPC Error
 */

class RPCError extends Error {
  constructor(msg, code) {
    super();

    this.type = 'RPCError';
    this.message = String(msg);
    this.code = code >>> 0;

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, RPCError);
  }
}

/*
 * Expose
 */

module.exports = Client;
