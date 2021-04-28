/*!
 * request.js - http request for brq
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/brq
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const URL = require('url');
const qs = require('querystring');
const mime = require('./mime');
const fetch = global.fetch;
const FetchHeaders = global.Headers;

class RequestOptions {
  /**
   * Request Options
   * @constructor
   * @ignore
   * @param {Object} options
   */

  constructor(options, buffer) {
    this.method = 'GET';
    this.ssl = false;
    this.host = 'localhost';
    this.port = 80;
    this.path = '/';
    this.query = '';
    this.agent = 'brq';
    this.lookup = null;

    this.type = null;
    this.expect = null;
    this.body = null;
    this.username = '';
    this.password = '';
    this.limit = 20 << 20;
    this.timeout = 5000;
    this.buffer = buffer || false;
    this.headers = Object.create(null);

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    if (typeof options === 'string')
      options = { url: options };

    if (options.method != null) {
      assert(typeof options.method === 'string');
      this.method = options.method.toUpperCase();
    }

    if (options.uri != null)
      this.navigate(options.uri);

    if (options.url != null)
      this.navigate(options.url);

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

    if (options.query != null) {
      if (typeof options.query === 'string') {
        this.query = options.query;
      } else {
        assert(typeof options.query === 'object');
        this.query = qs.stringify(options.query);
      }
    }

    if (options.username != null) {
      assert(typeof options.username === 'string');
      this.username = options.username;
    }

    if (options.password != null) {
      assert(typeof options.password === 'string');
      this.password = options.password;
    }

    if (options.agent != null) {
      assert(typeof options.agent === 'string');
      this.agent = options.agent;
    }

    if (options.json != null) {
      assert(typeof options.json === 'object');
      this.body = Buffer.from(JSON.stringify(options.json), 'utf8');
      this.type = 'json';
    }

    if (options.form != null) {
      assert(typeof options.form === 'object');
      this.body = Buffer.from(qs.stringify(options.form), 'utf8');
      this.type = 'form';
    }

    if (options.type != null) {
      assert(typeof options.type === 'string');
      this.type = options.type;
    }

    if (options.expect != null) {
      assert(typeof options.expect === 'string');
      this.expect = options.expect;
    }

    if (options.body != null) {
      if (typeof options.body === 'string') {
        this.body = Buffer.from(options.body, 'utf8');
      } else {
        assert(Buffer.isBuffer(options.body));
        this.body = options.body;
      }
    }

    if (options.extra != null) {
      assert(Buffer.isBuffer(options.extra));
      if (!this.body)
        this.body = options.extra;
      else
        this.body = Buffer.concat([this.body, options.extra]);
    }

    if (options.timeout != null) {
      assert(typeof options.timeout === 'number');
      this.timeout = options.timeout;
    }

    if (options.limit != null) {
      assert(typeof options.limit === 'number');
      this.limit = options.limit;
    }

    if (options.headers != null) {
      assert(typeof options.headers === 'object');
      this.headers = options.headers;
    }

    if (options.lookup != null) {
      assert(typeof options.lookup === 'function');
      this.lookup = options.lookup;
    }

    return this;
  }

  navigate(url) {
    assert(typeof url === 'string');

    if (url.indexOf('://') === -1)
      url = 'http://' + url;

    const data = URL.parse(url);

    if (data.protocol !== 'http:'
        && data.protocol !== 'https:') {
      throw new Error('Malformed URL.');
    }

    if (!data.hostname)
      throw new Error('Malformed URL.');

    this.ssl = data.protocol === 'https:';
    this.host = data.hostname;
    this.port = this.ssl ? 443 : 80;

    if (data.port != null) {
      const port = parseInt(data.port, 10);
      assert((port & 0xffff) === port);
      this.port = port;
    }

    this.path = data.pathname;
    this.query = data.query;

    if (data.auth) {
      const parts = data.auth.split(':');
      this.username = parts.shift();
      this.password = parts.join(':');
    }

    return this;
  }

  isExpected(type) {
    assert(typeof type === 'string');

    if (!this.expect)
      return true;

    return this.expect === type;
  }

  isOverflow(hdr) {
    if (hdr == null)
      return false;

    assert(typeof hdr === 'string');

    if (!this.buffer)
      return false;

    hdr = hdr.trim();

    if (!/^\d+$/.test(hdr))
      return false;

    hdr = hdr.replace(/^0+/g, '');

    if (hdr.length === 0)
      hdr = '0';

    if (hdr.length > 15)
      return false;

    const length = parseInt(hdr, 10);

    if (!Number.isSafeInteger(length))
      return true;

    return length > this.limit;
  }

  getHeaders() {
    const headers = new FetchHeaders();

    headers.append('User-Agent', this.agent);

    if (this.type)
      headers.append('Content-Type', mime.type(this.type));

    if (this.body)
      headers.append('Content-Length', this.body.length.toString(10));

    if (this.username || this.password) {
      const auth = `${this.username}:${this.password}`;
      const data = Buffer.from(auth, 'utf8');
      headers.append('Authorization', `Basic ${data.toString('base64')}`);
    }

    for (const name of Object.keys(this.headers))
      headers.append(name, this.headers[name]);

    return headers;
  }

  toURL() {
    let url = '';

    if (this.ssl)
      url += 'https://';
    else
      url += 'http://';

    if (this.host.indexOf(':') !== -1)
      url += `[${this.host}]`;
    else
      url += this.host;

    url += ':' + this.port;
    url += this.path;

    if (this.query)
      url += '?' + this.query;

    return url;
  }

  toHTTP() {
    return {
      method: this.method,
      headers: this.getHeaders(),
      body: this.body
        ? new Uint8Array(this.body.buffer,
                         this.body.byteOffset,
                         this.body.byteLength)
        : null,
      mode: 'cors',
      credentials: 'include',
      cache: 'no-cache',
      redirect: 'follow',
      referrer: 'no-referrer'
    };
  }
}

class Response {
  /**
   * Response
   * @constructor
   * @ignore
   */

  constructor() {
    this.statusCode = 0;
    this.headers = Object.create(null);
    this.type = 'bin';
    this.str = '';
    this.buf = null;
  }

  text() {
    if (!this.buf)
      return this.str;
    return this.buf.toString('utf8');
  }

  buffer() {
    if (!this.buf)
      return Buffer.from(this.str, 'utf8');
    return this.buf;
  }

  json() {
    const text = this.text().trim();

    if (text.length === 0)
      return Object.create(null);

    const body = JSON.parse(text);

    if (!body || typeof body !== 'object')
      throw new Error('JSON body is a non-object.');

    return body;
  }

  form() {
    return qs.parse(this.text());
  }

  static fromFetch(response) {
    const res = new Response();

    res.statusCode = response.status;

    for (const [key, value] of response.headers.entries())
      res.headers[key.toLowerCase()] = value;

    return res;
  }
}

/**
 * Make an HTTP request.
 * @private
 * @param {Object} options
 * @returns {Promise}
 */

async function _request(options, buffer) {
  if (typeof fetch !== 'function')
    throw new Error('Fetch API not available.');

  const opt = new RequestOptions(options, buffer);
  const response = await fetch(opt.toURL(), opt.toHTTP());
  const res = Response.fromFetch(response);
  const type = mime.ext(res.headers['content-type']);
  const length = res.headers['content-length'];

  if (!opt.isExpected(type))
    throw new Error('Wrong content-type for response.');

  if (opt.isOverflow(length))
    throw new Error('Response exceeded limit.');

  res.type = type;

  if (mime.textual(type)) {
    const data = await response.text();

    if (opt.limit && data.length > opt.limit)
      throw new Error('Response exceeded limit.');

    res.str = data;
  } else {
    const data = await response.arrayBuffer();

    if (opt.limit && data.byteLength > opt.limit)
      throw new Error('Response exceeded limit.');

    res.buf = Buffer.from(data, 0, data.byteLength);
  }

  return res;
}

/**
 * Make an HTTP request.
 * @param {Object} options
 * @returns {Promise}
 */

async function request(options) {
  if (typeof options === 'string')
    options = { url: options };

  return _request(options, true);
}

request.stream = function stream(options) {
  if (typeof options === 'string')
    options = { url: options };

  const s = new EventEmitter();
  const body = [];

  s.write = (data, enc) => {
    if (!Buffer.isBuffer(data)) {
      assert(typeof data === 'string');
      data = Buffer.from(data, enc);
    }
    body.push(data);
    return true;
  };

  s.end = () => {
    options.extra = Buffer.concat(body);
    _request(options, false).then((res) => {
      s.emit('headers', res.headers);
      s.emit('type', res.type);
      s.emit('response', res);
      s.emit('data', res.buffer());
      s.emit('end');
      s.emit('close');
    }).catch((err) => {
      s.emit('error', err);
    });
    return true;
  };

  return s;
};

/*
 * Expose
 */

module.exports = request;
