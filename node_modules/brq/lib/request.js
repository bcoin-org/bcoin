/*!
 * request.js - http request for brq
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/brq
 */

'use strict';

const assert = require('bsert');
const {Stream} = require('stream');
const mime = require('./mime');

/*
 * Lazily Loaded
 */

let URL = null;
let qs = null;
let http = null;
let https = null;
let StringDecoder = null;

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
    this.strictSSL = true;
    this.pool = false;
    this.agent = 'brq';
    this.lookup = null;

    this.type = null;
    this.expect = null;
    this.body = null;
    this.username = '';
    this.password = '';
    this.limit = 20 << 20;
    this.maxRedirects = 5;
    this.timeout = 5000;
    this.buffer = buffer || false;
    this.headers = Object.create(null);

    // Hack
    ensureRequires();

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

    if (options.strictSSL != null) {
      assert(typeof options.strictSSL === 'boolean');
      this.strictSSL = options.strictSSL;
    }

    if (options.pool != null) {
      assert(typeof options.pool === 'boolean');
      this.pool = options.pool;
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

    if (options.timeout != null) {
      assert(typeof options.timeout === 'number');
      this.timeout = options.timeout;
    }

    if (options.limit != null) {
      assert(typeof options.limit === 'number');
      this.limit = options.limit;
    }

    if (options.maxRedirects != null) {
      assert(typeof options.maxRedirects === 'number');
      this.maxRedirects = options.maxRedirects;
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

  getBackend() {
    ensureRequires(this.ssl);
    return this.ssl ? https : http;
  }

  getHeaders() {
    const headers = Object.create(null);

    headers['User-Agent'] = this.agent;

    if (this.type)
      headers['Content-Type'] = mime.type(this.type);

    if (this.body)
      headers['Content-Length'] = this.body.length.toString(10);

    if (this.username || this.password) {
      const auth = `${this.username}:${this.password}`;
      const data = Buffer.from(auth, 'utf8');
      headers['Authorization'] = `Basic ${data.toString('base64')}`;
    }

    Object.assign(headers, this.headers);

    return headers;
  }

  redirect(location) {
    assert(typeof location === 'string');

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

    this.navigate(URL.resolve(url, location));

    return this;
  }

  toHTTP() {
    let query = '';

    if (this.query)
      query = '?' + this.query;

    return {
      method: this.method,
      host: this.host,
      port: this.port,
      path: this.path + query,
      headers: this.getHeaders(),
      agent: this.pool ? null : false,
      lookup: this.lookup || undefined,
      rejectUnauthorized: this.strictSSL
    };
  }
}

class Request extends Stream {
  /**
   * Request
   * @constructor
   * @private
   * @param {Object} options
   */

  constructor(options, buffer) {
    super();

    this.options = new RequestOptions(options, buffer);
    this.req = null;
    this.res = null;
    this.statusCode = 0;
    this.headers = Object.create(null);
    this.type = 'bin';
    this.redirects = 0;
    this.timeout = null;
    this.finished = false;

    this.onResponse = this.handleResponse.bind(this);
    this.onData = this.handleData.bind(this);
    this.onEnd = this.handleEnd.bind(this);

    this.total = 0;
    this.decoder = null;
    this.buf = [];
    this.str = '';
  }

  startTimeout() {
    if (!this.options.timeout)
      return;

    this.timeout = setTimeout(() => {
      this.finish(new Error('Request timed out.'));
    }, this.options.timeout);
  }

  stopTimeout() {
    if (this.timeout != null) {
      clearTimeout(this.timeout);
      this.timeout = null;
    }
  }

  cleanup() {
    this.stopTimeout();

    if (this.req) {
      this.req.removeListener('response', this.onResponse);
      this.req.removeListener('error', this.onEnd);
      this.req.addListener('error', () => {});
    }

    if (this.res) {
      this.res.removeListener('data', this.onData);
      this.res.removeListener('error', this.onEnd);
      this.res.removeListener('end', this.onEnd);
      this.res.addListener('error', () => {});
    }
  }

  close() {
    if (this.req) {
      try {
        this.req.abort();
      } catch (e) {
        ;
      }
    }

    if (this.res) {
      try {
        this.res.destroy();
      } catch (e) {
        ;
      }
    }

    this.cleanup();

    this.req = null;
    this.res = null;
  }

  destroy() {
    this.close();
  }

  start() {
    const http = this.options.getBackend();
    const options = this.options.toHTTP();

    this.startTimeout();

    this.req = http.request(options);
    this.res = null;

    if (this.options.body)
      this.req.write(this.options.body);

    this.req.on('response', this.onResponse);
    this.req.on('error', this.onEnd);
  }

  write(data) {
    return this.req.write(data);
  }

  end() {
    return this.req.end();
  }

  finish(err) {
    if (this.finished)
      return;

    this.finished = true;

    if (err) {
      this.destroy();
      this.emit('error', err);
      return;
    }

    this.cleanup();
    this.emit('end');
    this.emit('close');
  }

  handleResponse(res) {
    const {headers} = res;
    const location = headers['location'];

    if (location) {
      if (this.redirects >= this.options.maxRedirects) {
        this.finish(new Error('Too many redirects.'));
        return;
      }

      this.redirects += 1;
      this.close();

      try {
        this.options.redirect(location);
      } catch (e) {
        this.finish(e);
        return;
      }

      this.start();
      this.end();

      return;
    }

    const type = mime.ext(headers['content-type']);

    if (!this.options.isExpected(type)) {
      this.finish(new Error('Wrong content-type for response.'));
      return;
    }

    const length = headers['content-length'];

    if (this.options.isOverflow(length)) {
      this.finish(new Error('Response exceeded limit.'));
      return;
    }

    this.res = res;
    this.statusCode = res.statusCode;
    this.headers = headers;
    this.type = type;

    this.res.on('data', this.onData);
    this.res.on('error', this.onEnd);
    this.res.on('end', this.onEnd);

    this.emit('headers', headers);
    this.emit('type', type);
    this.emit('response', res);

    if (this.options.buffer) {
      if (mime.textual(this.type)) {
        this.decoder = new StringDecoder('utf8');
        this.str = '';
      } else {
        this.buf = [];
      }
    }
  }

  handleData(data) {
    this.total += data.length;

    this.emit('data', data);

    if (this.options.buffer) {
      if (this.options.limit) {
        if (this.total > this.options.limit) {
          this.finish(new Error('Response exceeded limit.'));
          return;
        }
      }

      if (this.decoder) {
        this.str += this.decoder.write(data);
        return;
      }

      this.buf.push(data);
    }
  }

  handleEnd(err) {
    this.finish(err);
  }

  text() {
    if (this.decoder)
      return this.str;
    return this.buffer().toString('utf8');
  }

  buffer() {
    if (this.decoder)
      return Buffer.from(this.str, 'utf8');
    return Buffer.concat(this.buf);
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
}

/**
 * Make an HTTP request.
 * @param {Object} options
 * @returns {Promise}
 */

function request(options) {
  if (typeof options === 'string')
    options = { url: options };

  return new Promise((resolve, reject) => {
    const req = new Request(options, true);

    req.on('error', err => reject(err));
    req.on('end', () => resolve(req));

    req.start();
    req.end();
  });
}

request.stream = function stream(options) {
  const req = new Request(options, false);
  req.start();
  return req;
};

/*
 * Helpers
 */

function ensureRequires(ssl) {
  if (!URL)
    URL = require('url');

  if (!qs)
    qs = require('querystring');

  if (!http)
    http = require('http');

  if (ssl && !https)
    https = require('https');

  if (!StringDecoder)
    StringDecoder = require('string_decoder').StringDecoder;
}

/*
 * Expose
 */

module.exports = request;
