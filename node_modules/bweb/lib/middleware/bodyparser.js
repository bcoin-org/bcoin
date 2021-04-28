/*!
 * bodyparser.js - body parser for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

const assert = require('bsert');
const {StringDecoder} = require('string_decoder');
const {parseForm} = require('../util');

/**
 * Body parser middleware.
 * @param {Object} options
 * @returns {Function}
 */

function bodyParser(options) {
  const opt = new BodyParserOptions(options);

  return async (req, res) => {
    if (req.hasBody)
      return;

    try {
      req.resume();
      req.body = await parseBody(req, opt);
    } finally {
      req.pause();
    }

    req.hasBody = true;
  };
}

/**
 * Parse request body.
 * @private
 * @param {ServerRequest} req
 * @param {Object} options
 * @returns {Promise}
 */

async function parseBody(req, options) {
  if (req.method === 'GET')
    return Object.create(null);

  const type = options.type || req.type;

  switch (type) {
    case 'json': {
      const data = await readBody(req, options);

      if (!data)
        return Object.create(null);

      const body = JSON.parse(data);

      if (!body || typeof body !== 'object')
        throw new Error('JSON body must be an object.');

      return body;
    }
    case 'form': {
      const data = await readBody(req, options);

      if (!data)
        return Object.create(null);

      return parseForm(data, options.keyLimit);
    }
    default: {
      return Object.create(null);
    }
  }
}

/**
 * Read and buffer request body.
 * @param {ServerRequest} req
 * @param {Object} options
 * @returns {Promise}
 */

function readBody(req, options) {
  return new Promise((resolve, reject) => {
    return bufferBody(req, options, resolve, reject);
  });
}

/**
 * Read and buffer request body.
 * @private
 * @param {ServerRequest} req
 * @param {Object} options
 * @param {Function} resolve
 * @param {Function} reject
 */

function bufferBody(req, options, resolve, reject) {
  const decode = new StringDecoder('utf8');

  let hasData = false;
  let total = 0;
  let body = '';
  let timer = null;

  const cleanup = () => {
    /* eslint-disable */
    req.removeListener('data', onData);
    req.removeListener('error', onError);
    req.removeListener('end', onEnd);

    if (timer != null) {
      clearTimeout(timer);
      timer = null;
    }
    /* eslint-enable */
  };

  const onData = (data) => {
    total += data.length;
    hasData = true;

    if (total > options.bodyLimit) {
      reject(new Error('Request body overflow.'));
      return;
    }

    body += decode.write(data);
  };

  const onError = (err) => {
    cleanup();
    reject(err);
  };

  const onEnd = () => {
    cleanup();

    if (hasData) {
      resolve(body);
      return;
    }

    resolve(null);
  };

  timer = setTimeout(() => {
    cleanup();
    reject(new Error('Request body timed out.'));
  }, options.timeout);

  req.on('data', onData);
  req.on('error', onError);
  req.on('end', onEnd);
}

class BodyParserOptions {
  /**
   * Body Parser Options
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.keyLimit = 100;
    this.bodyLimit = 20 << 20;
    this.type = null;
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

  fromOptions(options) {
    assert(options);

    if (options.keyLimit != null) {
      assert(typeof options.keyLimit === 'number');
      this.keyLimit = options.keyLimit;
    }

    if (options.bodyLimit != null) {
      assert(typeof options.bodyLimit === 'number');
      this.bodyLimit = options.bodyLimit;
    }

    if (options.type != null) {
      assert(typeof options.type === 'string');
      this.type = options.type;
    }

    return this;
  }
}

/*
 * Expose
 */

module.exports = bodyParser;
