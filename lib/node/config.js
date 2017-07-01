/*!
 * config.js - configuration parsing for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const path = require('path');
const os = require('os');
const fs = require('../utils/fs');
const HOME = os.homedir ? os.homedir() : '/';

/**
 * Config Parser
 * @alias module:node.Config
 * @constructor
 * @param {String} module - Module name (e.g. `bcoin`).
 */

function Config(module) {
  if (!(this instanceof Config))
    return new Config(module);

  assert(typeof module === 'string');
  assert(module.length > 0);

  this.module = module;
  this.network = 'main';
  this.prefix = path.join(HOME, `.${module}`);

  this.options = Object.create(null);
  this.data = Object.create(null);
  this.env = Object.create(null);
  this.args = Object.create(null);
  this.argv = [];
  this.query = Object.create(null);
  this.hash = Object.create(null);
}

/**
 * Option name aliases.
 * @const {Object}
 */

Config.alias = {
  conf: {},
  env: {
    'seed': 'seeds',
    'node': 'nodes'
  },
  arg: {
    'seed': 'seeds',
    'node': 'nodes',
    'n': 'network'
  }
};

/**
 * Inject options.
 * @param {Object} options
 */

Config.prototype.inject = function inject(options) {
  let keys = Object.keys(options);

  for (let key of keys) {
    let value = options[key];

    switch (key) {
      case 'hash':
      case 'query':
      case 'env':
      case 'argv':
      case 'config':
        continue;
    }

    this.set(key, value);
  }
};

/**
 * Load options from hash, query, env, or args.
 * @param {Object} options
 */

Config.prototype.load = function load(options) {
  if (options.hash)
    this.parseHash(options.hash);

  if (options.query)
    this.parseQuery(options.query);

  if (options.env)
    this.parseEnv(options.env);

  if (options.argv)
    this.parseArg(options.argv);

  this.network = this.getNetwork();
  this.prefix = this.getPrefix();
};

/**
 * Open a config file.
 * @param {String} file - e.g. `bcoin.conf`.
 * @throws on IO error
 */

Config.prototype.open = function open(file) {
  let path, text;

  if (fs.unsupported)
    return;

  path = this.getFile(file);

  try {
    text = fs.readFileSync(path, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT')
      return;
    throw e;
  }

  this.parseConfig(text);

  this.network = this.getNetwork();
  this.prefix = this.getPrefix();
};

/**
 * Set default option.
 * @param {String} key
 * @param {Object} value
 */

Config.prototype.set = function set(key, value) {
  assert(typeof key === 'string', 'Key must be a string.');

  if (value == null)
    return;

  key = key.toLowerCase().replace(/-/g, '');

  this.options[key] = value;
};

/**
 * Test whether a config option is present.
 * @param {String} key
 * @returns {Boolean}
 */

Config.prototype.has = function has(key) {
  if (typeof key === 'number') {
    assert(key >= 0, 'Index must be positive.');
    if (key >= this.argv.length)
      return false;
    return true;
  }

  assert(typeof key === 'string', 'Key must be a string.');

  key = key.toLowerCase().replace(/-/g, '');

  if (this.hash[key] != null)
    return true;

  if (this.query[key] != null)
    return true;

  if (this.args[key] != null)
    return true;

  if (this.env[key] != null)
    return true;

  if (this.data[key] != null)
    return true;

  if (this.options[key] != null)
    return true;

  return false;
};

/**
 * Get a config option.
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Object|null}
 */

Config.prototype.get = function get(key, fallback) {
  let keys, value;

  if (fallback === undefined)
    fallback = null;

  if (Array.isArray(key)) {
    keys = key;
    for (let key of keys) {
      value = this.get(key);
      if (value !== null)
        return value;
    }
    return fallback;
  }

  if (typeof key === 'number') {
    assert(key >= 0, 'Index must be positive.');
    if (key >= this.argv.length)
      return fallback;
    return this.argv[key];
  }

  assert(typeof key === 'string', 'Key must be a string.');

  key = key.toLowerCase().replace(/-/g, '');

  if (this.hash[key] != null)
    return this.hash[key];

  if (this.query[key] != null)
    return this.query[key];

  if (this.args[key] != null)
    return this.args[key];

  if (this.env[key] != null)
    return this.env[key];

  if (this.data[key] != null)
    return this.data[key];

  if (this.options[key] != null)
    return this.options[key];

  return fallback;
};

/**
 * Get a config option (as a string).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {String|null}
 */

Config.prototype.str = function str(key, fallback) {
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string')
    throw new Error(`${key} must be a string.`);

  return value;
};

/**
 * Get a config option (as a number).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Config.prototype.num = function num(key, fallback) {
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (typeof value !== 'number')
      throw new Error(`${key} must be a positive integer.`);
    return value;
  }

  if (!/^\d+$/.test(value))
    throw new Error(`${key} must be a positive integer.`);

  value = parseInt(value, 10);

  if (!isFinite(value))
    throw new Error(`${key} must be a positive integer.`);

  return value;
};

/**
 * Get a config option (as a float).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Config.prototype.flt = function flt(key, fallback) {
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (typeof value !== 'number')
      throw new Error(`${key} must be a float.`);
    return value;
  }

  if (!/^\d*(?:\.\d*)?$/.test(value))
    throw new Error(`${key} must be a float.`);

  value = parseFloat(value);

  if (!isFinite(value))
    throw new Error(`${key} must be a float.`);

  return value;
};

/**
 * Get a value (as a satoshi number or btc string).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Config.prototype.amt = function amt(key, fallback) {
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (typeof value !== 'number')
      throw new Error(`${key} must be an amount.`);
    return value;
  }

  if (!/^\d+(\.\d{0,8})?$/.test(value))
    throw new Error(`${key} must be an amount.`);

  value = parseFloat(value);

  if (!isFinite(value))
    throw new Error(`${key} must be an amount.`);

  value *= 1e8;

  if (value % 1 !== 0 || value < 0 || value > 0x1fffffffffffff)
    throw new Error(`${key} must be an amount (uint64).`);

  return value;
};

/**
 * Get a config option (as a boolean).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Boolean|null}
 */

Config.prototype.bool = function bool(key, fallback) {
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (typeof value !== 'boolean')
      throw new Error(`${key} must be a boolean.`);
    return value;
  }

  if (value === 'true' || value === '1')
    return true;

  if (value === 'false' || value === '0')
    return false;

  throw new Error(`${key} must be a boolean.`);
};

/**
 * Get a config option (as a buffer).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Buffer|null}
 */

Config.prototype.buf = function buf(key, fallback) {
  let value = this.get(key);
  let data;

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (!Buffer.isBuffer(value))
      throw new Error(`${key} must be a buffer.`);
    return value;
  }

  data = Buffer.from(value, 'hex');

  if (data.length !== value.length / 2)
    throw new Error(`${key} must be a hex string.`);

  return data;
};

/**
 * Get a config option (as an array of strings).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {String[]|null}
 */

Config.prototype.array = function array(key, fallback) {
  let value = this.get(key);
  let result, parts;

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (!Array.isArray(value))
      throw new Error(`${key} must be an array.`);
    return value;
  }

  parts = value.trim().split(/\s*,\s*/);
  result = [];

  for (let part of parts) {
    if (part.length === 0)
      continue;

    result.push(part);
  }

  return result;
};

/**
 * Get a config option (as an object).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Object|null}
 */

Config.prototype.obj = function obj(key, fallback) {
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (!value || typeof value !== 'object')
    throw new Error(`${key} must be an object.`);

  return value;
};

/**
 * Get a config option (as a function).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Function|null}
 */

Config.prototype.func = function func(key, fallback) {
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (!value || typeof value !== 'function')
    throw new Error(`${key} must be a function.`);

  return value;
};

/**
 * Get a config option (as a string).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {String|null}
 */

Config.prototype.path = function _path(key, fallback) {
  let value = this.str(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  switch (value[0]) {
    case '~': // home dir
      value = path.join(HOME, value.substring(1));
      break;
    case '@': // prefix
      value = path.join(this.prefix, value.substring(1));
      break;
    default: // cwd
      break;
  }

  return path.normalize(value);
};

/**
 * Get a config option (in MB).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Config.prototype.mb = function mb(key, fallback) {
  let value = this.num(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  return value * 1024 * 1024;
};

/**
 * Grab network type from config data.
 * @private
 * @returns {String}
 */

Config.prototype.getNetwork = function getNetwork() {
  let network = this.str('network');

  if (!network)
    network = 'main';

  assert(isAlpha(network), 'Bad network.');

  return network;
};

/**
 * Grab prefix from config data.
 * @private
 * @returns {String}
 */

Config.prototype.getPrefix = function getPrefix() {
  let prefix = this.str('prefix');
  let network;

  if (prefix) {
    if (prefix[0] === '~')
      prefix = path.join(HOME, prefix.substring(1));
    return prefix;
  }

  prefix = path.join(HOME, `.${this.module}`);
  network = this.str('network');

  if (network) {
    assert(isAlpha(network), 'Bad network.');
    if (network !== 'main')
      prefix = path.join(prefix, network);
  }

  return path.normalize(prefix);
};

/**
 * Grab config filename from config data.
 * @private
 * @param {String} file
 * @returns {String}
 */

Config.prototype.getFile = function getFile(file) {
  let name = this.str('config');

  if (name)
    return name;

  return path.join(this.prefix, file);
};

/**
 * Ensure prefix.
 * @returns {Promise}
 */

Config.prototype.ensure = function ensure() {
  if (fs.unsupported)
    return Promise.resolve();

  return fs.mkdirp(this.prefix);
};

/**
 * Create a file path using `prefix`.
 * @param {String} file
 * @returns {String}
 */

Config.prototype.location = function location(file) {
  return path.join(this.prefix, file);
};

/**
 * Parse config text.
 * @private
 * @param {String} text
 */

Config.prototype.parseConfig = function parseConfig(text) {
  let parts;

  assert(typeof text === 'string', 'Config must be text.');

  text = text.trim();
  parts = text.split(/\n+/);

  for (let line of parts) {
    let key, value, eq, col, alias;

    line = line.trim();

    if (line.length === 0)
      continue;

    if (/^\s*#/.test(line))
      continue;

    eq = line.indexOf('=');
    col = line.indexOf(':');

    if (col !== -1 && (col < eq || eq === -1))
      eq = col;

    if (eq === -1) {
      key = line.trim();
      value = '';
    } else {
      key = line.substring(0, eq).trim();
      value = line.substring(eq + 1).trim();
    }

    key = key.replace(/\-/g, '').toLowerCase();

    alias = Config.alias.conf[key];
    if (alias)
      key = alias;

    if (key.length === 0)
      continue;

    if (value.length === 0)
      continue;

    this.data[key] = value;
  }
};

/**
 * Parse arguments.
 * @private
 * @param {Array?} argv
 */

Config.prototype.parseArg = function parseArg(argv) {
  let key;

  if (!argv || typeof argv !== 'object')
    argv = process.argv;

  assert(Array.isArray(argv));

  for (let i = 2; i < argv.length; i++) {
    let arg = argv[i];
    let value, alias, equals;

    assert(typeof arg === 'string');

    if (arg.indexOf('--') === 0) {
      // e.g. --opt
      arg = arg.split('=');
      key = arg[0];

      if (arg.length > 1) {
        // e.g. --opt=val
        value = arg.slice(1).join('=').trim();
        equals = true;
      } else {
        value = 'true';
        equals = false;
      }

      key = key.replace(/\-/g, '');

      if (key.length === 0)
        continue;

      if (value.length === 0)
        continue;

      alias = Config.alias.arg[key];
      if (alias)
        key = alias;

      this.args[key] = value;

      continue;
    }

    if (arg[0] === '-') {
      // e.g. -abc
      arg = arg.substring(1);

      for (key of arg) {
        alias = Config.alias.arg[key];
        if (alias)
          key = alias;
        this.args[key] = 'true';
        equals = false;
      }

      continue;
    }

    // e.g. foo
    value = arg.trim();

    if (value.length === 0)
      continue;

    if (key && !equals) {
      this.args[key] = value;
      key = null;
    } else {
      this.argv.push(value);
    }
  }
};

/**
 * Parse environment variables.
 * @private
 * @param {Object?} env
 * @returns {Object}
 */

Config.prototype.parseEnv = function parseEnv(env) {
  let prefix = this.module;
  let keys;

  prefix = prefix.toUpperCase();
  prefix = prefix.replace(/-/g, '_');
  prefix += '_';

  if (!env || typeof env !== 'object')
    env = process.env;

  assert(env && typeof env === 'object');

  keys = Object.keys(env);

  for (let key of keys) {
    let value, alias;

    if (key.indexOf(prefix) !== 0)
      continue;

    assert(typeof env[key] === 'string');

    value = env[key].trim();

    key = key.substring(prefix.length);
    key = key.replace(/_/g, '').toLowerCase();

    if (key.length === 0)
      continue;

    if (value.length === 0)
      continue;

    alias = Config.alias.env[key];
    if (alias)
      key = alias;

    this.env[key] = value;
  }
};

/**
 * Parse uri querystring variables.
 * @private
 * @param {String} query
 */

Config.prototype.parseQuery = function parseQuery(query) {
  if (typeof query !== 'string') {
    if (!global.location)
      return {};

    query = global.location.search;

    if (typeof query !== 'string')
      return {};
  }

  return this.parseForm(query, this.query);
};

/**
 * Parse uri hash variables.
 * @private
 * @param {String} hash
 */

Config.prototype.parseHash = function parseHash(hash) {
  if (typeof hash !== 'string') {
    if (!global.location)
      return {};

    hash = global.location.hash;

    if (typeof hash !== 'string')
      return {};
  }

  return this.parseForm(hash, this.hash);
};

/**
 * Parse form-urlencoded variables.
 * @private
 * @param {String} query
 */

Config.prototype.parseForm = function parseForm(query, map) {
  let parts;

  assert(typeof query === 'string');

  if (query.length === 0)
    return;

  if (query[0] === '?' || query[0] === '#')
    query = query.substring(1);

  parts = query.split('&');

  for (let pair of parts) {
    let index = pair.indexOf('=');
    let key, value, alias;

    if (index === -1) {
      key = pair;
      value = '';
    } else {
      key = pair.substring(0, index);
      value = pair.substring(index + 1);
    }

    key = unescape(key);
    key = key.replace(/\-/g, '').toLowerCase();

    if (key.length === 0)
      continue;

    value = unescape(value);

    if (value.length === 0)
      continue;

    alias = Config.alias.env[key];
    if (alias)
      key = alias;

    map[key] = value;
  }
};

/*
 * Helpers
 */

function unescape(str) {
  try {
    str = decodeURIComponent(str).replace(/\+/g, ' ');
  } finally {
    return str.replace(/\0/g, '');
  }
}

function isAlpha(str) {
  if (typeof str !== 'string')
    return false;

  if (!/^[a-z0-9]+$/.test(str))
    return false;

  return true;
}

/*
 * Expose
 */

module.exports = Config;
