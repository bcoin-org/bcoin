/*!
 * config.js - configuration parsing for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const Path = require('path');
const os = require('os');
const fs = require('./fs');
const HOME = os.homedir ? os.homedir() : '/';

/**
 * Config Parser
 */

class Config {
  /**
   * Create a config.
   * @constructor
   * @param {String} module - Module name (e.g. `bcoin`).
   * @param {Object?} options
   */

  constructor(module, options) {
    assert(typeof module === 'string');
    assert(module.length > 0);

    this.module = module;
    this.prefix = Path.join(HOME, `.${module}`);
    this.suffix = null;
    this.fallback = null;
    this.alias = Object.create(null);

    this.options = Object.create(null);
    this.data = Object.create(null);
    this.env = Object.create(null);
    this.args = Object.create(null);
    this.argv = [];
    this.pass = [];
    this.query = Object.create(null);
    this.hash = Object.create(null);

    if (options)
      this.init(options);
  }

  /**
   * Initialize options.
   * @private
   * @param {Object} options
   */

  init(options) {
    assert(options && typeof options === 'object');

    if (options.suffix != null) {
      assert(typeof options.suffix === 'string');
      this.suffix = options.suffix;
    }

    if (options.fallback != null) {
      assert(typeof options.fallback === 'string');
      this.fallback = options.fallback;
    }

    if (options.alias) {
      assert(typeof options.alias === 'object');
      for (const key of Object.keys(options.alias)) {
        const value = options.alias[key];
        assert(typeof value === 'string');
        this.alias[key] = value;
      }
    }
  }

  /**
   * Inject options.
   * @param {Object} options
   */

  inject(options) {
    for (const key of Object.keys(options)) {
      const value = options[key];

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
  }

  /**
   * Load options from hash, query, env, or args.
   * @param {Object} options
   */

  load(options) {
    if (options.hash)
      this.parseHash(options.hash);

    if (options.query)
      this.parseQuery(options.query);

    if (options.env)
      this.parseEnv(options.env);

    if (options.argv)
      this.parseArg(options.argv);

    this.prefix = this.getPrefix();
  }

  /**
   * Open a config file.
   * @param {String} file - e.g. `bcoin.conf`.
   * @throws on IO error
   */

  open(file) {
    if (fs.unsupported)
      return;

    const path = this.getFile(file);

    let text;
    try {
      text = fs.readFileSync(path, 'utf8');
    } catch (e) {
      if (e.code === 'ENOENT')
        return;
      throw e;
    }

    this.parseConfig(text);

    this.prefix = this.getPrefix();
  }

  /**
   * Create a child config. Filter by plugin name.
   * @param {String} name
   * @returns {Config}
   */

  filter(name) {
    assert(typeof name === 'string');

    const child = new Config(this.module);

    child.prefix = this.prefix;
    child.suffix = this.suffix;
    child.fallback = this.fallback;
    child.argv = this.argv;
    child.pass = this.pass;

    _filter(name, this.env, child.env);
    _filter(name, this.args, child.args);
    _filter(name, this.query, child.query);
    _filter(name, this.hash, child.hash);

    return child;
  }

  /**
   * Set default option.
   * @param {String} key
   * @param {Object} value
   */

  set(key, value) {
    assert(typeof key === 'string', 'Key must be a string.');

    if (value == null)
      return;

    key = key.replace(/-/g, '');
    key = key.toLowerCase();

    this.options[key] = value;
  }

  /**
   * Test whether a config option is present.
   * @param {String} key
   * @returns {Boolean}
   */

  has(key) {
    if (typeof key === 'number') {
      assert(key >= 0, 'Index must be positive.');
      if (key >= this.argv.length)
        return false;
      return true;
    }

    assert(typeof key === 'string', 'Key must be a string.');

    key = key.replace(/-/g, '');
    key = key.toLowerCase();

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
  }

  /**
   * Get a config option.
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Object|null}
   */

  get(key, fallback) {
    if (fallback === undefined)
      fallback = null;

    if (Array.isArray(key)) {
      const keys = key;
      for (const key of keys) {
        const value = this.get(key);
        if (value !== null)
          return value;
      }
      return fallback;
    }

    if (typeof key === 'number') {
      assert(key >= 0, 'Index must be positive.');

      if (key >= this.argv.length)
        return fallback;

      if (this.argv[key] != null)
        return this.argv[key];

      return fallback;
    }

    assert(typeof key === 'string', 'Key must be a string.');

    key = key.replace(/-/g, '');
    key = key.toLowerCase();

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
  }

  /**
   * Get a value's type.
   * @param {String} key
   * @returns {String}
   */

  typeOf(key) {
    const value = this.get(key);

    if (value === null)
      return 'null';

    return typeof value;
  }

  /**
   * Get a config option (as a string).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {String|null}
   */

  str(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (typeof value !== 'string')
      throw new Error(`${fmt(key)} must be a string.`);

    return value;
  }

  /**
   * Get a config option (as an integer).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  int(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (typeof value !== 'string') {
      if (typeof value !== 'number')
        throw new Error(`${fmt(key)} must be an int.`);

      if (!Number.isSafeInteger(value))
        throw new Error(`${fmt(key)} must be an int.`);

      return value;
    }

    if (!/^\-?\d+$/.test(value))
      throw new Error(`${fmt(key)} must be an int.`);

    const num = parseInt(value, 10);

    if (!Number.isSafeInteger(num))
      throw new Error(`${fmt(key)} must be an int.`);

    return num;
  }

  /**
   * Get a config option (as a unsigned integer).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  uint(key, fallback) {
    const value = this.int(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (value < 0)
      throw new Error(`${fmt(key)} must be a uint.`);

    return value;
  }

  /**
   * Get a config option (as a float).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  float(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (typeof value !== 'string') {
      if (typeof value !== 'number')
        throw new Error(`${fmt(key)} must be a float.`);

      if (!isFinite(value))
        throw new Error(`${fmt(key)} must be a float.`);

      return value;
    }

    if (!/^\-?\d*(?:\.\d*)?$/.test(value))
      throw new Error(`${fmt(key)} must be a float.`);

    if (!/\d/.test(value))
      throw new Error(`${fmt(key)} must be a float.`);

    const num = parseFloat(value);

    if (!isFinite(num))
      throw new Error(`${fmt(key)} must be a float.`);

    return num;
  }

  /**
   * Get a config option (as a positive float).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  ufloat(key, fallback) {
    const value = this.float(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (value < 0)
      throw new Error(`${fmt(key)} must be a positive float.`);

    return value;
  }

  /**
   * Get a value (as a fixed number).
   * @param {String} key
   * @param {Number?} exp
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  fixed(key, exp, fallback) {
    const value = this.float(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    try {
      return fromFloat(value, exp || 0);
    } catch (e) {
      throw new Error(`${fmt(key)} must be a fixed number.`);
    }
  }

  /**
   * Get a value (as a positive fixed number).
   * @param {String} key
   * @param {Number?} exp
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  ufixed(key, exp, fallback) {
    const value = this.fixed(key, exp);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (value < 0)
      throw new Error(`${fmt(key)} must be a positive fixed number.`);

    return value;
  }

  /**
   * Get a config option (as a boolean).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Boolean|null}
   */

  bool(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    // Bitcoin Core compat.
    if (typeof value === 'number') {
      if (value === 1)
        return true;

      if (value === 0)
        return false;
    }

    if (typeof value !== 'string') {
      if (typeof value !== 'boolean')
        throw new Error(`${fmt(key)} must be a boolean.`);
      return value;
    }

    if (value === 'true' || value === '1')
      return true;

    if (value === 'false' || value === '0')
      return false;

    throw new Error(`${fmt(key)} must be a boolean.`);
  }

  /**
   * Get a config option (as a buffer).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Buffer|null}
   */

  buf(key, fallback, enc) {
    const value = this.get(key);

    if (!enc)
      enc = 'hex';

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (typeof value !== 'string') {
      if (!Buffer.isBuffer(value))
        throw new Error(`${fmt(key)} must be a buffer.`);
      return value;
    }

    const data = Buffer.from(value, enc);

    if (data.length !== Buffer.byteLength(value, enc))
      throw new Error(`${fmt(key)} must be a ${enc} string.`);

    return data;
  }

  /**
   * Get a config option (as an array of strings).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {String[]|null}
   */

  array(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (typeof value !== 'string') {
      if (!Array.isArray(value))
        throw new Error(`${fmt(key)} must be an array.`);
      return value;
    }

    const parts = value.trim().split(/\s*,\s*/);
    const result = [];

    for (const part of parts) {
      if (part.length === 0)
        continue;

      result.push(part);
    }

    return result;
  }

  /**
   * Get a config option (as an object).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Object|null}
   */

  obj(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (typeof value !== 'object' || Array.isArray(value))
      throw new Error(`${fmt(key)} must be an object.`);

    return value;
  }

  /**
   * Get a config option (as a function).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Function|null}
   */

  func(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (typeof value !== 'function')
      throw new Error(`${fmt(key)} must be a function.`);

    return value;
  }

  /**
   * Get a config option (as a string).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {String|null}
   */

  path(key, fallback) {
    let value = this.str(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (value.length === 0)
      return fallback;

    switch (value[0]) {
      case '~': // home dir
        value = Path.join(HOME, value.substring(1));
        break;
      case '@': // prefix
        value = Path.join(this.prefix, value.substring(1));
        break;
      default: // cwd
        break;
    }

    return Path.normalize(value);
  }

  /**
   * Get a config option (in MB).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  mb(key, fallback) {
    const value = this.uint(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    return value * 1024 * 1024;
  }

  /**
   * Grab suffix from config data.
   * @returns {String}
   */

  getSuffix() {
    if (!this.suffix)
      throw new Error('No suffix presented.');

    const suffix = this.str(this.suffix, this.fallback);

    assert(isAlpha(suffix), 'Bad suffix.');

    return suffix;
  }

  /**
   * Grab prefix from config data.
   * @private
   * @returns {String}
   */

  getPrefix() {
    let prefix = this.str('prefix');

    if (prefix) {
      if (prefix[0] === '~')
        prefix = Path.join(HOME, prefix.substring(1));
    } else {
      prefix = Path.join(HOME, `.${this.module}`);
    }

    if (this.suffix) {
      const suffix = this.str(this.suffix);

      if (suffix) {
        assert(isAlpha(suffix), 'Bad suffix.');
        if (this.fallback && suffix !== this.fallback)
          prefix = Path.join(prefix, suffix);
      }
    }

    return Path.normalize(prefix);
  }

  /**
   * Grab config filename from config data.
   * @private
   * @param {String} file
   * @returns {String}
   */

  getFile(file) {
    const name = this.str('config');

    if (name)
      return name;

    return Path.join(this.prefix, file);
  }

  /**
   * Create a file path using `prefix`.
   * @param {String} file
   * @returns {String}
   */

  location(file) {
    return Path.join(this.prefix, file);
  }

  /**
   * Parse config text.
   * @private
   * @param {String} text
   */

  parseConfig(text) {
    assert(typeof text === 'string', 'Config must be text.');

    if (text.charCodeAt(0) === 0xfeff)
      text = text.substring(1);

    text = text.replace(/\r\n/g, '\n');
    text = text.replace(/\r/g, '\n');
    text = text.replace(/\\\n/g, '');

    let num = 0;

    for (const chunk of text.split('\n')) {
      const line = chunk.trim();

      num += 1;

      if (line.length === 0)
        continue;

      if (line[0] === '#')
        continue;

      const index = line.indexOf(':');

      if (index === -1)
        throw new Error(`Expected ':' on line ${num}: "${line}".`);

      let key = line.substring(0, index).trim();

      key = key.replace(/\-/g, '');

      if (!isLowerKey(key))
        throw new Error(`Invalid option on line ${num}: ${key}.`);

      const value = line.substring(index + 1).trim();

      if (value.length === 0)
        continue;

      const alias = this.alias[key];

      if (alias)
        key = alias;

      this.data[key] = value;
    }
  }

  /**
   * Parse arguments.
   * @private
   * @param {Array?} argv
   */

  parseArg(argv) {
    if (!argv || typeof argv !== 'object')
      argv = process.argv;

    assert(Array.isArray(argv));

    let last = null;
    let pass = false;

    for (let i = 2; i < argv.length; i++) {
      const arg = argv[i];

      assert(typeof arg === 'string');

      if (arg === '--') {
        pass = true;
        continue;
      }

      if (pass) {
        this.pass.push(arg);
        continue;
      }

      if (arg.length === 0) {
        last = null;
        continue;
      }

      if (arg.indexOf('--') === 0) {
        const index = arg.indexOf('=');

        let key = null;
        let value = null;
        let empty = false;

        if (index !== -1) {
          // e.g. --opt=val
          key = arg.substring(2, index);
          value = arg.substring(index + 1);
          last = null;
          empty = false;
        } else {
          // e.g. --opt
          key = arg.substring(2);
          value = 'true';
          last = null;
          empty = true;
        }

        key = key.replace(/\-/g, '');

        if (!isLowerKey(key))
          throw new Error(`Invalid argument: --${key}.`);

        if (value.length === 0)
          continue;

        // Do not allow one-letter aliases.
        if (key.length > 1) {
          const alias = this.alias[key];
          if (alias)
            key = alias;
        }

        this.args[key] = value;

        if (empty)
          last = key;

        continue;
      }

      if (arg[0] === '-') {
        // e.g. -abc
        last = null;

        for (let j = 1; j < arg.length; j++) {
          let key = arg[j];

          if ((key < 'a' || key > 'z')
              && (key < 'A' || key > 'Z')
              && (key < '0' || key > '9')
              && key !== '?') {
            throw new Error(`Invalid argument: -${key}.`);
          }

          const alias = this.alias[key];

          if (alias)
            key = alias;

          this.args[key] = 'true';

          last = key;
        }

        continue;
      }

      // e.g. foo
      const value = arg;

      if (value.length === 0) {
        last = null;
        continue;
      }

      if (last) {
        this.args[last] = value;
        last = null;
      } else {
        this.argv.push(value);
      }
    }
  }

  /**
   * Parse environment variables.
   * @private
   * @param {Object?} env
   * @returns {Object}
   */

  parseEnv(env) {
    let prefix = this.module;

    prefix = prefix.toUpperCase();
    prefix = prefix.replace(/-/g, '_');
    prefix += '_';

    if (!env || typeof env !== 'object')
      env = process.env;

    assert(env && typeof env === 'object');

    for (let key of Object.keys(env)) {
      const value = env[key];

      assert(typeof value === 'string');

      if (key.indexOf(prefix) !== 0)
        continue;

      key = key.substring(prefix.length);
      key = key.replace(/_/g, '');

      if (!isUpperKey(key))
        continue;

      if (value.length === 0)
        continue;

      key = key.toLowerCase();

      // Do not allow one-letter aliases.
      if (key.length > 1) {
        const alias = this.alias[key];
        if (alias)
          key = alias;
      }

      this.env[key] = value;
    }
  }

  /**
   * Parse uri querystring variables.
   * @private
   * @param {String} query
   */

  parseQuery(query) {
    if (typeof query !== 'string') {
      if (!global.location)
        return {};

      query = global.location.search;

      if (typeof query !== 'string')
        return {};
    }

    return this.parseForm(query, '?', this.query);
  }

  /**
   * Parse uri hash variables.
   * @private
   * @param {String} hash
   */

  parseHash(hash) {
    if (typeof hash !== 'string') {
      if (!global.location)
        return {};

      hash = global.location.hash;

      if (typeof hash !== 'string')
        return {};
    }

    return this.parseForm(hash, '#', this.hash);
  }

  /**
   * Parse form-urlencoded variables.
   * @private
   * @param {String} query
   * @param {String} ch
   * @param {Object} map
   */

  parseForm(query, ch, map) {
    assert(typeof query === 'string');

    if (query.length === 0)
      return;

    if (query[0] === ch)
      query = query.substring(1);

    for (const pair of query.split('&')) {
      const index = pair.indexOf('=');

      let key, value;
      if (index !== -1) {
        key = pair.substring(0, index);
        value = pair.substring(index + 1);
      } else {
        key = pair;
        value = 'true';
      }

      key = unescape(key);
      key = key.replace(/\-/g, '');

      if (!isLowerKey(key))
        continue;

      value = unescape(value);

      if (value.length === 0)
        continue;

      const alias = this.alias[key];

      if (alias)
        key = alias;

      map[key] = value;
    }
  }
}

/*
 * Helpers
 */

function fmt(key) {
  if (Array.isArray(key))
    key = key[0];

  if (typeof key === 'number')
    return `Argument #${key}`;

  return key;
}

function unescape(str) {
  try {
    str = decodeURIComponent(str);
    str = str.replace(/\+/g, ' ');
  } catch (e) {
    ;
  }
  str = str.replace(/\0/g, '');
  return str;
}

function isAlpha(str) {
  return /^[a-z0-9_\-]+$/i.test(str);
}

function isKey(key) {
  return /^[a-zA-Z0-9]+$/.test(key);
}

function isLowerKey(key) {
  if (!isKey(key))
    return false;

  return !/[A-Z]/.test(key);
}

function isUpperKey(key) {
  if (!isKey(key))
    return false;

  return !/[a-z]/.test(key);
}

function _filter(name, a, b) {
  for (const key of Object.keys(a)) {
    if (key.length > name.length && key.indexOf(name) === 0) {
      const sub = key.substring(name.length);
      b[sub] = a[key];
    }
  }
}

function fromFloat(num, exp) {
  assert(typeof num === 'number' && isFinite(num));
  assert(Number.isSafeInteger(exp));

  let str = num.toFixed(exp);
  let sign = 1;

  if (str.length > 0 && str[0] === '-') {
    str = str.substring(1);
    sign = -1;
  }

  let hi = str;
  let lo = '0';

  const index = str.indexOf('.');

  if (index !== -1) {
    hi = str.substring(0, index);
    lo = str.substring(index + 1);
  }

  hi = hi.replace(/^0+/, '');
  lo = lo.replace(/0+$/, '');

  assert(hi.length <= 16 - exp,
    'Fixed number string exceeds 2^53-1.');

  assert(lo.length <= exp,
    'Too many decimal places in fixed number string.');

  if (hi.length === 0)
    hi = '0';

  while (lo.length < exp)
    lo += '0';

  if (lo.length === 0)
    lo = '0';

  assert(/^\d+$/.test(hi) && /^\d+$/.test(lo),
    'Non-numeric characters in fixed number string.');

  hi = parseInt(hi, 10);
  lo = parseInt(lo, 10);

  const mult = Math.pow(10, exp);
  const maxLo = Number.MAX_SAFE_INTEGER % mult;
  const maxHi = (Number.MAX_SAFE_INTEGER - maxLo) / mult;

  assert(hi < maxHi || (hi === maxHi && lo <= maxLo),
    'Fixed number string exceeds 2^53-1.');

  return sign * (hi * mult + lo);
}

/*
 * Expose
 */

module.exports = Config;
