/*!
 * config.js - bcoin configuration
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('../protocol/network');
var util = require('../utils/util');
var assert = require('assert');
var fs = require('fs');
var global = util.global;

/**
 * @exports config
 */

function config(options) {
  return config.parse(options);
}

/**
 * Option name aliases.
 * @const {Object}
 */

config.alias = {
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
 * Parse options and potentially env, args, and config.
 * @param {Object} options
 * @returns {Object}
 */

config.parse = function parse(options) {
  var data = Object.create(null);
  var raw = Object.create(null);
  var arg, conf, prefix, filename, dirname;

  if (!options)
    options = {};

  merge(data, options);

  if (options.env) {
    arg = config.parseEnv();
    merge(raw, arg.data);
    merge(data, arg);
  }

  if (options.arg) {
    arg = config.parseArg();
    merge(raw, arg.data);
    merge(data, arg);
  }

  if (options.query) {
    arg = config.parseQuery();
    merge(raw, arg.data);
    merge(data, arg);
  }

  if (options.hash) {
    arg = config.parseHash();
    merge(raw, arg.data);
    merge(data, arg);
  }

  if (data.config && !util.isBrowser) {
    prefix = config.getPrefix(data);
    filename = data.config;

    if (typeof filename !== 'string')
      filename = resolve(prefix, 'bcoin.conf');

    dirname = util.normalize(filename, true);
    conf = config.readConfig(filename, prefix, dirname);
    raw = merge(conf.data, raw);
    data = merge(conf, data);

    prefix = config.getPrefix(data);

    if (!data.knownPeers) {
      filename = resolve(prefix, 'known-peers');
      data.knownPeers = config.readKnown(filename);
    }

    if (!data.authPeers) {
      filename = resolve(prefix, 'authorized-peers');
      data.authPeers = config.readAuth(filename);
    }
  }

  data.data = raw;

  // Force fast properties
  // after all those merges.
  util.fastProp(data);

  return data;
};

/**
 * Grab prefix from env, args, and options.
 * @param {Object} env
 * @param {Object} arg
 * @param {Object} options
 */

config.getPrefix = function getPrefix(data) {
  var prefix = data.prefix;
  var network;

  if (!prefix)
    prefix = util.HOME + '/.bcoin';

  network = Network.get(data.network).type;

  prefix = util.normalize(prefix);

  if (network !== 'main')
    prefix += '/' + network;

  return prefix;
};

/**
 * Enforce types on parsed data.
 * @param {Object} data
 */

config.parseData = function parseData(data, prefix, dirname) {
  var options = {};

  // Config
  options.config = path(data.config);

  // Options
  options.network = str(data.network);
  options.useWorkers = bool(data.useworkers);
  options.maxWorkers = num(data.maxworkers);
  options.workerTimeout = num(data.workertimeout);
  options.sigcacheSize = num(data.sigcachesize);

  // Node
  options.prefix = path(data.prefix, null, dirname);
  options.db = str(data.db);
  options.maxFiles = num(data.maxfiles);
  options.cacheSize = mul(data.cachesize, 1024 * 1024);
  options.fast = bool(data.fast);

  // Update the prefix if we're using one.
  if (prefix && options.prefix)
    prefix = config.getPrefix(options);

  // Logger
  options.logLevel = str(data.loglevel);
  options.logConsole = bool(data.logconsole);
  options.logFile = boolpath(data.logfile, prefix, dirname);

  // Chain
  options.forceWitness = bool(data.forcewitness);
  options.prune = bool(data.prune);
  options.checkpoints = bool(data.checkpoints);
  options.coinCache = mul(data.coincache, 1024 * 1024);
  options.indexTX = bool(data.indextx);
  options.indexAddress = bool(data.indexaddress);

  // Mempool
  options.limitFree = bool(data.limitfree);
  options.limitFreeRelay = bool(data.limitfreerelay);
  options.requireStandard = bool(data.requirestandard);
  options.rejectAbsurdFees = bool(data.rejectabsurdfees);
  options.replaceByFee = bool(data.replacebyfee);

  // Pool
  options.selfish = bool(data.selfish);
  options.compact = bool(data.compact);
  options.bip151 = bool(data.bip151);
  options.bip150 = bool(data.bip150);
  options.identityKey = key(data.identitykey);
  options.proxyServer = str(data.proxyserver);
  options.seeds = list(data.seeds);
  options.nodes = list(data.nodes);
  options.maxOutbound = num(data.maxoutbound);
  options.maxInbound = num(data.maxinbound);
  options.publicHost = str(data.publichost);
  options.publicPort = num(data.publicport);
  options.host = str(data.host);
  options.port = num(data.port);
  options.listen = bool(data.listen);
  options.knownPeers = file(data.knownpeers, prefix, dirname, 'utf8');
  options.authPeers = file(data.authpeers, prefix, dirname, 'utf8');

  // Miner
  options.payoutAddress = list(data.payoutaddress);
  options.coinbaseFlags = str(data.coinbaseflags);

  // HTTP
  options.sslCert = file(data.sslcert, prefix, dirname);
  options.sslKey = file(data.sslkey, prefix, dirname);
  options.httpPort = num(data.httpport);
  options.httpHost = str(data.httphost);
  options.apiKey = str(data.apikey);
  options.serviceKey = str(data.servicekey);
  options.walletAuth = bool(data.walletauth);
  options.noAuth = bool(data.noauth);

  // Wallet
  options.startHeight = num(data.startheight);
  options.wipeNoReally = bool(data.wipenoreally);

  options.data = data;

  if (options.knownPeers != null)
    options.knownPeers = config.parseKnown(options.knownPeers);

  if (options.authPeers != null)
    options.authPeers = config.parseAuth(options.authPeers);

  return options;
};

/**
 * Parse config file.
 * @param {String} file
 * @returns {Object}
 */

config.readConfig = function readConfig(file, prefix, dirname) {
  return config.parseConfig(readFile(file), prefix, dirname);
};

/**
 * Parse known peers file.
 * @param {String} file
 * @returns {Object}
 */

config.readKnown = function readKnown(file) {
  return config.parseKnown(readFile(file));
};

/**
 * Parse authorized peers file.
 * @param {String} file
 * @returns {Object}
 */

config.readAuth = function readAuth(file) {
  return config.parseAuth(readFile(file));
};

/**
 * Parse config text.
 * @param {String} text
 * @returns {Object}
 */

config.parseConfig = function parseConfig(text, prefix, dirname) {
  var data = Object.create(null);
  var i, parts, line, key, value, eq, col, alias;

  assert(typeof text === 'string', 'Config must be text.');

  text = text.trim();
  parts = text.split(/\n+/);

  for (i = 0; i < parts.length; i++) {
    line = parts[i].trim();

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

    alias = config.alias.conf[key];
    if (alias)
      key = alias;

    if (key.length === 0)
      continue;

    if (value.length === 0)
      continue;

    data[key] = value;
  }

  return config.parseData(data, prefix, dirname);
};

/**
 * Parse arguments.
 * @param {Array?} argv
 * @returns {Object}
 */

config.parseArg = function parseArg(argv) {
  var data = Object.create(null);
  var args = [];
  var i, arg, key, value, alias, equals;

  if (!argv)
    argv = process.argv;

  argv = argv.slice(2);

  while (argv.length) {
    arg = argv.shift();

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

      alias = config.alias.arg[key];
      if (alias)
        key = alias;

      data[key] = value;

      continue;
    }

    if (arg[0] === '-') {
      // e.g. -abc
      arg = arg.substring(1);

      for (i = 0; i < arg.length; i++) {
        key = arg[i];
        alias = config.alias.arg[key];
        if (alias)
          key = alias;
        data[key] = 'true';
        equals = false;
      }

      continue;
    }

    // e.g. foo
    value = arg.trim();

    if (value.length === 0)
      continue;

    if (key && !equals) {
      data[key] = value;
      key = null;
    } else {
      args.push(value);
    }
  }

  data.args = args;

  return config.parseData(data);
};

/**
 * Parse environment variables.
 * @param {Object} env
 * @returns {Object}
 */

config.parseEnv = function parseEnv(env, prefix) {
  var data = Object.create(null);
  var i, keys, key, value, alias;

  if (!env)
    env = process.env;

  if (!prefix)
    prefix = 'BCOIN_';

  keys = Object.keys(env);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];

    if (key.indexOf(prefix) !== 0)
      continue;

    value = env[key].trim();

    key = key.substring(prefix.length);
    key = key.replace(/_/g, '').toLowerCase();

    if (key.length === 0)
      continue;

    if (value.length === 0)
      continue;

    alias = config.alias.env[key];
    if (alias)
      key = alias;

    data[key] = value;
  }

  return config.parseData(data);
};

/**
 * Parse uri querystring variables.
 * @param {String} query
 * @returns {Object}
 */

config.parseQuery = function parseQuery(query) {
  if (query == null) {
    if (!util.isBrowser || !global.location)
      return {};

    query = global.location.search || '';
  }

  return config.parseForm(query);
};

/**
 * Parse uri hash variables.
 * @param {String} hash
 * @returns {Object}
 */

config.parseHash = function parseHash(hash) {
  if (hash == null) {
    if (!util.isBrowser || !global.location)
      return {};

    hash = global.location.hash || '';
  }

  return config.parseForm(hash);
};

/**
 * Parse form-urlencoded variables.
 * @param {String} query
 * @returns {Object}
 */

config.parseForm = function parseForm(query) {
  var data = Object.create(null);
  var i, parts, index, pair, key, value, alias;

  assert(typeof query === 'string');

  if (query.length === 0)
    return data;

  if (query[0] === '?' || query[0] === '#')
    query = query.substring(1);

  parts = query.split('&');

  for (i = 0; i < parts.length; i++) {
    pair = parts[i];
    index = pair.indexOf('=');

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

    alias = config.alias.env[key];
    if (alias)
      key = alias;

    data[key] = value;
  }

  return config.parseData(data);
};

/**
 * Parse known peers.
 * @param {String} text
 * @returns {Object}
 */

config.parseKnown = function parseKnown(text) {
  var lines = text.split(/\n+/);
  var map = Object.create(null);
  var i, line, parts, hostname, host, ip, key;

  for (i = 0; i < lines.length; i++) {
    line = lines[i].trim();

    if (line.length === 0)
      continue;

    if (/^\s*#/.test(line))
      continue;

    parts = line.split(/\s+/);

    if (parts.length < 2)
      continue;

    hostname = parts[0].trim().split(',');

    if (hostname.length >= 2) {
      host = hostname[0];
      ip = hostname[1];
    } else {
      host = null;
      ip = hostname[0];
    }

    key = parts[1].trim();
    key = new Buffer(key, 'hex');

    if (key.length !== 33)
      throw new Error('Invalid key: ' + parts[1]);

    if (host && host.length > 0)
      map[host] = key;

    if (ip.length === 0)
      continue;

    map[ip] = key;
  }

  return map;
};

/**
 * Parse authorized peers.
 * @param {String} text
 * @returns {Buffer[]} keys
 */

config.parseAuth = function parseAuth(text) {
  var lines = text.split(/\n+/);
  var keys = [];
  var i, line, key;

  for (i = 0; i < lines.length; i++) {
    line = lines[i].trim();

    if (line.length === 0)
      continue;

    if (/^\s*#/.test(line))
      continue;

    key = new Buffer(line, 'hex');

    if (key.length !== 33)
      throw new Error('Invalid key: ' + line);

    keys.push(key);
  }

  return keys;
};

/*
 * Helpers
 */

function str(value) {
  if (!value)
    return null;
  return value;
}

function list(value) {
  if (!value)
    return null;

  if (typeof value !== 'string')
    return null;

  return value.trim().split(/\s*,\s*/);
}

function key(value) {
  var key;

  if (!value)
    return null;

  if (typeof value !== 'string')
    return null;

  key = new Buffer(value, 'hex');

  if (key.length !== 32)
    throw new Error('Invalid key: ' + value);

  return key;
}

function path(value, prefix, dirname) {
  if (!value)
    return null;

  switch (value[0]) {
    case '~': // home dir
      value = util.HOME + value.substring(1);
      break;
    case '@': // prefix
      if (prefix)
        value = prefix + value.substring(1);
      break;
    default: // dirname of config, or cwd
      if (dirname)
        value = resolve(dirname, value);
      break;
  }

  return util.normalize(value);
}

function bool(value) {
  if (!value)
    return null;

  if (value === 'true' || value === '1')
    return true;

  if (value === 'false' || value === '0')
    return false;

  return null;
}

function num(value) {
  if (!value)
    return null;

  value = +value;

  if (!isFinite(value))
    return null;

  return value;
}

function mul(value, mult) {
  value = num(value);
  if (value == null)
    return value;
  return value * mult;
}

function boolpath(value, prefix, dirname) {
  if (!value)
    return null;

  if (value === 'true' || value === '1')
    return true;

  if (value === 'false' || value === '0')
    return false;

  return path(value, prefix, dirname);
}

function file(value, prefix, dirname, enc) {
  if (fs.unsupported)
    return null;

  value = path(value, prefix, dirname);

  if (!value)
    return null;

  try {
    return fs.readFileSync(value, enc);
  } catch (e) {
    if (e.code === 'ENOENT')
      return null;
    throw e;
  }
}

function resolve(a, b) {
  if (b[0] === '/')
    return b;
  return util.normalize(a + '/' + b);
}

function readFile(file) {
  if (fs.unsupported)
    return '';

  if (!file)
    return '';

  if (typeof file !== 'string')
    return '';

  try {
    return fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT')
      return '';
    throw e;
  }
}

function merge(a, b) {
  var keys = Object.keys(b);
  var i, key;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    if (b[key] != null)
      a[key] = b[key];
  }

  return a;
}

function unescape(str) {
  try {
    str = decodeURIComponent(str).replace(/\+/g, ' ');
  } finally {
    return str.replace(/\0/g, '');
  }
}

/*
 * Expose
 */

module.exports = config;
