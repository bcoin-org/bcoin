/*!
 * config.js - bcoin configuration
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('../protocol/network');
var utils = require('../utils/utils');
var assert = utils.assert;
var fs;

if (!utils.isBrowser)
  fs = require('fs');

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
    'seed': 'preferredseed'
  },
  arg: {
    'seed': 'preferredseed'
  }
};

/**
 * Parse options and potentially env, args, and config.
 * @param {Object} options
 * @returns {Object}
 */

config.parse = function parse(options) {
  var env = {};
  var arg = {};
  var data = {};
  var text, prefix;

  if (!options)
    options = {};

  if (options.env)
    env = config.parseEnv();

  if (options.arg)
    arg = config.parseArg();

  merge(data, options);
  merge(data, env);
  merge(data, arg);

  if (data.config) {
    if (typeof data.config === 'string') {
      text = config.parseFile(data.config);
    } else {
      prefix = config.getPrefix(data);
      text = config.parseFile(prefix + '/bcoin.conf');
    }

    data = merge(text, data);
    prefix = config.getPrefix(data);

    if (!data.knownPeers)
      data.knownPeers = config.parseKnown(prefix + '/known-peers');

    if (!data.authPeers)
      data.authPeers = config.parseAuth(prefix + '/authorized-peers');
  }

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
    prefix = utils.HOME + '/.bcoin';

  network = Network.get(data.network).type;

  prefix = utils.normalize(prefix);

  if (network !== 'main')
    prefix += '/' + network;

  return prefix;
};

/**
 * Enforce types on parsed data.
 * @param {Object} data
 */

config.parseData = function parseData(data) {
  var options = {};

  // Config
  options.config = path(data.config);

  // Options
  options.network = str(data.network);
  options.useWorkers = bool(data.useworkers);
  options.maxWorkers = num(data.maxworkers);
  options.workerTimeout = num(data.workertimeout);
  options.sigcacheSize = num(data.sigcachesize);

  // Logger
  options.logLevel = str(data.loglevel);
  options.logConsole = bool(data.logconsole);
  options.logFile = boolpath(data.logfile);

  // Node
  options.prefix = path(data.prefix);
  options.db = str(data.db);
  options.maxFiles = num(data.maxfiles);
  options.fast = bool(data.fast);

  // Chain
  options.witness = bool(data.witness);
  options.prune = bool(data.prune);
  options.useCheckpoints = bool(data.usecheckpoints);
  options.coinCache = bool(data.coincache);
  options.indexTX = bool(data.indextx);
  options.indexAddress = bool(data.indexaddress);
  options.noScan = bool(data.noscan);

  // Mempool
  options.limitFree = bool(data.limitfree);
  options.limitFreeRelay = bool(data.limitfreerelay);
  options.requireStandard = bool(data.requirestandard);
  options.rejectAbsurdFees = bool(data.rejectabsurdfees);
  options.replaceByFee = bool(data.replacebyfee);

  // Pool
  options.selfish = bool(data.selfish);
  options.headers = bool(data.headers);
  options.compact = bool(data.compact);
  options.bip151 = bool(data.bip151);
  options.bip150 = bool(data.bip150);
  options.identityKey = key(data.identitykey);
  options.proxyServer = str(data.proxyserver);
  options.preferredSeed = str(data.preferredseed);
  options.maxPeers = num(data.maxpeers);
  options.maxLeeches = num(data.maxleeches);
  options.ignoreDiscovery = bool(data.ignorediscovery);
  options.port = num(data.port);
  options.listen = bool(data.listen);

  // Miner
  options.payoutAddress = str(data.payoutaddress);
  options.coinbaseFlags = str(data.coinbaseflags);
  options.parallel = bool(data.parallel);

  // HTTP
  options.sslCert = file(data.sslcert);
  options.sslKey = file(data.sslkey);
  options.httpPort = num(data.httpport);
  options.httpHost = str(data.httphost);
  options.apiKey = str(data.apikey);
  options.walletAuth = bool(data.walletauth);
  options.noAuth = bool(data.noauth);

  options.data = data;

  return options;
};

/**
 * Parse config file.
 * @param {String} file
 * @returns {Object}
 */

config.parseFile = function parseFile(file) {
  return config.parseText(readFile(file));
};

/**
 * Parse known peers file.
 * @param {String} file
 * @returns {Object}
 */

config.parseKnown = function parseKnown(file) {
  return config.parseKnownText(readFile(file));
};

/**
 * Parse authorized peers file.
 * @param {String} file
 * @returns {Object}
 */

config.parseAuth = function parseAuth(file) {
  return config.parseAuthText(readFile(file));
};

/**
 * Parse config text.
 * @param {String} text
 * @returns {Object}
 */

config.parseText = function parseText(text) {
  var data = {};
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
      value = null;
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

  return config.parseData(data);
};

/**
 * Parse arguments.
 * @param {Array?} argv
 * @returns {Object}
 */

config.parseArg = function parseArg(argv) {
  var data = { args: [] };
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

      alias = config.alias.arg[key];
      if (alias)
        key = alias;

      if (value.length === 0)
        continue;

      if (key.length === 0)
        continue;

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
      data.args.push(value);
    }
  }

  return config.parseData(data);
};

/**
 * Parse environment variables.
 * @param {Object} env
 * @returns {Object}
 */

config.parseEnv = function parseEnv(env) {
  var data = {};
  var i, keys, key, value, alias;

  if (!env)
    env = process.env;

  keys = Object.keys(env);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];

    if (key.indexOf('BCOIN_') !== 0)
      continue;

    value = env[key].trim();

    key = key.substring(6);
    key = key.replace(/_/g, '').toLowerCase();

    alias = config.alias.env[key];
    if (alias)
      key = alias;

    if (key.length === 0)
      continue;

    if (value.length === 0)
      continue;

    data[key] = value;
  }

  return config.parseData(data);
};

/**
 * Parse known peers.
 * @param {String} text
 * @returns {Object}
 */

config.parseKnownText = function parseKnownText(text) {
  var lines = text.split(/\n+/);
  var map = {};
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

config.parseAuthText = function parseAuthText(text) {
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

function path(value) {
  if (!value)
    return null;
  return utils.normalize(value.replace(/^~/, utils.HOME));
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

function boolpath(value) {
  if (!value)
    return null;

  if (value === 'true' || value === '1')
    return true;

  if (value === 'false' || value === '0')
    return false;

  return path(value);
}

function file(value) {
  if (!fs)
    return null;

  value = path(value);

  if (!value)
    return null;

  return fs.readFileSync(value);
}

function readFile(file) {
  if (!fs)
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

/*
 * Expose
 */

module.exports = config;
