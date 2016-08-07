/*!
 * config.js - bcoin configuration
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('./network');
var utils = require('./utils');
var assert = utils.assert;
var fs;

if (!utils.isBrowser)
  fs = require('f' + 's');

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
  var text = {};
  var data = {};
  var prefix;

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
  }

  merge(text, data);

  return text;
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
  options.fast = bool(data.fast);

  // Chain
  options.witness = bool(data.witness);
  options.prune = bool(data.prune);
  options.useCheckpoints = bool(data.usecheckpoints);
  options.coinCache = bool(data.coincache);
  options.indexTX = bool(data.indextx);
  options.indexAddress = bool(data.indexaddress);

  // Mempool
  options.limitFree = bool(data.limitfree);
  options.limitFreeRelay = bool(data.limitfreerelay);
  options.requireStandard = bool(data.requirestandard);
  options.rejectInsaneFees = bool(data.rejectinsanefees);
  options.replaceByFee = bool(data.replacebyfee);

  // Pool
  options.selfish = bool(data.selfish);
  options.headers = bool(data.headers);
  options.compact = bool(data.compact);
  options.bip151 = bool(data.bip151);
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
      key = line.slice(0, eq).trim();
      value = line.slice(eq + 1).trim();
    }

    key = key.replace(/\-/g, '').toLowerCase();

    alias = config.alias.conf[key];
    if (alias)
      key = alias;

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
  var data = {};
  var i, arg, key, value, alias;

  if (!argv)
    argv = process.argv;

  argv = argv.slice();

  while (argv.length) {
    arg = argv.shift();

    if (arg.indexOf('--') === 0) {
      // e.g. --opt
      arg = arg.split('=');
      key = arg[0];

      if (arg.length > 1) {
        // e.g. --opt=val
        value = arg.slice(1).join('=').trim();
      } else {
        value = 'true';
      }

      key = key.replace(/\-/g, '');

      alias = config.alias.arg[key];
      if (alias)
        key = alias;

      if (value.length === 0)
        continue;

      data[key] = value;

      continue;
    }

    if (arg[0] === '-') {
      // e.g. -abc
      arg = arg.substring(1).split('');

      for (i = 0; i < arg.length; i++) {
        key = arg[i].trim();
        alias = config.alias.arg[key];
        if (alias)
          key = alias;
        data[key] = 'true';
      }

      continue;
    }

    // e.g. foo
    if (key) {
      value = arg.trim();

      if (value.length === 0)
        continue;

      data[key] = value;
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

    if (value.length === 0)
      continue;

    data[key] = value;
  }

  return config.parseData(data);
};

/*
 * Helpers
 */

function str(value) {
  if (!value)
    return null;
  return value;
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
}

/*
 * Expose
 */

module.exports = config;
