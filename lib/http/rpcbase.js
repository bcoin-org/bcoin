/*!
 * rpcbase.js - json rpc for bcoin.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var EventEmitter = require('events').EventEmitter;
var util = require('../utils/util');
var co = require('../utils/co');
var Lock = require('../utils/lock');
var Logger = require('../node/logger');

/**
 * JSON RPC
 * @alias module:http.RPCBase
 * @constructor
 */

function RPCBase() {
  if (!(this instanceof RPCBase))
    return new RPCBase();

  EventEmitter.call(this);

  this.logger = Logger.global;
  this.calls = {};
  this.mounts = [];
  this.locker = new Lock();
}

util.inherits(RPCBase, EventEmitter);

/**
 * RPC errors.
 * @enum {Number}
 * @default
 */

RPCBase.errors = {
  // Standard JSON-RPC 2.0 errors
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  PARSE_ERROR: -32700,

  // General application defined errors
  MISC_ERROR: -1,
  FORBIDDEN_BY_SAFE_MODE: -2,
  TYPE_ERROR: -3,
  INVALID_ADDRESS_OR_KEY: -5,
  OUT_OF_MEMORY: -7,
  INVALID_PARAMETER: -8,
  DATABASE_ERROR: -20,
  DESERIALIZATION_ERROR: -22,
  VERIFY_ERROR: -25,
  VERIFY_REJECTED: -26,
  VERIFY_ALREADY_IN_CHAIN: -27,
  IN_WARMUP: -28,

  // Aliases for backward compatibility
  TRANSACTION_ERROR: -25,
  TRANSACTION_REJECTED: -26,
  TRANSACTION_ALREADY_IN_CHAIN: -27,

  // P2P client errors
  CLIENT_NOT_CONNECTED: -9,
  CLIENT_IN_INITIAL_DOWNLOAD: -10,
  CLIENT_NODE_ALREADY_ADDED: -23,
  CLIENT_NODE_NOT_ADDED: -24,
  CLIENT_NODE_NOT_CONNECTED: -29,
  CLIENT_INVALID_IP_OR_SUBNET: -30,
  CLIENT_P2P_DISABLED: -31,

  // Wallet errors
  WALLET_ERROR: -4,
  WALLET_INSUFFICIENT_FUNDS: -6,
  WALLET_INVALID_ACCOUNT_NAME: -11,
  WALLET_KEYPOOL_RAN_OUT: -12,
  WALLET_UNLOCK_NEEDED: -13,
  WALLET_PASSPHRASE_INCORRECT: -14,
  WALLET_WRONG_ENC_STATE: -15,
  WALLET_ENCRYPTION_FAILED: -16,
  WALLET_ALREADY_UNLOCKED: -17
};

/**
 * Magic string for signing.
 * @const {String}
 * @default
 */

RPCBase.MAGIC_STRING = 'Bitcoin Signed Message:\n';

/**
 * Execute batched RPC calls.
 * @param {Object|Object[]} body
 * @param {Object} query
 * @returns {Promise}
 */

RPCBase.prototype.call = co(function* call(body, query) {
  var cmds = body;
  var out = [];
  var array = true;
  var i, cmd, result;

  if (!Array.isArray(cmds)) {
    cmds = [cmds];
    array = false;
  }

  for (i = 0; i < cmds.length; i++) {
    cmd = cmds[i];

    assert(cmd && typeof cmd === 'object', 'Command must be an object.');
    assert(typeof cmd.method === 'string', 'Method must be a string.');

    if (!cmd.params)
      cmd.params = [];

    assert(Array.isArray(cmd.params), 'Params must be an array.');

    assert(!cmd.id || typeof cmd.id !== 'object', 'Invalid ID.');
  }

  for (i = 0; i < cmds.length; i++) {
    cmd = cmds[i];

    if (cmd.method !== 'getwork'
        && cmd.method !== 'getblocktemplate'
        && cmd.method !== 'getbestblockhash') {
      this.logger.debug('Handling RPC call: %s.', cmd.method);
      if (cmd.method !== 'submitblock'
          && cmd.method !== 'getmemorypool') {
        this.logger.debug(cmd.params);
      }
    }

    if (cmd.method === 'getwork') {
      if (query.longpoll)
        cmd.method = 'getworklp';
    }

    try {
      result = yield this.execute(cmd);
    } catch (err) {
      if (err.type === 'RPCError') {
        out.push({
          result: null,
          error: {
            message: err.message,
            code: -1
          },
          id: cmd.id
        });
        continue;
      }

      this.logger.error(err);

      out.push({
        result: null,
        error: {
          message: err.message,
          code: 1
        },
        id: cmd.id
      });

      continue;
    }

    if (result === undefined)
      result = null;

    out.push({
      result: result,
      error: null,
      id: cmd.id
    });
  }

  if (!array)
    out = out[0];

  return out;
});

/**
 * Execute an RPC call.
 * @private
 * @param {Object} json
 * @param {Boolean} help
 * @returns {Promise}
 */

RPCBase.prototype.execute = co(function* execute(json, help) {
  var func = this.calls[json.method];
  var i, mount;

  if (!func) {
    for (i = 0; i < this.mounts.length; i++) {
      mount = this.mounts[i];
      if (mount.calls[json.method])
        return yield mount.execute(json, help);
    }
    throw new RPCError('Method not found: ' + json.method + '.');
  }

  return yield func.call(this, json.params, help);
});

/**
 * Add a custom RPC call.
 * @param {String} name
 * @param {Function} func
 */

RPCBase.prototype.add = function add(name, func) {
  assert(typeof func === 'function', 'Handler must be a function.');
  assert(!this.calls[name], 'Duplicate RPC call.');
  this.calls[name] = func;
};

/**
 * Mount another RPC object.
 * @param {Object} rpc
 */

RPCBase.prototype.mount = function mount(rpc) {
  assert(rpc, 'RPC must be an object.');
  assert(typeof rpc.execute === 'function', 'Execute must be a method.');
  this.mounts.push(rpc);
};

/**
 * Attach to another RPC object.
 * @param {Object} rpc
 */

RPCBase.prototype.attach = function attach(rpc) {
  assert(rpc, 'RPC must be an object.');
  assert(typeof rpc.execute === 'function', 'Execute must be a method.');
  rpc.mount(this);
};

/**
 * RPC Error
 * @constructor
 * @ignore
 */

function RPCError(msg, code) {
  Error.call(this);

  if (Error.captureStackTrace)
    Error.captureStackTrace(this, RPCError);

  this.type = 'RPCError';
  this.message = msg;
  this.code = code != null ? code : -1;
}

util.inherits(RPCError, Error);

/*
 * Expose
 */

exports = RPCBase;
exports.RPCError = RPCError;

module.exports = exports;
