/*!
 * wallet/index.js - wallet for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module wallet
 */

exports.Account = require('./account');
exports.Client = require('./client');
exports.common = require('./common');
exports.HTTP = require('./http');
exports.layout = require('./layout');
exports.MasterKey = require('./masterkey');
exports.NodeClient = require('./nodeclient');
exports.Path = require('./path');
exports.plugin = require('./plugin');
exports.records = require('./records');
exports.RPC = require('./rpc');
exports.Node = require('./node');
exports.TXDB = require('./txdb');
exports.WalletDB = require('./walletdb');
exports.Wallet = require('./wallet');
exports.WalletKey = require('./walletkey');
