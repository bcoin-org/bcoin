/*!
 * rpc.js - bitcoind-compatible json rpc for bcoin.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var fs = require('../utils/fs');
var util = require('../utils/util');
var crypto = require('../crypto/crypto');
var Amount = require('../btc/amount');
var Script = require('../script/script');
var Address = require('../primitives/address');
var KeyRing = require('../primitives/keyring');
var MerkleBlock = require('../primitives/merkleblock');
var MTX = require('../primitives/mtx');
var Outpoint = require('../primitives/outpoint');
var Output = require('../primitives/output');
var TX = require('../primitives/tx');
var encoding = require('../utils/encoding');
var RPCBase = require('../http/rpcbase');
var pkg = require('../pkg');
var Validator = require('../utils/validator');
var common = require('./common');
var RPCError = RPCBase.RPCError;
var errs = RPCBase.errors;
var MAGIC_STRING = RPCBase.MAGIC_STRING;

/**
 * Bitcoin Core RPC
 * @alias module:wallet.RPC
 * @constructor
 * @param {WalletDB} wdb
 */

function RPC(wdb) {
  if (!(this instanceof RPC))
    return new RPC(wdb);

  RPCBase.call(this);

  assert(wdb, 'RPC requires a WalletDB.');

  this.wdb = wdb;
  this.network = wdb.network;
  this.logger = wdb.logger.context('rpc');
  this.client = wdb.client;

  this.wallet = null;
  this.feeRate = null;

  this.init();
}

util.inherits(RPC, RPCBase);

RPC.prototype.init = function init() {
  this.add('help', this.help);
  this.add('stop', this.stop);
  this.add('fundrawtransaction', this.fundRawTransaction);
  this.add('resendwallettransactions', this.resendWalletTransactions);
  this.add('abandontransaction', this.abandonTransaction);
  this.add('addmultisigaddress', this.addMultisigAddress);
  this.add('addwitnessaddress', this.addWitnessAddress);
  this.add('backupwallet', this.backupWallet);
  this.add('dumpprivkey', this.dumpPrivKey);
  this.add('dumpwallet', this.dumpWallet);
  this.add('encryptwallet', this.encryptWallet);
  this.add('getaccountaddress', this.getAccountAddress);
  this.add('getaccount', this.getAccount);
  this.add('getaddressesbyaccount', this.getAddressesByAccount);
  this.add('getbalance', this.getBalance);
  this.add('getnewaddress', this.getNewAddress);
  this.add('getrawchangeaddress', this.getRawChangeAddress);
  this.add('getreceivedbyaccount', this.getReceivedByAccount);
  this.add('getreceivedbyaddress', this.getReceivedByAddress);
  this.add('gettransaction', this.getTransaction);
  this.add('getunconfirmedbalance', this.getUnconfirmedBalance);
  this.add('getwalletinfo', this.getWalletInfo);
  this.add('importprivkey', this.importPrivKey);
  this.add('importwallet', this.importWallet);
  this.add('importaddress', this.importAddress);
  this.add('importprunedfunds', this.importPrunedFunds);
  this.add('importpubkey', this.importPubkey);
  this.add('keypoolrefill', this.keyPoolRefill);
  this.add('listaccounts', this.listAccounts);
  this.add('listaddressgroupings', this.listAddressGroupings);
  this.add('listlockunspent', this.listLockUnspent);
  this.add('listreceivedbyaccount', this.listReceivedByAccount);
  this.add('listreceivedbyaddress', this.listReceivedByAddress);
  this.add('listsinceblock', this.listSinceBlock);
  this.add('listtransactions', this.listTransactions);
  this.add('listunspent', this.listUnspent);
  this.add('lockunspent', this.lockUnspent);
  this.add('move', this.move);
  this.add('sendfrom', this.sendFrom);
  this.add('sendmany', this.sendMany);
  this.add('sendtoaddress', this.sendToAddress);
  this.add('setaccount', this.setAccount);
  this.add('settxfee', this.setTXFee);
  this.add('signmessage', this.signMessage);
  this.add('walletlock', this.walletLock);
  this.add('walletpassphrasechange', this.walletPassphraseChange);
  this.add('walletpassphrase', this.walletPassphrase);
  this.add('removeprunedfunds', this.removePrunedFunds);
  this.add('selectwallet', this.selectWallet);
  this.add('getmemoryinfo', this.getMemoryInfo);
  this.add('setloglevel', this.setLogLevel);
};

RPC.prototype.help = async function _help(args, help) {
  var json;

  if (args.length === 0)
    return 'Select a command.';

  json = {
    method: args[0],
    params: []
  };

  return await this.execute(json, true);
};

RPC.prototype.stop = async function stop(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'stop');

  this.wdb.close();

  return 'Stopping.';
};

RPC.prototype.fundRawTransaction = async function fundRawTransaction(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var options = valid.obj(1);
  var wallet = this.wallet;
  var rate = this.feeRate;
  var change, tx;

  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'fundrawtransaction "hexstring" ( options )');
  }

  if (!data)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid hex string.');

  tx = MTX.fromRaw(data);

  if (tx.outputs.length === 0) {
    throw new RPCError(errs.INVALID_PARAMETER,
      'TX must have at least one output.');
  }

  if (options) {
    valid = new Validator([options]);
    change = valid.str('changeAddress');
    rate = valid.btc('feeRate');

    if (change)
      change = parseAddress(change, this.network);
  }

  options = {
    rate: rate,
    changeAddress: change
  };

  await wallet.fund(tx, options);

  return {
    hex: tx.toRaw().toString('hex'),
    changepos: tx.changeIndex,
    fee: Amount.btc(tx.getFee(), true)
  };
};

/*
 * Wallet
 */

RPC.prototype.resendWalletTransactions = async function resendWalletTransactions(args, help) {
  var wallet = this.wallet;
  var hashes = [];
  var i, tx, txs;

  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'resendwallettransactions');

  txs = await wallet.resend();

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    hashes.push(tx.txid());
  }

  return hashes;
};

RPC.prototype.addMultisigAddress = async function addMultisigAddress(args, help) {
  if (help || args.length < 2 || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'addmultisigaddress nrequired ["key",...] ( "account" )');
  }

  // Impossible to implement in bcoin (no address book).
  throw new Error('Not implemented.');
};

RPC.prototype.addWitnessAddress = async function addWitnessAddress(args, help) {
  if (help || args.length < 1 || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'addwitnessaddress "address"');

  // Unlikely to be implemented.
  throw new Error('Not implemented.');
};

RPC.prototype.backupWallet = async function backupWallet(args, help) {
  var valid = new Validator([args]);
  var dest = valid.str(0);

  if (help || args.length !== 1 || !dest)
    throw new RPCError(errs.MISC_ERROR, 'backupwallet "destination"');

  await this.wdb.backup(dest);

  return null;
};

RPC.prototype.dumpPrivKey = async function dumpPrivKey(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var hash, ring;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'dumpprivkey "bitcoinaddress"');

  hash = parseHash(addr, this.network);
  ring = await wallet.getPrivateKey(hash);

  if (!ring)
    throw new RPCError(errs.MISC_ERROR, 'Key not found.');

  return ring.toSecret();
};

RPC.prototype.dumpWallet = async function dumpWallet(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var file = valid.str(0);
  var time = util.date();
  var i, tip, addr, fmt, str, out, hash, hashes, ring;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'dumpwallet "filename"');

  if (!file)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  tip = await this.wdb.getTip();

  out = [
    util.fmt('# Wallet Dump created by Bcoin %s', pkg.version),
    util.fmt('# * Created on %s', time),
    util.fmt('# * Best block at time of backup was %d (%s).',
      tip.height, util.revHex(tip.hash)),
    util.fmt('# * File: %s', file),
    ''
  ];

  hashes = await wallet.getAddressHashes();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    ring = await wallet.getPrivateKey(hash);

    if (!ring)
      continue;

    addr = ring.getAddress('string');
    fmt = '%s %s label= addr=%s';

    if (ring.branch === 1)
      fmt = '%s %s change=1 addr=%s';

    str = util.fmt(fmt, ring.toSecret(), time, addr);

    out.push(str);
  }

  out.push('');
  out.push('# End of dump');
  out.push('');

  out = out.join('\n');

  if (fs.unsupported)
    return out;

  await fs.writeFile(file, out, 'utf8');

  return null;
};

RPC.prototype.encryptWallet = async function encryptWallet(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var passphrase = valid.str(0, '');

  if (!wallet.master.encrypted && (help || args.length !== 1))
    throw new RPCError(errs.MISC_ERROR, 'encryptwallet "passphrase"');

  if (wallet.master.encrypted) {
    throw new RPCError(errs.WALLET_WRONG_ENC_STATE,
      'Already running with an encrypted wallet.');
  }

  if (passphrase.length < 1)
    throw new RPCError(errs.MISC_ERROR, 'encryptwallet "passphrase"');

  try {
    await wallet.setPassphrase(passphrase);
  } catch (e) {
    throw new RPCError(errs.WALLET_ENCRYPTION_FAILED, 'Encryption failed.');
  }

  return 'wallet encrypted; we do not need to stop!';
};

RPC.prototype.getAccountAddress = async function getAccountAddress(args, help) {
  var valid = new Validator([args]);
  var wallet = this.wallet;
  var name = valid.str(0, '');
  var account;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'getaccountaddress "account"');

  if (!name)
    name = 'default';

  account = await wallet.getAccount(name);

  if (!account)
    return '';

  return account.receive.getAddress('string');
};

RPC.prototype.getAccount = async function getAccount(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var hash, path;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'getaccount "bitcoinaddress"');

  hash = parseHash(addr, this.network);
  path = await wallet.getPath(hash);

  if (!path)
    return '';

  return path.name;
};

RPC.prototype.getAddressesByAccount = async function getAddressesByAccount(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var name = valid.str(0, '');
  var i, path, address, addrs, paths;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'getaddressesbyaccount "account"');

  if (name === '')
    name = 'default';

  addrs = [];

  paths = await wallet.getPaths(name);

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    address = path.toAddress();
    addrs.push(address.toString(this.network));
  }

  return addrs;
};

RPC.prototype.getBalance = async function getBalance(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var name = valid.str(0);
  var minconf = valid.u32(1, 0);
  var watchOnly = valid.bool(2, false);
  var value, balance;

  if (help || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'getbalance ( "account" minconf includeWatchonly )');
  }

  if (name === '')
    name = 'default';

  if (name === '*')
    name = null;

  if (wallet.watchOnly !== watchOnly)
    return 0;

  balance = await wallet.getBalance(name);

  if (minconf > 0)
    value = balance.confirmed;
  else
    value = balance.unconfirmed;

  return Amount.btc(value, true);
};

RPC.prototype.getNewAddress = async function getNewAddress(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var name = valid.str(0);
  var address;

  if (help || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'getnewaddress ( "account" )');

  if (name === '')
    name = 'default';

  address = await wallet.createReceive(name);

  return address.getAddress('string');
};

RPC.prototype.getRawChangeAddress = async function getRawChangeAddress(args, help) {
  var wallet = this.wallet;
  var address;

  if (help || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'getrawchangeaddress');

  address = await wallet.createChange();

  return address.getAddress('string');
};

RPC.prototype.getReceivedByAccount = async function getReceivedByAccount(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var name = valid.str(0);
  var minconf = valid.u32(0, 0);
  var height = this.wdb.state.height;
  var total = 0;
  var filter = {};
  var lastConf = -1;
  var i, j, path, wtx, output, conf, hash, paths, txs;

  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'getreceivedbyaccount "account" ( minconf )');
  }

  if (name === '')
    name = 'default';

  paths = await wallet.getPaths(name);

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    filter[path.hash] = true;
  }

  txs = await wallet.getHistory(name);

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];

    conf = wtx.getDepth(height);

    if (conf < minconf)
      continue;

    if (lastConf === -1 || conf < lastConf)
      lastConf = conf;

    for (j = 0; j < wtx.tx.outputs.length; j++) {
      output = wtx.tx.outputs[j];
      hash = output.getHash('hex');
      if (hash && filter[hash])
        total += output.value;
    }
  }

  return Amount.btc(total, true);
};

RPC.prototype.getReceivedByAddress = async function getReceivedByAddress(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var minconf = valid.u32(1, 0);
  var height = this.wdb.state.height;
  var total = 0;
  var i, j, hash, wtx, output, txs;

  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'getreceivedbyaddress "bitcoinaddress" ( minconf )');
  }

  hash = parseHash(addr, this.network);
  txs = await wallet.getHistory();

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];

    if (wtx.getDepth(height) < minconf)
      continue;

    for (j = 0; j < wtx.tx.outputs.length; j++) {
      output = wtx.tx.outputs[j];
      if (output.getHash('hex') === hash)
        total += output.value;
    }
  }

  return Amount.btc(total, true);
};

RPC.prototype._toWalletTX = async function _toWalletTX(wtx) {
  var wallet = this.wallet;
  var details = await wallet.toDetails(wtx);
  var det = [];
  var sent = 0;
  var received = 0;
  var receive = true;
  var i, member;

  if (!details)
    throw new RPCError(errs.WALLET_ERROR, 'TX not found.');

  for (i = 0; i < details.inputs.length; i++) {
    member = details.inputs[i];
    if (member.path) {
      receive = false;
      break;
    }
  }

  for (i = 0; i < details.outputs.length; i++) {
    member = details.outputs[i];

    if (member.path) {
      if (member.path.branch === 1)
        continue;

      det.push({
        account: member.path.name,
        address: member.address.toString(this.network),
        category: 'receive',
        amount: Amount.btc(member.value, true),
        label: member.path.name,
        vout: i
      });

      received += member.value;

      continue;
    }

    if (receive)
      continue;

    det.push({
      account: '',
      address: member.address
        ? member.address.toString(this.network)
        : null,
      category: 'send',
      amount: -(Amount.btc(member.value, true)),
      fee: -(Amount.btc(details.fee, true)),
      vout: i
    });

    sent += member.value;
  }

  return {
    amount: Amount.btc(receive ? received : -sent, true),
    confirmations: details.confirmations,
    blockhash: details.block ? util.revHex(details.block) : null,
    blockindex: details.index,
    blocktime: details.ts,
    txid: util.revHex(details.hash),
    walletconflicts: [],
    time: details.ps,
    timereceived: details.ps,
    'bip125-replaceable': 'no',
    details: det,
    hex: details.tx.toRaw().toString('hex')
  };
};

RPC.prototype.getTransaction = async function getTransaction(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var watchOnly = valid.bool(1, false);
  var wtx;

  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'gettransaction "txid" ( includeWatchonly )');
  }

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter');

  wtx = await wallet.getTX(hash);

  if (!wtx)
    throw new RPCError(errs.WALLET_ERROR, 'TX not found.');

  return await this._toWalletTX(wtx, watchOnly);
};

RPC.prototype.abandonTransaction = async function abandonTransaction(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var result;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'abandontransaction "txid"');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  result = await wallet.abandon(hash);

  if (!result)
    throw new RPCError(errs.WALLET_ERROR, 'Transaction not in wallet.');

  return null;
};

RPC.prototype.getUnconfirmedBalance = async function getUnconfirmedBalance(args, help) {
  var wallet = this.wallet;
  var balance;

  if (help || args.length > 0)
    throw new RPCError(errs.MISC_ERROR, 'getunconfirmedbalance');

  balance = await wallet.getBalance();

  return Amount.btc(balance.unconfirmed, true);
};

RPC.prototype.getWalletInfo = async function getWalletInfo(args, help) {
  var wallet = this.wallet;
  var balance;

  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getwalletinfo');

  balance = await wallet.getBalance();

  return {
    walletid: wallet.id,
    walletversion: 6,
    balance: Amount.btc(balance.unconfirmed, true),
    unconfirmed_balance: Amount.btc(balance.unconfirmed, true),
    txcount: wallet.txdb.state.tx,
    keypoololdest: 0,
    keypoolsize: 0,
    unlocked_until: wallet.master.until,
    paytxfee: this.feeRate != null
      ? Amount.btc(this.feeRate, true)
      : 0
  };
};

RPC.prototype.importPrivKey = async function importPrivKey(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var secret = valid.str(0);
  var rescan = valid.bool(2, false);
  var key;

  if (help || args.length < 1 || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'importprivkey "bitcoinprivkey" ( "label" rescan )');
  }

  key = parseSecret(secret, this.network);

  await wallet.importKey(0, key);

  if (rescan)
    await this.wdb.rescan(0);

  return null;
};

RPC.prototype.importWallet = async function importWallet(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var file = valid.str(0);
  var rescan = valid.bool(1, false);
  var keys = [];
  var i, lines, line, parts;
  var secret, data, key;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'importwallet "filename" ( rescan )');

  if (fs.unsupported)
    throw new RPCError(errs.INTERNAL_ERROR, 'FS not available.');

  data = await fs.readFile(file, 'utf8');

  lines = data.split(/\n+/);

  for (i = 0; i < lines.length; i++) {
    line = lines[i].trim();

    if (line.length === 0)
      continue;

    if (/^\s*#/.test(line))
      continue;

    parts = line.split(/\s+/);

    if (parts.length < 4)
      throw new RPCError(errs.DESERIALIZATION_ERROR, 'Malformed wallet.');

    secret = parseSecret(parts[0], this.network);

    keys.push(secret);
  }

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    await wallet.importKey(0, key);
  }

  if (rescan)
    await this.wdb.rescan(0);

  return null;
};

RPC.prototype.importAddress = async function importAddress(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var rescan = valid.bool(2, false);
  var p2sh = valid.bool(3, false);
  var script;

  if (help || args.length < 1 || args.length > 4) {
    throw new RPCError(errs.MISC_ERROR,
      'importaddress "address" ( "label" rescan p2sh )');
  }

  if (p2sh) {
    script = valid.buf(0);

    if (!script)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid parameters.');

    script = Script.fromRaw(script);
    script = Script.fromScripthash(script.hash160());

    addr = script.getAddress();
  } else {
    addr = parseAddress(addr, this.network);
  }

  await wallet.importAddress(0, addr);

  if (rescan)
    await this.wdb.rescan(0);

  return null;
};

RPC.prototype.importPubkey = async function importPubkey(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var rescan = valid.bool(2, false);
  var key;

  if (help || args.length < 1 || args.length > 4) {
    throw new RPCError(errs.MISC_ERROR,
      'importpubkey "pubkey" ( "label" rescan )');
  }

  if (!data)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  key = KeyRing.fromPublic(data, this.network);

  await wallet.importKey(0, key);

  if (rescan)
    await this.wdb.rescan(0);

  return null;
};

RPC.prototype.keyPoolRefill = async function keyPoolRefill(args, help) {
  if (help || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'keypoolrefill ( newsize )');
  return null;
};

RPC.prototype.listAccounts = async function listAccounts(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var minconf = valid.u32(0, 0);
  var watchOnly = valid.bool(1, false);
  var map = {};
  var i, accounts, account, balance, value;

  if (help || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'listaccounts ( minconf includeWatchonly)');
  }

  accounts = await wallet.getAccounts();

  for (i = 0; i < accounts.length; i++) {
    account = accounts[i];
    balance = await wallet.getBalance(account);

    value = balance.unconfirmed;

    if (minconf > 0)
      value = balance.confirmed;

    if (wallet.watchOnly !== watchOnly)
      value = 0;

    map[account] = Amount.btc(value, true);
  }

  return map;
};

RPC.prototype.listAddressGroupings = async function listAddressGroupings(args, help) {
  if (help)
    throw new RPCError(errs.MISC_ERROR, 'listaddressgroupings');
  throw new Error('Not implemented.');
};

RPC.prototype.listLockUnspent = async function listLockUnspent(args, help) {
  var wallet = this.wallet;
  var i, outpoints, outpoint, out;

  if (help || args.length > 0)
    throw new RPCError(errs.MISC_ERROR, 'listlockunspent');

  outpoints = wallet.getLocked();
  out = [];

  for (i = 0; i < outpoints.length; i++) {
    outpoint = outpoints[i];
    out.push({
      txid: outpoint.txid(),
      vout: outpoint.index
    });
  }

  return out;
};

RPC.prototype.listReceivedByAccount = async function listReceivedByAccount(args, help) {
  var valid = new Validator([args]);
  var minconf = valid.u32(0, 0);
  var includeEmpty = valid.bool(1, false);
  var watchOnly = valid.bool(2, false);

  if (help || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'listreceivedbyaccount ( minconf includeempty includeWatchonly )');
  }

  return await this._listReceived(minconf, includeEmpty, watchOnly, true);
};

RPC.prototype.listReceivedByAddress = async function listReceivedByAddress(args, help) {
  var valid = new Validator([args]);
  var minconf = valid.u32(0, 0);
  var includeEmpty = valid.bool(1, false);
  var watchOnly = valid.bool(2, false);

  if (help || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'listreceivedbyaddress ( minconf includeempty includeWatchonly )');
  }

  return await this._listReceived(minconf, includeEmpty, watchOnly, false);
};

RPC.prototype._listReceived = async function _listReceived(minconf, empty, watchOnly, account) {
  var wallet = this.wallet;
  var paths = await wallet.getPaths();
  var height = this.wdb.state.height;
  var out = [];
  var result = [];
  var map = {};
  var i, j, path, wtx, output, conf, hash;
  var entry, address, keys, key, item, txs;

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    address = path.toAddress();
    map[path.hash] = {
      involvesWatchonly: wallet.watchOnly,
      address: address.toString(this.network),
      account: path.name,
      amount: 0,
      confirmations: -1,
      label: '',
    };
  }

  txs = await wallet.getHistory();

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];

    conf = wtx.getDepth(height);

    if (conf < minconf)
      continue;

    for (j = 0; j < wtx.tx.outputs.length; j++) {
      output = wtx.tx.outputs[j];
      address = output.getAddress();

      if (!address)
        continue;

      hash = address.getHash('hex');
      entry = map[hash];

      if (entry) {
        if (entry.confirmations === -1 || conf < entry.confirmations)
          entry.confirmations = conf;
        entry.address = address.toString(this.network);
        entry.amount += output.value;
      }
    }
  }

  keys = Object.keys(map);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    entry = map[key];
    out.push(entry);
  }

  if (account) {
    map = {};

    for (i = 0; i < out.length; i++) {
      entry = out[i];
      item = map[entry.account];
      if (!item) {
        map[entry.account] = entry;
        entry.address = undefined;
        continue;
      }
      item.amount += entry.amount;
    }

    out = [];
    keys = Object.keys(map);

    for (i = 0; i < keys.length; i++) {
      key = keys[i];
      entry = map[key];
      out.push(entry);
    }
  }

  for (i = 0; i < out.length; i++) {
    entry = out[i];

    if (!empty && entry.amount === 0)
      continue;

    if (entry.confirmations === -1)
      entry.confirmations = 0;

    entry.amount = Amount.btc(entry.amount, true);
    result.push(entry);
  }

  return result;
};

RPC.prototype.listSinceBlock = async function listSinceBlock(args, help) {
  var wallet = this.wallet;
  var chainHeight = this.wdb.state.height;
  var valid = new Validator([args]);
  var block = valid.hash(0);
  var minconf = valid.u32(1, 0);
  var watchOnly = valid.bool(2, false);
  var height = -1;
  var out = [];
  var i, entry, highest, txs, wtx, json;

  if (help) {
    throw new RPCError(errs.MISC_ERROR,
      'listsinceblock ( "blockhash" target-confirmations includeWatchonly)');
  }

  if (wallet.watchOnly !== watchOnly)
    return out;

  if (block) {
    entry = await this.client.getEntry(block);
    if (entry)
      height = entry.height;
  }

  if (height === -1)
    height = this.chain.height;

  txs = await wallet.getHistory();

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];

    if (wtx.height < height)
      continue;

    if (wtx.getDepth(chainHeight) < minconf)
      continue;

    if (!highest || wtx.height > highest)
      highest = wtx;

    json = await this._toListTX(wtx);

    out.push(json);
  }

  return {
    transactions: out,
    lastblock: highest && highest.block
      ? util.revHex(highest.block)
      : encoding.NULL_HASH
  };
};

RPC.prototype._toListTX = async function _toListTX(wtx) {
  var wallet = this.wallet;
  var details = await wallet.toDetails(wtx);
  var sent = 0;
  var received = 0;
  var receive = true;
  var sendMember, recMember, sendIndex, recIndex;
  var i, member, index;

  if (!details)
    throw new RPCError(errs.WALLET_ERROR, 'TX not found.');

  for (i = 0; i < details.inputs.length; i++) {
    member = details.inputs[i];
    if (member.path) {
      receive = false;
      break;
    }
  }

  for (i = 0; i < details.outputs.length; i++) {
    member = details.outputs[i];

    if (member.path) {
      if (member.path.branch === 1)
        continue;
      received += member.value;
      recMember = member;
      recIndex = i;
      continue;
    }

    sent += member.value;
    sendMember = member;
    sendIndex = i;
  }

  if (receive) {
    member = recMember;
    index = recIndex;
  } else {
    member = sendMember;
    index = sendIndex;
  }

  // In the odd case where we send to ourselves.
  if (!member) {
    assert(!receive);
    member = recMember;
    index = recIndex;
  }

  return {
    account: member.path ? member.path.name : '',
    address: member.address
      ? member.address.toString(this.network)
      : null,
    category: receive ? 'receive' : 'send',
    amount: Amount.btc(receive ? received : -sent, true),
    label: member.path ? member.path.name : undefined,
    vout: index,
    confirmations: details.getDepth(),
    blockhash: details.block ? util.revHex(details.block) : null,
    blockindex: details.index,
    blocktime: details.ts,
    txid: util.revHex(details.hash),
    walletconflicts: [],
    time: details.ps,
    timereceived: details.ps,
    'bip125-replaceable': 'no'
  };
};

RPC.prototype.listTransactions = async function listTransactions(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var name = valid.str(0);
  var count = valid.u32(1, 10);
  var from = valid.u32(2, 0);
  var watchOnly = valid.bool(3, false);
  var end = from + count;
  var out = [];
  var i, txs, wtx, json;

  if (help || args.length > 4) {
    throw new RPCError(errs.MISC_ERROR,
      'listtransactions ( "account" count from includeWatchonly)');
  }

  if (wallet.watchOnly !== watchOnly)
    return out;

  if (name === '')
    name = 'default';

  txs = await wallet.getHistory();

  common.sortTX(txs);

  end = Math.min(end, txs.length);

  for (i = from; i < end; i++) {
    wtx = txs[i];
    json = await this._toListTX(wtx);
    out.push(json);
  }

  return out;
};

RPC.prototype.listUnspent = async function listUnspent(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var minDepth = valid.u32(0, 1);
  var maxDepth = valid.u32(1, 9999999);
  var addrs = valid.array(2);
  var height = this.wdb.state.height;
  var out = [];
  var map = {};
  var i, depth, address, hash, coins, coin, ring;

  if (help || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'listunspent ( minconf maxconf  ["address",...] )');
  }

  if (addrs) {
    valid = new Validator([addrs]);
    for (i = 0; i < addrs.length; i++) {
      address = valid.str(i, '');
      hash = parseHash(address, this.network);

      if (map[hash])
        throw new RPCError(errs.INVALID_PARAMETER, 'Duplicate address.');

      map[hash] = true;
    }
  }

  coins = await wallet.getCoins();

  common.sortCoins(coins);

  for (i = 0; i < coins.length; i++ ) {
    coin = coins[i];
    depth = coin.getDepth(height);

    if (!(depth >= minDepth && depth <= maxDepth))
      continue;

    address = coin.getAddress();

    if (!address)
      continue;

    hash = coin.getHash('hex');

    if (addrs) {
      if (!hash || !map[hash])
        continue;
    }

    ring = await wallet.getKey(hash);

    out.push({
      txid: coin.txid(),
      vout: coin.index,
      address: address ? address.toString(this.network) : null,
      account: ring ? ring.name : undefined,
      redeemScript: ring && ring.script
        ? ring.script.toJSON()
        : undefined,
      scriptPubKey: coin.script.toJSON(),
      amount: Amount.btc(coin.value, true),
      confirmations: depth,
      spendable: !wallet.isLocked(coin),
      solvable: true
    });
  }

  return out;
};

RPC.prototype.lockUnspent = async function lockUnspent(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var unlock = valid.bool(0, false);
  var outputs = valid.array(1);
  var i, output, outpoint, hash, index;

  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'lockunspent unlock ([{"txid":"txid","vout":n},...])');
  }

  if (args.length === 1) {
    if (unlock)
      wallet.unlockCoins();
    return true;
  }

  if (!outputs)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  for (i = 0; i < outputs.length; i++) {
    output = outputs[i];
    valid = new Validator([output]);
    hash = valid.hash('txid');
    index = valid.u32('vout');

    if (hash == null || index == null)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid parameter.');

    outpoint = new Outpoint();
    outpoint.hash = hash;
    outpoint.index = index;

    if (unlock) {
      wallet.unlockCoin(outpoint);
      continue;
    }

    wallet.lockCoin(outpoint);
  }

  return true;
};

RPC.prototype.move = async function move(args, help) {
  // Not implementing: stupid and deprecated.
  throw new Error('Not implemented.');
};

RPC.prototype.sendFrom = async function sendFrom(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var name = valid.str(0);
  var addr = valid.str(1);
  var value = valid.btc(2);
  var minconf = valid.u32(3, 0);
  var options, tx;

  if (help || args.length < 3 || args.length > 6) {
    throw new RPCError(errs.MISC_ERROR,
      'sendfrom "fromaccount" "tobitcoinaddress"'
      + ' amount ( minconf "comment" "comment-to" )');
  }

  if (!addr || value == null)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  addr = parseAddress(addr, this.network);

  if (name === '')
    name = 'default';

  options = {
    account: name,
    subtractFee: false,
    rate: this.feeRate,
    depth: minconf,
    outputs: [{
      address: addr,
      value: value
    }]
  };

  tx = await wallet.send(options);

  return tx.txid();
};

RPC.prototype.sendMany = async function sendMany(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var name = valid.str(0);
  var sendTo = valid.obj(1);
  var minconf = valid.u32(2, 1);
  var subtractFee = valid.bool(4, false);
  var outputs = [];
  var uniq = {};
  var i, keys, tx, key, value, address;
  var hash, output, options;

  if (help || args.length < 2 || args.length > 5) {
    throw new RPCError(errs.MISC_ERROR,
      'sendmany "fromaccount" {"address":amount,...}'
      + ' ( minconf "comment" ["address",...] )');
  }

  if (name === '')
    name = 'default';

  if (!sendTo)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  keys = Object.keys(sendTo);
  valid = new Validator([sendTo]);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    value = valid.btc(key);
    address = parseAddress(key, this.network);
    hash = address.getHash('hex');

    if (value == null)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid parameter.');

    if (uniq[hash])
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid parameter.');

    uniq[hash] = true;

    output = new Output();
    output.value = value;
    output.script.fromAddress(address);
    outputs.push(output);
  }

  options = {
    outputs: outputs,
    subtractFee: subtractFee,
    account: name,
    depth: minconf
  };

  tx = await wallet.send(options);

  return tx.txid();
};

RPC.prototype.sendToAddress = async function sendToAddress(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var addr = valid.str(0);
  var value = valid.btc(1);
  var subtractFee = valid.bool(4, false);
  var options, tx;

  if (help || args.length < 2 || args.length > 5) {
    throw new RPCError(errs.MISC_ERROR,
      'sendtoaddress "bitcoinaddress" amount'
      + ' ( "comment" "comment-to" subtractfeefromamount )');
  }

  addr = parseAddress(addr, this.network);

  if (!addr || value == null)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  options = {
    subtractFee: subtractFee,
    rate: this.feeRate,
    outputs: [{
      address: addr,
      value: value
    }]
  };

  tx = await wallet.send(options);

  return tx.txid();
};

RPC.prototype.setAccount = async function setAccount(args, help) {
  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'setaccount "bitcoinaddress" "account"');
  }

  // Impossible to implement in bcoin:
  throw new Error('Not implemented.');
};

RPC.prototype.setTXFee = async function setTXFee(args, help) {
  var valid = new Validator([args]);
  var rate = valid.btc(0);

  if (help || args.length < 1 || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'settxfee amount');

  if (rate == null)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  this.feeRate = rate;

  return true;
};

RPC.prototype.signMessage = async function signMessage(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var msg = valid.str(1, '');
  var sig, ring;

  if (help || args.length !== 2) {
    throw new RPCError(errs.MISC_ERROR,
      'signmessage "bitcoinaddress" "message"');
  }

  addr = parseHash(addr, this.network);

  ring = await wallet.getKey(addr);

  if (!ring)
    throw new RPCError(errs.WALLET_ERROR, 'Address not found.');

  if (!wallet.master.key)
    throw new RPCError(errs.WALLET_UNLOCK_NEEDED, 'Wallet is locked.');

  msg = Buffer.from(MAGIC_STRING + msg, 'utf8');
  msg = crypto.hash256(msg);

  sig = ring.sign(msg);

  return sig.toString('base64');
};

RPC.prototype.walletLock = async function walletLock(args, help) {
  var wallet = this.wallet;

  if (help || (wallet.master.encrypted && args.length !== 0))
    throw new RPCError(errs.MISC_ERROR, 'walletlock');

  if (!wallet.master.encrypted)
    throw new RPCError(errs.WALLET_WRONG_ENC_STATE, 'Wallet is not encrypted.');

  await wallet.lock();

  return null;
};

RPC.prototype.walletPassphraseChange = async function walletPassphraseChange(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var old = valid.str(0, '');
  var new_ = valid.str(1, '');

  if (help || (wallet.master.encrypted && args.length !== 2)) {
    throw new RPCError(errs.MISC_ERROR, 'walletpassphrasechange'
      + ' "oldpassphrase" "newpassphrase"');
  }

  if (!wallet.master.encrypted)
    throw new RPCError(errs.WALLET_WRONG_ENC_STATE, 'Wallet is not encrypted.');

  if (old.length < 1 || new_.length < 1)
    throw new RPCError(errs.INVALID_PARAMETER, 'Invalid parameter');

  await wallet.setPassphrase(old, new_);

  return null;
};

RPC.prototype.walletPassphrase = async function walletPassphrase(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var passphrase = valid.str(0, '');
  var timeout = valid.u32(1);

  if (help || (wallet.master.encrypted && args.length !== 2)) {
    throw new RPCError(errs.MISC_ERROR,
      'walletpassphrase "passphrase" timeout');
  }

  if (!wallet.master.encrypted)
    throw new RPCError(errs.WALLET_WRONG_ENC_STATE, 'Wallet is not encrypted.');

  if (passphrase.length < 1)
    throw new RPCError(errs.INVALID_PARAMETER, 'Invalid parameter');

  if (timeout == null)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter');

  await wallet.unlock(passphrase, timeout);

  return null;
};

RPC.prototype.importPrunedFunds = async function importPrunedFunds(args, help) {
  var valid = new Validator([args]);
  var tx = valid.buf(0);
  var block = valid.buf(1);
  var hash, height;

  if (help || args.length < 2 || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'importprunedfunds "rawtransaction" "txoutproof" ( "label" )');
  }

  if (!tx || !block)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  tx = TX.fromRaw(tx);
  block = MerkleBlock.fromRaw(block);
  hash = block.hash('hex');

  if (!block.verify())
    throw new RPCError(errs.VERIFY_ERROR, 'Invalid proof.');

  if (!block.hasTX(tx.hash('hex')))
    throw new RPCError(errs.VERIFY_ERROR, 'Invalid proof.');

  height = await this.client.getEntry(hash);

  if (height === -1)
    throw new RPCError(errs.VERIFY_ERROR, 'Invalid proof.');

  block = {
    hash: hash,
    ts: block.ts,
    height: height
  };

  if (!(await this.wdb.addTX(tx, block)))
    throw new RPCError(errs.WALLET_ERROR, 'No tracked address for TX.');

  return null;
};

RPC.prototype.removePrunedFunds = async function removePrunedFunds(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var hash = valid.hash(0);

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'removeprunedfunds "txid"');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  if (!(await wallet.remove(hash)))
    throw new RPCError(errs.WALLET_ERROR, 'Transaction not in wallet.');

  return null;
};

RPC.prototype.selectWallet = async function selectWallet(args, help) {
  var valid = new Validator([args]);
  var id = valid.str(0);
  var wallet;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'selectwallet "id"');

  wallet = await this.wdb.get(id);

  if (!wallet)
    throw new RPCError(errs.WALLET_ERROR, 'Wallet not found.');

  this.wallet = wallet;

  return null;
};

RPC.prototype.getMemoryInfo = async function getMemoryInfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getmemoryinfo');

  return util.memoryUsage();
};

RPC.prototype.setLogLevel = async function setLogLevel(args, help) {
  var valid = new Validator([args]);
  var level = valid.str(0, '');

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'setloglevel "level"');

  this.logger.setLevel(level);

  return null;
};

/*
 * Helpers
 */

function parseHash(raw, network) {
  var addr = parseAddress(raw, network);
  return addr.getHash('hex');
}

function parseAddress(raw, network) {
  try {
    return Address.fromString(raw, network);
  } catch (e) {
    throw new RPCError(errs.INVALID_ADDRESS_OR_KEY, 'Invalid address.');
  }
}

function parseSecret(raw, network) {
  try {
    return KeyRing.fromSecret(raw, network);
  } catch (e) {
    throw new RPCError(errs.INVALID_ADDRESS_OR_KEY, 'Invalid key.');
  }
}

/*
 * Expose
 */

module.exports = RPC;
