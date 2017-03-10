/*!
 * rpc.js - bitcoind-compatible json rpc for bcoin.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var fs = require('../utils/fs');
var util = require('../utils/util');
var co = require('../utils/co');
var crypto = require('../crypto/crypto');
var Amount = require('../btc/amount');
var Script = require('../script/script');
var Address = require('../primitives/address');
var KeyRing = require('../primitives/keyring');
var Lock = require('../utils/lock');
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

  this.network = wdb.network;
  this.logger = wdb.logger;
  this.client = wdb.client;
  this.wdb = wdb;
  this.wallet = null;

  this.locker = new Lock();

  this.feeRate = null;

  this.init();
}

util.inherits(RPC, RPCBase);

RPC.prototype.init = function init() {
  this.add('fundrawtransaction', this.fundrawtransaction);
  this.add('resendwallettransactions', this.resendwallettransactions);
  this.add('abandontransaction', this.abandontransaction);
  this.add('addmultisigaddress', this.addmultisigaddress);
  this.add('addwitnessaddress', this.addwitnessaddress);
  this.add('backupwallet', this.backupwallet);
  this.add('dumpprivkey', this.dumpprivkey);
  this.add('dumpwallet', this.dumpwallet);
  this.add('encryptwallet', this.encryptwallet);
  this.add('getaccountaddress', this.getaccountaddress);
  this.add('getaccount', this.getaccount);
  this.add('getaddressesbyaccount', this.getaddressesbyaccount);
  this.add('getbalance', this.getbalance);
  this.add('getnewaddress', this.getnewaddress);
  this.add('getrawchangeaddress', this.getrawchangeaddress);
  this.add('getreceivedbyaccount', this.getreceivedbyaccount);
  this.add('getreceivedbyaddress', this.getreceivedbyaddress);
  this.add('gettransaction', this.gettransaction);
  this.add('getunconfirmedbalance', this.getunconfirmedbalance);
  this.add('getwalletinfo', this.getwalletinfo);
  this.add('importprivkey', this.importprivkey);
  this.add('importwallet', this.importwallet);
  this.add('importaddress', this.importaddress);
  this.add('importprunedfunds', this.importprunedfunds);
  this.add('importpubkey', this.importpubkey);
  this.add('keypoolrefill', this.keypoolrefill);
  this.add('listaccounts', this.listaccounts);
  this.add('listaddressgroupings', this.listaddressgroupings);
  this.add('listlockunspent', this.listlockunspent);
  this.add('listreceivedbyaccount', this.listreceivedbyaccount);
  this.add('listreceivedbyaddress', this.listreceivedbyaddress);
  this.add('listsinceblock', this.listsinceblock);
  this.add('listtransactions', this.listtransactions);
  this.add('listunspent', this.listunspent);
  this.add('lockunspent', this.lockunspent);
  this.add('move', this.move);
  this.add('sendfrom', this.sendfrom);
  this.add('sendmany', this.sendmany);
  this.add('sendtoaddress', this.sendtoaddress);
  this.add('setaccount', this.setaccount);
  this.add('settxfee', this.settxfee);
  this.add('signmessage', this.signmessage);
  this.add('walletlock', this.walletlock);
  this.add('walletpassphrasechange', this.walletpassphrasechange);
  this.add('walletpassphrase', this.walletpassphrase);
  this.add('removeprunedfunds', this.removeprunedfunds);
};

RPC.prototype.fundrawtransaction = co(function* fundrawtransaction(args, help) {
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var options = valid.obj(1);
  var wallet = this.wallet;
  var rate = this.feeRate;
  var change, tx;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('fundrawtransaction "hexstring" ( options )');

  if (!data)
    throw new RPCError('Invalid parameter.');

  tx = MTX.fromRaw(data);

  if (tx.outputs.length === 0)
    throw new RPCError('TX must have at least one output.');

  if (options) {
    valid = new Validator([options]);
    change = valid.str('changeAddress');
    rate = valid.btc('feeRate');

    if (change)
      change = Address.fromBase58(change, this.network);
  }

  options = {
    rate: rate,
    changeAddress: change
  };

  yield wallet.fund(tx, options);

  return {
    hex: tx.toRaw().toString('hex'),
    changepos: tx.changeIndex,
    fee: Amount.btc(tx.getFee(), true)
  };
});

/*
 * Wallet
 */

RPC.prototype.resendwallettransactions = co(function* resendwallettransactions(args, help) {
  var wallet = this.wallet;
  var hashes = [];
  var i, tx, txs;

  if (help || args.length !== 0)
    throw new RPCError('resendwallettransactions');

  txs = yield wallet.resend();

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    hashes.push(tx.txid());
  }

  return hashes;
});

RPC.prototype.addmultisigaddress = co(function* addmultisigaddress(args, help) {
  if (help || args.length < 2 || args.length > 3) {
    throw new RPCError('addmultisigaddress'
      + ' nrequired ["key",...] ( "account" )');
  }

  // Impossible to implement in bcoin (no address book).
  throw new Error('Not implemented.');
});

RPC.prototype.addwitnessaddress = co(function* addwitnessaddress(args, help) {
  if (help || args.length < 1 || args.length > 1)
    throw new RPCError('addwitnessaddress "address"');

  // Unlikely to be implemented.
  throw new Error('Not implemented.');
});

RPC.prototype.backupwallet = co(function* backupwallet(args, help) {
  var valid = new Validator([args]);
  var dest = valid.str(0);

  if (help || args.length !== 1 || !dest)
    throw new RPCError('backupwallet "destination"');

  yield this.wdb.backup(dest);

  return null;
});

RPC.prototype.dumpprivkey = co(function* dumpprivkey(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var hash = Address.getHash(addr, 'hex');
  var ring;

  if (help || args.length !== 1)
    throw new RPCError('dumpprivkey "bitcoinaddress"');

  if (!hash)
    throw new RPCError('Invalid address.');

  ring = yield wallet.getPrivateKey(hash);

  if (!ring)
    throw new RPCError('Key not found.');

  return ring.toSecret();
});

RPC.prototype.dumpwallet = co(function* dumpwallet(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var file = valid.str(0);
  var time = util.date();
  var i, tip, addr, fmt, str, out, hash, hashes, ring;

  if (help || args.length !== 1)
    throw new RPCError('dumpwallet "filename"');

  if (!file)
    throw new RPCError('Invalid parameter.');

  tip = yield this.wdb.getTip();

  out = [
    util.fmt('# Wallet Dump created by Bcoin %s', pkg.version),
    util.fmt('# * Created on %s', time),
    util.fmt('# * Best block at time of backup was %d (%s).',
      tip.height, util.revHex(tip.hash)),
    util.fmt('# * File: %s', file),
    ''
  ];

  hashes = yield wallet.getAddressHashes();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    ring = yield wallet.getPrivateKey(hash);

    if (!ring)
      continue;

    addr = ring.getAddress('base58');
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

  yield fs.writeFile(file, out, 'utf8');

  return null;
});

RPC.prototype.encryptwallet = co(function* encryptwallet(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var passphrase = valid.str(0, '');

  if (!wallet.master.encrypted && (help || args.length !== 1))
    throw new RPCError('encryptwallet "passphrase"');

  if (wallet.master.encrypted)
    throw new RPCError('Already running with an encrypted wallet');

  if (passphrase.length < 1)
    throw new RPCError('encryptwallet "passphrase"');

  yield wallet.setPassphrase(passphrase);

  return 'wallet encrypted; we do not need to stop!';
});

RPC.prototype.getaccountaddress = co(function* getaccountaddress(args, help) {
  var valid = new Validator([args]);
  var wallet = this.wallet;
  var name = valid.str(0, '');
  var account;

  if (help || args.length !== 1)
    throw new RPCError('getaccountaddress "account"');

  if (!name)
    name = 'default';

  account = yield wallet.getAccount(name);

  if (!account)
    return '';

  return account.receive.getAddress('base58');
});

RPC.prototype.getaccount = co(function* getaccount(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var hash = Address.getHash(addr, 'hex');
  var path;

  if (help || args.length !== 1)
    throw new RPCError('getaccount "bitcoinaddress"');

  if (!hash)
    throw new RPCError('Invalid address.');

  path = yield wallet.getPath(hash);

  if (!path)
    return '';

  return path.name;
});

RPC.prototype.getaddressesbyaccount = co(function* getaddressesbyaccount(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var name = valid.str(0, '');
  var i, path, address, addrs, paths;

  if (help || args.length !== 1)
    throw new RPCError('getaddressesbyaccount "account"');

  if (name === '')
    name = 'default';

  addrs = [];

  paths = yield wallet.getPaths(name);

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    address = path.toAddress();
    addrs.push(address.toBase58(this.network));
  }

  return addrs;
});

RPC.prototype.getbalance = co(function* getbalance(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var name = valid.str(0);
  var minconf = valid.u32(1, 0);
  var watchOnly = valid.bool(2, false);
  var value, balance;

  if (help || args.length > 3)
    throw new RPCError('getbalance ( "account" minconf includeWatchonly )');

  if (name === '')
    name = 'default';

  if (name === '*')
    name = null;

  if (wallet.watchOnly !== watchOnly)
    return 0;

  balance = yield wallet.getBalance(name);

  if (minconf > 0)
    value = balance.confirmed;
  else
    value = balance.unconfirmed;

  return Amount.btc(value, true);
});

RPC.prototype.getnewaddress = co(function* getnewaddress(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var name = valid.str(0);
  var address;

  if (help || args.length > 1)
    throw new RPCError('getnewaddress ( "account" )');

  if (name === '')
    name = 'default';

  address = yield wallet.createReceive(name);

  return address.getAddress('base58');
});

RPC.prototype.getrawchangeaddress = co(function* getrawchangeaddress(args, help) {
  var wallet = this.wallet;
  var address;

  if (help || args.length > 1)
    throw new RPCError('getrawchangeaddress');

  address = yield wallet.createChange();

  return address.getAddress('base58');
});

RPC.prototype.getreceivedbyaccount = co(function* getreceivedbyaccount(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var name = valid.str(0);
  var minconf = valid.u32(0, 0);
  var height = this.wdb.state.height;
  var total = 0;
  var filter = {};
  var lastConf = -1;
  var i, j, path, wtx, output, conf, hash, paths, txs;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getreceivedbyaccount "account" ( minconf )');

  if (name === '')
    name = 'default';

  paths = yield wallet.getPaths(name);

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    filter[path.hash] = true;
  }

  txs = yield wallet.getHistory(name);

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
});

RPC.prototype.getreceivedbyaddress = co(function* getreceivedbyaddress(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var minconf = valid.u32(1, 0);
  var hash = Address.getHash(addr, 'hex');
  var height = this.wdb.state.height;
  var total = 0;
  var i, j, wtx, output, txs;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getreceivedbyaddress "bitcoinaddress" ( minconf )');

  if (!hash)
    throw new RPCError('Invalid address');

  txs = yield wallet.getHistory();

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
});

RPC.prototype._toWalletTX = co(function* _toWalletTX(wtx) {
  var wallet = this.wallet;
  var details = yield wallet.toDetails(wtx);
  var det = [];
  var sent = 0;
  var received = 0;
  var receive = true;
  var i, member;

  if (!details)
    throw new RPCError('TX not found.');

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
        address: member.address.toBase58(this.network),
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
        ? member.address.toBase58(this.network)
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
});

RPC.prototype.gettransaction = co(function* gettransaction(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var watchOnly = valid.bool(1, false);
  var wtx;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('gettransaction "txid" ( includeWatchonly )');

  if (!hash)
    throw new RPCError('Invalid parameter');

  wtx = yield wallet.getTX(hash);

  if (!wtx)
    throw new RPCError('TX not found.');

  return yield this._toWalletTX(wtx, watchOnly);
});

RPC.prototype.abandontransaction = co(function* abandontransaction(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var hash = valid.hash(0);
  var result;

  if (help || args.length !== 1)
    throw new RPCError('abandontransaction "txid"');

  if (!hash)
    throw new RPCError('Invalid parameter.');

  result = yield wallet.abandon(hash);

  if (!result)
    throw new RPCError('Transaction not in wallet.');

  return null;
});

RPC.prototype.getunconfirmedbalance = co(function* getunconfirmedbalance(args, help) {
  var wallet = this.wallet;
  var balance;

  if (help || args.length > 0)
    throw new RPCError('getunconfirmedbalance');

  balance = yield wallet.getBalance();

  return Amount.btc(balance.unconfirmed, true);
});

RPC.prototype.getwalletinfo = co(function* getwalletinfo(args, help) {
  var wallet = this.wallet;
  var balance;

  if (help || args.length !== 0)
    throw new RPCError('getwalletinfo');

  balance = yield wallet.getBalance();

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
});

RPC.prototype.importprivkey = co(function* importprivkey(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var secret = valid.str(0);
  var rescan = valid.bool(2, false);
  var key;

  if (help || args.length < 1 || args.length > 3)
    throw new RPCError('importprivkey "bitcoinprivkey" ( "label" rescan )');

  key = KeyRing.fromSecret(secret, this.network);

  yield wallet.importKey(0, key);

  if (rescan)
    yield this.wdb.rescan(0);

  return null;
});

RPC.prototype.importwallet = co(function* importwallet(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var file = valid.str(0);
  var rescan = valid.bool(1, false);
  var keys = [];
  var i, lines, line, parts;
  var secret, time, label, addr;
  var data, key;

  if (help || args.length !== 1)
    throw new RPCError('importwallet "filename" ( rescan )');

  if (fs.unsupported)
    throw new RPCError('FS not available.');

  data = yield fs.readFile(file, 'utf8');

  lines = data.split(/\n+/);

  for (i = 0; i < lines.length; i++) {
    line = lines[i].trim();

    if (line.length === 0)
      continue;

    if (/^\s*#/.test(line))
      continue;

    parts = line.split(/\s+/);

    if (parts.length < 4)
      throw new RPCError('Malformed wallet.');

    secret = KeyRing.fromSecret(parts[0], this.network);

    time = +parts[1];
    label = parts[2];
    addr = parts[3];

    keys.push(secret);
  }

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    yield wallet.importKey(0, key);
  }

  if (rescan)
    yield this.wdb.rescan(0);

  return null;
});

RPC.prototype.importaddress = co(function* importaddress(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var rescan = valid.bool(2, false);
  var p2sh = valid.bool(3, false);
  var script;

  if (help || args.length < 1 || args.length > 4)
    throw new RPCError('importaddress "address" ( "label" rescan p2sh )');

  if (p2sh) {
    script = valid.buf(0);

    if (!script)
      throw new RPCError('Invalid parameters.');

    script = Script.fromRaw(script);
    script = Script.fromScripthash(script.hash160());

    addr = script.getAddress();
  } else {
    addr = Address.fromBase58(addr, this.network);
  }

  yield wallet.importAddress(0, addr);

  if (rescan)
    yield this.wdb.rescan(0);

  return null;
});

RPC.prototype.importpubkey = co(function* importpubkey(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var data = valid.buf(0);
  var rescan = valid.bool(2, false);
  var key;

  if (help || args.length < 1 || args.length > 4)
    throw new RPCError('importpubkey "pubkey" ( "label" rescan )');

  if (!data)
    throw new RPCError('Invalid parameter.');

  key = KeyRing.fromPublic(data, this.network);

  yield wallet.importKey(0, key);

  if (rescan)
    yield this.wdb.rescan(0);

  return null;
});

RPC.prototype.keypoolrefill = co(function* keypoolrefill(args, help) {
  if (help || args.length > 1)
    throw new RPCError('keypoolrefill ( newsize )');
  return null;
});

RPC.prototype.listaccounts = co(function* listaccounts(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var minconf = valid.u32(0, 0);
  var watchOnly = valid.bool(1, false);
  var map = {};
  var i, accounts, account, balance, value;

  if (help || args.length > 2)
    throw new RPCError('listaccounts ( minconf includeWatchonly)');

  accounts = yield wallet.getAccounts();

  for (i = 0; i < accounts.length; i++) {
    account = accounts[i];
    balance = yield wallet.getBalance(account);

    value = balance.unconfirmed;

    if (minconf > 0)
      value = balance.confirmed;

    if (wallet.watchOnly !== watchOnly)
      value = 0;

    map[account] = Amount.btc(value, true);
  }

  return map;
});

RPC.prototype.listaddressgroupings = co(function* listaddressgroupings(args, help) {
  if (help)
    throw new RPCError('listaddressgroupings');
  throw new Error('Not implemented.');
});

RPC.prototype.listlockunspent = co(function* listlockunspent(args, help) {
  var wallet = this.wallet;
  var i, outpoints, outpoint, out;

  if (help || args.length > 0)
    throw new RPCError('listlockunspent');

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
});

RPC.prototype.listreceivedbyaccount = co(function* listreceivedbyaccount(args, help) {
  var valid = new Validator([args]);
  var minconf = valid.u32(0, 0);
  var includeEmpty = valid.bool(1, false);
  var watchOnly = valid.bool(2, false);

  if (help || args.length > 3) {
    throw new RPCError('listreceivedbyaccount'
      + ' ( minconf includeempty includeWatchonly )');
  }

  return yield this._listReceived(minconf, includeEmpty, watchOnly, true);
});

RPC.prototype.listreceivedbyaddress = co(function* listreceivedbyaddress(args, help) {
  var valid = new Validator([args]);
  var minconf = valid.u32(0, 0);
  var includeEmpty = valid.bool(1, false);
  var watchOnly = valid.bool(2, false);

  if (help || args.length > 3) {
    throw new RPCError('listreceivedbyaddress'
      + ' ( minconf includeempty includeWatchonly )');
  }

  return yield this._listReceived(minconf, includeEmpty, watchOnly, false);
});

RPC.prototype._listReceived = co(function* _listReceived(minconf, empty, watchOnly, account) {
  var wallet = this.wallet;
  var paths = yield wallet.getPaths();
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
      address: address.toBase58(this.network),
      account: path.name,
      amount: 0,
      confirmations: -1,
      label: '',
    };
  }

  txs = yield wallet.getHistory();

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
        entry.address = address.toBase58(this.network);
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
});

RPC.prototype.listsinceblock = co(function* listsinceblock(args, help) {
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
    throw new RPCError('listsinceblock'
      + ' ( "blockhash" target-confirmations includeWatchonly)');
  }

  if (wallet.watchOnly !== watchOnly)
    return out;

  if (block) {
    entry = yield this.client.getEntry(block);
    if (entry)
      height = entry.height;
  }

  if (height === -1)
    height = this.chain.height;

  txs = yield wallet.getHistory();

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];

    if (wtx.height < height)
      continue;

    if (wtx.getDepth(chainHeight) < minconf)
      continue;

    if (!highest || wtx.height > highest)
      highest = wtx;

    json = yield this._toListTX(wtx);

    out.push(json);
  }

  return {
    transactions: out,
    lastblock: highest && highest.block
      ? util.revHex(highest.block)
      : encoding.NULL_HASH
  };
});

RPC.prototype._toListTX = co(function* _toListTX(wtx) {
  var wallet = this.wallet;
  var details = yield wallet.toDetails(wtx);
  var sent = 0;
  var received = 0;
  var receive = true;
  var sendMember, recMember, sendIndex, recIndex;
  var i, member, index;

  if (!details)
    throw new RPCError('TX not found.');

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
      ? member.address.toBase58(this.network)
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
});

RPC.prototype.listtransactions = co(function* listtransactions(args, help) {
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
    throw new RPCError(
      'listtransactions ( "account" count from includeWatchonly)');
  }

  if (wallet.watchOnly !== watchOnly)
    return out;

  if (name === '')
    name = 'default';

  txs = yield wallet.getHistory();

  common.sortTX(txs);

  end = Math.min(end, txs.length);

  for (i = from; i < end; i++) {
    wtx = txs[i];
    json = yield this._toListTX(wtx);
    out.push(json);
  }

  return out;
});

RPC.prototype.listunspent = co(function* listunspent(args, help) {
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
    throw new RPCError('listunspent'
      + ' ( minconf maxconf  ["address",...] )');
  }

  if (addrs) {
    valid = new Validator([addrs]);
    for (i = 0; i < addrs.length; i++) {
      address = valid.str(i, '');
      hash = Address.getHash(address, 'hex');

      if (!hash)
        throw new RPCError('Invalid address.');

      if (map[hash])
        throw new RPCError('Duplicate address.');

      map[hash] = true;
    }
  }

  coins = yield wallet.getCoins();

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

    ring = yield wallet.getKey(hash);

    out.push({
      txid: coin.txid(),
      vout: coin.index,
      address: address ? address.toBase58(this.network) : null,
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
});

RPC.prototype.lockunspent = co(function* lockunspent(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var unlock = valid.bool(0, false);
  var outputs = valid.array(1);
  var i, output, outpoint, hash, index;

  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError('lockunspent'
      + ' unlock ([{"txid":"txid","vout":n},...])');
  }

  if (args.length === 1) {
    if (unlock)
      wallet.unlockCoins();
    return true;
  }

  if (!outputs)
    throw new RPCError('Invalid parameter.');

  for (i = 0; i < outputs.length; i++) {
    output = outputs[i];
    valid = new Validator([output]);
    hash = valid.hash('txid');
    index = valid.u32('vout');

    if (hash == null || index == null)
      throw new RPCError('Invalid parameter.');

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
});

RPC.prototype.move = co(function* move(args, help) {
  // Not implementing: stupid and deprecated.
  throw new Error('Not implemented.');
});

RPC.prototype.sendfrom = co(function* sendfrom(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var name = valid.str(0);
  var addr = valid.str(1);
  var value = valid.btc(2);
  var minconf = valid.u32(3, 0);
  var options, tx;

  if (help || args.length < 3 || args.length > 6) {
    throw new RPCError('sendfrom'
      + ' "fromaccount" "tobitcoinaddress"'
      + ' amount ( minconf "comment" "comment-to" )');
  }

  if (!addr || value == null)
    throw new RPCError('Invalid parameter.');

  addr = Address.fromBase58(addr, this.network);

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

  tx = yield wallet.send(options);

  return tx.txid();
});

RPC.prototype.sendmany = co(function* sendmany(args, help) {
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
    throw new RPCError('sendmany'
      + ' "fromaccount" {"address":amount,...}'
      + ' ( minconf "comment" ["address",...] )');
  }

  if (name === '')
    name = 'default';

  if (!sendTo)
    throw new RPCError('Invalid parameter.');

  keys = Object.keys(sendTo);
  valid = new Validator([sendTo]);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    value = valid.btc(key);
    address = Address.fromBase58(key, this.network);
    hash = address.getHash('hex');

    if (value == null)
      throw new RPCError('Invalid parameter.');

    if (uniq[hash])
      throw new RPCError('Invalid parameter.');

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

  tx = yield wallet.send(options);

  return tx.txid();
});

RPC.prototype.sendtoaddress = co(function* sendtoaddress(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var addr = valid.str(0);
  var value = valid.btc(1);
  var subtractFee = valid.bool(4, false);
  var options, tx;

  if (help || args.length < 2 || args.length > 5) {
    throw new RPCError('sendtoaddress'
      + ' "bitcoinaddress" amount'
      + ' ( "comment" "comment-to"'
      + ' subtractfeefromamount )');
  }

  addr = Address.fromBase58(addr, this.network);

  if (!addr || value == null)
    throw new RPCError('Invalid parameter.');

  options = {
    subtractFee: subtractFee,
    rate: this.feeRate,
    outputs: [{
      address: addr,
      value: value
    }]
  };

  tx = yield wallet.send(options);

  return tx.txid();
});

RPC.prototype.setaccount = co(function* setaccount(args, help) {
  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('setaccount "bitcoinaddress" "account"');

  // Impossible to implement in bcoin:
  throw new Error('Not implemented.');
});

RPC.prototype.settxfee = co(function* settxfee(args, help) {
  var valid = new Validator([args]);
  var rate = valid.btc(0);

  if (help || args.length < 1 || args.length > 1)
    throw new RPCError('settxfee amount');

  if (rate == null)
    throw new RPCError('Invalid parameter.');

  this.feeRate = rate;

  return true;
});

RPC.prototype.signmessage = co(function* signmessage(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var addr = valid.str(0, '');
  var msg = valid.str(1, '');
  var sig, ring;

  if (help || args.length !== 2)
    throw new RPCError('signmessage "bitcoinaddress" "message"');

  addr = Address.getHash(addr, 'hex');

  if (!addr)
    throw new RPCError('Invalid address.');

  ring = yield wallet.getKey(addr);

  if (!ring)
    throw new RPCError('Address not found.');

  if (!wallet.master.key)
    throw new RPCError('Wallet is locked.');

  msg = new Buffer(MAGIC_STRING + msg, 'utf8');
  msg = crypto.hash256(msg);

  sig = ring.sign(msg);

  return sig.toString('base64');
});

RPC.prototype.walletlock = co(function* walletlock(args, help) {
  var wallet = this.wallet;

  if (help || (wallet.master.encrypted && args.length !== 0))
    throw new RPCError('walletlock');

  if (!wallet.master.encrypted)
    throw new RPCError('Wallet is not encrypted.');

  yield wallet.lock();

  return null;
});

RPC.prototype.walletpassphrasechange = co(function* walletpassphrasechange(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var old = valid.str(0, '');
  var new_ = valid.str(1, '');

  if (help || (wallet.master.encrypted && args.length !== 2)) {
    throw new RPCError('walletpassphrasechange'
      + ' "oldpassphrase" "newpassphrase"');
  }

  if (!wallet.master.encrypted)
    throw new RPCError('Wallet is not encrypted.');

  if (old.length < 1 || new_.length < 1)
    throw new RPCError('Invalid parameter');

  yield wallet.setPassphrase(old, new_);

  return null;
});

RPC.prototype.walletpassphrase = co(function* walletpassphrase(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var passphrase = valid.str(0, '');
  var timeout = valid.u32(1);

  if (help || (wallet.master.encrypted && args.length !== 2))
    throw new RPCError('walletpassphrase "passphrase" timeout');

  if (!wallet.master.encrypted)
    throw new RPCError('Wallet is not encrypted.');

  if (passphrase.length < 1)
    throw new RPCError('Invalid parameter');

  if (timeout == null)
    throw new RPCError('Invalid parameter');

  yield wallet.unlock(passphrase, timeout);

  return null;
});

RPC.prototype.importprunedfunds = co(function* importprunedfunds(args, help) {
  var valid = new Validator([args]);
  var tx = valid.buf(0);
  var block = valid.buf(1);
  var hash, height;

  if (help || args.length < 2 || args.length > 3) {
    throw new RPCError('importprunedfunds'
      + ' "rawtransaction" "txoutproof" ( "label" )');
  }

  if (!tx || !block)
    throw new RPCError('Invalid parameter.');

  tx = TX.fromRaw(tx);
  block = MerkleBlock.fromRaw(block);
  hash = block.hash('hex');

  if (!block.verify())
    throw new RPCError('Invalid proof.');

  if (!block.hasTX(tx.hash('hex')))
    throw new RPCError('Invalid proof.');

  height = yield this.client.getEntry(hash);

  if (height === -1)
    throw new RPCError('Invalid proof.');

  block = {
    hash: hash,
    ts: block.ts,
    height: height
  };

  if (!(yield this.wdb.addTX(tx, block)))
    throw new RPCError('No tracked address for TX.');

  return null;
});

RPC.prototype.removeprunedfunds = co(function* removeprunedfunds(args, help) {
  var wallet = this.wallet;
  var valid = new Validator([args]);
  var hash = valid.hash(0);

  if (help || args.length !== 1)
    throw new RPCError('removeprunedfunds "txid"');

  if (!hash)
    throw new RPCError('Invalid parameter.');

  if (!(yield wallet.remove(hash)))
    throw new RPCError('Transaction not in wallet.');

  return null;
});

RPC.prototype.selectwallet = co(function* selectwallet(args, help) {
  var valid = new Validator([args]);
  var id = valid.str(0);
  var wallet;

  if (help || args.length !== 1)
    throw new RPCError('selectwallet "id"');

  wallet = yield this.wdb.get(id);

  if (!wallet)
    throw new RPCError('Wallet not found.');

  this.wallet = wallet;

  return null;
});

/*
 * Expose
 */

module.exports = RPC;
