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
var consensus = require('../protocol/consensus');
var pkg = require('../pkg');

/**
 * Bitcoin Core RPC
 * @alias module:wallet.RPC
 * @constructor
 * @param {Node} node
 */

function RPC(walletdb) {
  if (!(this instanceof RPC))
    return new RPC(walletdb);

  assert(walletdb, 'RPC requires a WalletDB.');

  this.network = walletdb.network;
  this.logger = walletdb.logger;
  this.walletdb = walletdb;
  this.wallet = null;

  this.locker = new Lock();

  this.feeRate = null;
}

RPC.magic = 'Bitcoin Signed Message:\n';

RPC.prototype.attach = function attach(rpc) {
  rpc.add('fundrawtransaction', this.fundrawtransaction, this);
  rpc.add('resendwallettransactions', this.resendwallettransactions, this);
  rpc.add('abandontransaction', this.abandontransaction, this);
  rpc.add('addmultisigaddress', this.addmultisigaddress, this);
  rpc.add('addwitnessaddress', this.addwitnessaddress, this);
  rpc.add('backupwallet', this.backupwallet, this);
  rpc.add('dumpprivkey', this.dumpprivkey, this);
  rpc.add('dumpwallet', this.dumpwallet, this);
  rpc.add('encryptwallet', this.encryptwallet, this);
  rpc.add('getaccountaddress', this.getaccountaddress, this);
  rpc.add('getaccount', this.getaccount, this);
  rpc.add('getaddressesbyaccount', this.getaddressesbyaccount, this);
  rpc.add('getbalance', this.getbalance, this);
  rpc.add('getnewaddress', this.getnewaddress, this);
  rpc.add('getrawchangeaddress', this.getrawchangeaddress, this);
  rpc.add('getreceivedbyaccount', this.getreceivedbyaccount, this);
  rpc.add('getreceivedbyaddress', this.getreceivedbyaddress, this);
  rpc.add('gettransaction', this.gettransaction, this);
  rpc.add('getunconfirmedbalance', this.getunconfirmedbalance, this);
  rpc.add('getwalletinfo', this.getwalletinfo, this);
  rpc.add('importprivkey', this.importprivkey, this);
  rpc.add('importwallet', this.importwallet, this);
  rpc.add('importaddress', this.importaddress, this);
  rpc.add('importprunedfunds', this.importprunedfunds, this);
  rpc.add('importpubkey', this.importpubkey, this);
  rpc.add('keypoolrefill', this.keypoolrefill, this);
  rpc.add('listaccounts', this.listaccounts, this);
  rpc.add('listaddressgroupings', this.listaddressgroupings, this);
  rpc.add('listlockunspent', this.listlockunspent, this);
  rpc.add('listreceivedbyaccount', this.listreceivedbyaccount, this);
  rpc.add('listreceivedbyaddress', this.listreceivedbyaddress, this);
  rpc.add('listsinceblock', this.listsinceblock, this);
  rpc.add('listtransactions', this.listtransactions, this);
  rpc.add('listunspent', this.listunspent, this);
  rpc.add('lockunspent', this.lockunspent, this);
  rpc.add('move', this.move, this);
  rpc.add('sendfrom', this.sendfrom, this);
  rpc.add('sendmany', this.sendmany, this);
  rpc.add('sendtoaddress', this.sendtoaddress, this);
  rpc.add('setaccount', this.setaccount, this);
  rpc.add('settxfee', this.settxfee, this);
  rpc.add('signmessage', this.signmessage, this);
  rpc.add('walletlock', this.walletlock, this);
  rpc.add('walletpassphrasechange', this.walletpassphrasechange, this);
  rpc.add('walletpassphrase', this.walletpassphrase, this);
  rpc.add('removeprunedfunds', this.removeprunedfunds, this);
};

RPC.prototype.execute = function execute(json, help) {
  switch (json.method) {
    case 'fundrawtransaction':
      return this.fundrawtransaction(json.params, help);
    case 'resendwallettransactions':
      return this.resendwallettransactions(json.params, help);
    case 'abandontransaction':
      return this.abandontransaction(json.params, help);
    case 'addmultisigaddress':
      return this.addmultisigaddress(json.params, help);
    case 'addwitnessaddress':
      return this.addwitnessaddress(json.params, help);
    case 'backupwallet':
      return this.backupwallet(json.params, help);
    case 'dumpprivkey':
      return this.dumpprivkey(json.params, help);
    case 'dumpwallet':
      return this.dumpwallet(json.params, help);
    case 'encryptwallet':
      return this.encryptwallet(json.params, help);
    case 'getaccountaddress':
      return this.getaccountaddress(json.params, help);
    case 'getaccount':
      return this.getaccount(json.params, help);
    case 'getaddressesbyaccount':
      return this.getaddressesbyaccount(json.params, help);
    case 'getbalance':
      return this.getbalance(json.params, help);
    case 'getnewaddress':
      return this.getnewaddress(json.params, help);
    case 'getrawchangeaddress':
      return this.getrawchangeaddress(json.params, help);
    case 'getreceivedbyaccount':
      return this.getreceivedbyaccount(json.params, help);
    case 'getreceivedbyaddress':
      return this.getreceivedbyaddress(json.params, help);
    case 'gettransaction':
      return this.gettransaction(json.params, help);
    case 'getunconfirmedbalance':
      return this.getunconfirmedbalance(json.params, help);
    case 'getwalletinfo':
      return this.getwalletinfo(json.params, help);
    case 'importprivkey':
      return this.importprivkey(json.params, help);
    case 'importwallet':
      return this.importwallet(json.params, help);
    case 'importaddress':
      return this.importaddress(json.params, help);
    case 'importprunedfunds':
      return this.importprunedfunds(json.params, help);
    case 'importpubkey':
      return this.importpubkey(json.params, help);
    case 'keypoolrefill':
      return this.keypoolrefill(json.params, help);
    case 'listaccounts':
      return this.listaccounts(json.params, help);
    case 'listaddressgroupings':
      return this.listaddressgroupings(json.params, help);
    case 'listlockunspent':
      return this.listlockunspent(json.params, help);
    case 'listreceivedbyaccount':
      return this.listreceivedbyaccount(json.params, help);
    case 'listreceivedbyaddress':
      return this.listreceivedbyaddress(json.params, help);
    case 'listsinceblock':
      return this.listsinceblock(json.params, help);
    case 'listtransactions':
      return this.listtransactions(json.params, help);
    case 'listunspent':
      return this.listunspent(json.params, help);
    case 'lockunspent':
      return this.lockunspent(json.params, help);
    case 'move':
      return this.move(json.params, help);
    case 'sendfrom':
      return this.sendfrom(json.params, help);
    case 'sendmany':
      return this.sendmany(json.params, help);
    case 'sendtoaddress':
      return this.sendtoaddress(json.params, help);
    case 'setaccount':
      return this.setaccount(json.params, help);
    case 'settxfee':
      return this.settxfee(json.params, help);
    case 'signmessage':
      return this.signmessage(json.params, help);
    case 'walletlock':
      return this.walletlock(json.params, help);
    case 'walletpassphrasechange':
      return this.walletpassphrasechange(json.params, help);
    case 'walletpassphrase':
      return this.walletpassphrase(json.params, help);
    case 'removeprunedfunds':
      return this.removeprunedfunds(json.params, help);
    default:
      return Promise.reject(new Error('Unknown RPC call: ' + json.method));
  }
};

RPC.prototype.fundrawtransaction = co(function* fundrawtransaction(args, help) {
  var wallet = this.wallet;
  var feeRate = this.feeRate;
  var tx, options, changeAddress;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('fundrawtransaction "hexstring" ( options )');

  if (!util.isHex(args[0]))
    throw new RPCError('Invalid parameter.');

  tx = MTX.fromRaw(args[0], 'hex');

  if (tx.outputs.length === 0)
    throw new RPCError('TX must have at least one output.');

  if (args.length > 1) {
    options = toObject(args[1]);
    changeAddress = toString(options.changeAddress);

    if (changeAddress)
      changeAddress = Address.fromBase58(changeAddress, this.network);

    feeRate = options.feeRate;

    if (feeRate != null)
      feeRate = toSatoshi(feeRate);
  }

  options = {
    rate: feeRate,
    changeAddress: changeAddress
  };

  yield wallet.fund(tx, options);

  return {
    hex: tx.toRaw().toString('hex'),
    changepos: tx.changeIndex,
    fee: Amount.btc(tx.getFee(), true)
  };
});

RPC.prototype._createRedeem = co(function* _createRedeem(args, help) {
  var wallet = this.wallet;
  var i, m, n, keys, hash, script, key, ring;

  if (!util.isNumber(args[0])
      || !Array.isArray(args[1])
      || args[0] < 1
      || args[1].length < args[0]
      || args[1].length > 16) {
    throw new RPCError('Invalid parameter.');
  }

  m = args[0];
  n = args[1].length;
  keys = args[1];

  for (i = 0; i < keys.length; i++) {
    key = keys[i];

    if (!util.isBase58(key)) {
      if (!util.isHex(key))
        throw new RPCError('Invalid key.');
      keys[i] = new Buffer(key, 'hex');
      continue;
    }

    hash = Address.getHash(key, 'hex');

    if (!hash)
      throw new RPCError('Invalid key.');

    ring = yield wallet.getKey(hash);

    if (!ring)
      throw new RPCError('Invalid key.');

    keys[i] = ring.publicKey;
  }

  try {
    script = Script.fromMultisig(m, n, keys);
  } catch (e) {
    throw new RPCError('Invalid parameters.');
  }

  if (script.getSize() > consensus.MAX_SCRIPT_PUSH)
    throw new RPCError('Redeem script exceeds size limit.');

  return script;
});

RPC.prototype.createmultisig = co(function* createmultisig(args, help) {
  var script, address;

  if (help || args.length < 2 || args.length > 2)
    throw new RPCError('createmultisig nrequired ["key",...]');

  script = yield this._createRedeem(args);
  address = script.getAddress();

  return {
    address: address.toBase58(this.network),
    redeemScript: script.toJSON()
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
  var dest;

  if (help || args.length !== 1)
    throw new RPCError('backupwallet "destination"');

  dest = toString(args[0]);

  yield this.walletdb.backup(dest);

  return null;
});

RPC.prototype.dumpprivkey = co(function* dumpprivkey(args, help) {
  var wallet = this.wallet;
  var hash, ring;

  if (help || args.length !== 1)
    throw new RPCError('dumpprivkey "bitcoinaddress"');

  hash = Address.getHash(toString(args[0]), 'hex');

  if (!hash)
    throw new RPCError('Invalid address.');

  ring = yield wallet.getPrivateKey(hash);

  if (!ring)
    throw new RPCError('Key not found.');

  return ring.toSecret();
});

RPC.prototype.dumpwallet = co(function* dumpwallet(args, help) {
  var wallet = this.wallet;
  var i, file, time, address, fmt, str, out, hash, hashes, ring;

  if (help || args.length !== 1)
    throw new RPCError('dumpwallet "filename"');

  if (!args[0] || typeof args[0] !== 'string')
    throw new RPCError('Invalid parameter.');

  file = toString(args[0]);
  time = util.date();
  out = [
    util.fmt('# Wallet Dump created by Bcoin %s', pkg.version),
    util.fmt('# * Created on %s', time),
    util.fmt('# * Best block at time of backup was %d (%s),',
      this.chain.height, this.chain.tip.rhash()),
    util.fmt('#   mined on %s', util.date(this.chain.tip.ts)),
    util.fmt('# * File: %s', file),
    ''
  ];

  hashes = yield wallet.getAddressHashes();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    ring = yield wallet.getPrivateKey(hash);

    if (!ring)
      continue;

    address = ring.getAddress('base58');
    fmt = '%s %s label= addr=%s';

    if (ring.branch === 1)
      fmt = '%s %s change=1 addr=%s';

    str = util.fmt(fmt, ring.toSecret(), time, address);

    out.push(str);
  }

  out.push('');
  out.push('# End of dump');
  out.push('');

  out = out.join('\n');

  if (fs.unsupported)
    return out;

  yield fs.writeFile(file, out, 'utf8');

  return out;
});

RPC.prototype.encryptwallet = co(function* encryptwallet(args, help) {
  var wallet = this.wallet;
  var passphrase;

  if (!wallet.master.encrypted && (help || args.length !== 1))
    throw new RPCError('encryptwallet "passphrase"');

  if (wallet.master.encrypted)
    throw new RPCError('Already running with an encrypted wallet');

  passphrase = toString(args[0]);

  if (passphrase.length < 1)
    throw new RPCError('encryptwallet "passphrase"');

  yield wallet.setPassphrase(passphrase);

  return 'wallet encrypted; we do not need to stop!';
});

RPC.prototype.getaccountaddress = co(function* getaccountaddress(args, help) {
  var wallet = this.wallet;
  var account;

  if (help || args.length !== 1)
    throw new RPCError('getaccountaddress "account"');

  account = toString(args[0]);

  if (!account)
    account = 'default';

  account = yield wallet.getAccount(account);

  if (!account)
    return '';

  return account.receive.getAddress('base58');
});

RPC.prototype.getaccount = co(function* getaccount(args, help) {
  var wallet = this.wallet;
  var hash, path;

  if (help || args.length !== 1)
    throw new RPCError('getaccount "bitcoinaddress"');

  hash = Address.getHash(args[0], 'hex');

  if (!hash)
    throw new RPCError('Invalid address.');

  path = yield wallet.getPath(hash);

  if (!path)
    return '';

  return path.name;
});

RPC.prototype.getaddressesbyaccount = co(function* getaddressesbyaccount(args, help) {
  var wallet = this.wallet;
  var i, path, account, address, addrs, paths;

  if (help || args.length !== 1)
    throw new RPCError('getaddressesbyaccount "account"');

  account = toString(args[0]);

  if (!account)
    account = 'default';

  addrs = [];

  paths = yield wallet.getPaths(account);

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    address = path.toAddress();
    addrs.push(address.toBase58(this.network));
  }

  return addrs;
});

RPC.prototype.getbalance = co(function* getbalance(args, help) {
  var wallet = this.wallet;
  var minconf = 0;
  var account, value, balance;

  if (help || args.length > 3)
    throw new RPCError('getbalance ( "account" minconf includeWatchonly )');

  if (args.length >= 1) {
    account = toString(args[0]);

    if (!account)
      account = 'default';

    if (account === '*')
      account = null;
  }

  if (args.length >= 2)
    minconf = toNumber(args[1], 0);

  balance = yield wallet.getBalance(account);

  if (minconf)
    value = balance.confirmed;
  else
    value = balance.unconfirmed;

  return Amount.btc(value, true);
});

RPC.prototype.getnewaddress = co(function* getnewaddress(args, help) {
  var wallet = this.wallet;
  var account, address;

  if (help || args.length > 1)
    throw new RPCError('getnewaddress ( "account" )');

  if (args.length === 1)
    account = toString(args[0]);

  if (!account)
    account = 'default';

  address = yield wallet.createReceive(account);

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
  var minconf = 0;
  var total = 0;
  var filter = {};
  var lastConf = -1;
  var i, j, path, wtx, output, conf, hash, account, paths, txs;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getreceivedbyaccount "account" ( minconf )');

  account = toString(args[0]);

  if (!account)
    account = 'default';

  if (args.length === 2)
    minconf = toNumber(args[1], 0);

  paths = yield wallet.getPaths(account);

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    filter[path.hash] = true;
  }

  txs = yield wallet.getHistory(account);

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];

    conf = wtx.getDepth(this.chain.height);

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
  var minconf = 0;
  var total = 0;
  var i, j, hash, wtx, output, txs;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('getreceivedbyaddress "bitcoinaddress" ( minconf )');

  hash = Address.getHash(toString(args[0]), 'hex');

  if (!hash)
    throw new RPCError('Invalid address');

  if (args.length === 2)
    minconf = toNumber(args[1], 0);

  txs = yield wallet.getHistory();

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];

    if (wtx.getDepth(this.chain.height) < minconf)
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
  var hash, wtx;

  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('gettransaction "txid" ( includeWatchonly )');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter');

  wtx = yield wallet.getTX(hash);

  if (!wtx)
    throw new RPCError('TX not found.');

  return yield this._toWalletTX(wtx);
});

RPC.prototype.abandontransaction = co(function* abandontransaction(args, help) {
  var wallet = this.wallet;
  var hash, result;

  if (help || args.length !== 1)
    throw new RPCError('abandontransaction "txid"');

  hash = toHash(args[0]);

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
  var secret, label, rescan, key;

  if (help || args.length < 1 || args.length > 3)
    throw new RPCError('importprivkey "bitcoinprivkey" ( "label" rescan )');

  secret = toString(args[0]);

  if (args.length > 1)
    label = toString(args[1]);

  if (args.length > 2)
    rescan = toBool(args[2]);

  if (rescan && this.chain.options.prune)
    throw new RPCError('Cannot rescan when pruned.');

  key = KeyRing.fromSecret(secret, this.network);

  yield wallet.importKey(0, key);

  if (rescan)
    yield this.walletdb.rescan(0);

  return null;
});

RPC.prototype.importwallet = co(function* importwallet(args, help) {
  var wallet = this.wallet;
  var file, keys, lines, line, parts;
  var i, secret, time, label, addr;
  var data, key, rescan;

  if (help || args.length !== 1)
    throw new RPCError('importwallet "filename" ( rescan )');

  if (fs.unsupported)
    throw new RPCError('FS not available.');

  file = toString(args[0]);

  if (args.length > 1)
    rescan = toBool(args[1]);

  if (rescan && this.chain.options.prune)
    throw new RPCError('Cannot rescan when pruned.');

  data = yield fs.readFile(file, 'utf8');

  lines = data.split(/\n+/);
  keys = [];

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
    yield this.walletdb.rescan(0);

  return null;
});

RPC.prototype.importaddress = co(function* importaddress(args, help) {
  var wallet = this.wallet;
  var addr, label, rescan, p2sh;

  if (help || args.length < 1 || args.length > 4)
    throw new RPCError('importaddress "address" ( "label" rescan p2sh )');

  addr = toString(args[0]);

  if (args.length > 1)
    label = toString(args[1]);

  if (args.length > 2)
    rescan = toBool(args[2]);

  if (args.length > 3)
    p2sh = toBool(args[3]);

  if (rescan && this.chain.options.prune)
    throw new RPCError('Cannot rescan when pruned.');

  addr = Address.fromBase58(addr, this.network);

  yield wallet.importAddress(0, addr);

  if (rescan)
    yield this.walletdb.rescan(0);

  return null;
});

RPC.prototype.importpubkey = co(function* importpubkey(args, help) {
  var wallet = this.wallet;
  var pubkey, label, rescan, key;

  if (help || args.length < 1 || args.length > 4)
    throw new RPCError('importpubkey "pubkey" ( "label" rescan )');

  pubkey = toString(args[0]);

  if (!util.isHex(pubkey))
    throw new RPCError('Invalid parameter.');

  if (args.length > 1)
    label = toString(args[1]);

  if (args.length > 2)
    rescan = toBool(args[2]);

  if (rescan && this.chain.options.prune)
    throw new RPCError('Cannot rescan when pruned.');

  pubkey = new Buffer(pubkey, 'hex');

  key = KeyRing.fromPublic(pubkey, this.network);

  yield wallet.importKey(0, key);

  if (rescan)
    yield this.walletdb.rescan(0);

  return null;
});

RPC.prototype.keypoolrefill = co(function* keypoolrefill(args, help) {
  if (help || args.length > 1)
    throw new RPCError('keypoolrefill ( newsize )');
  return null;
});

RPC.prototype.listaccounts = co(function* listaccounts(args, help) {
  var wallet = this.wallet;
  var i, map, accounts, account, balance;

  if (help || args.length > 2)
    throw new RPCError('listaccounts ( minconf includeWatchonly)');

  map = {};
  accounts = yield wallet.getAccounts();

  for (i = 0; i < accounts.length; i++) {
    account = accounts[i];
    balance = yield wallet.getBalance(account);
    map[account] = Amount.btc(balance.unconfirmed, true);
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
  var minconf = 0;
  var includeEmpty = false;

  if (help || args.length > 3) {
    throw new RPCError('listreceivedbyaccount'
      + ' ( minconf includeempty includeWatchonly )');
  }

  if (args.length > 0)
    minconf = toNumber(args[0], 0);

  if (args.length > 1)
    includeEmpty = toBool(args[1], false);

  return yield this._listReceived(minconf, includeEmpty, true);
});

RPC.prototype.listreceivedbyaddress = co(function* listreceivedbyaddress(args, help) {
  var minconf = 0;
  var includeEmpty = false;

  if (help || args.length > 3) {
    throw new RPCError('listreceivedbyaddress'
      + ' ( minconf includeempty includeWatchonly )');
  }

  if (args.length > 0)
    minconf = toNumber(args[0], 0);

  if (args.length > 1)
    includeEmpty = toBool(args[1], false);

  return yield this._listReceived(minconf, includeEmpty, false);
});

RPC.prototype._listReceived = co(function* _listReceived(minconf, empty, account) {
  var wallet = this.wallet;
  var out = [];
  var result = [];
  var map = {};
  var paths = yield wallet.getPaths();
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

    conf = wtx.getDepth(this.chain.height);

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
  var minconf = 0;
  var out = [];
  var i, block, highest, height;
  var txs, wtx, json;

  if (help) {
    throw new RPCError('listsinceblock'
      + ' ( "blockhash" target-confirmations includeWatchonly)');
  }

  if (args.length > 0) {
    block = toHash(args[0]);
    if (!block)
      throw new RPCError('Invalid parameter.');
  }

  if (args.length > 1)
    minconf = toNumber(args[1], 0);

  height = yield this.chain.db.getHeight(block);

  if (height === -1)
    height = this.chain.height;

  txs = yield wallet.getHistory();

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];

    if (wtx.height < height)
      continue;

    if (wtx.getDepth(this.chain.height) < minconf)
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
  var sent = 0;
  var received = 0;
  var receive = true;
  var sendMember, recMember, sendIndex, recIndex;
  var i, member, index;
  var details = yield wallet.toDetails(wtx);

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
  var account = null;
  var count = 10;
  var i, txs, wtx, json;

  if (help || args.length > 4) {
    throw new RPCError(
      'listtransactions ( "account" count from includeWatchonly)');
  }

  if (args.length > 0) {
    account = toString(args[0]);
    if (!account)
      account = 'default';
  }

  if (args.length > 1) {
    count = toNumber(args[1], 10);
    if (count < 0)
      count = 10;
  }

  txs = yield wallet.getHistory();

  sortTX(txs);

  for (i = 0; i < txs.length; i++) {
    wtx = txs[i];
    json = yield this._toListTX(wtx);
    txs[i] = json;
  }

  return txs;
});

RPC.prototype.listunspent = co(function* listunspent(args, help) {
  var wallet = this.wallet;
  var minDepth = 1;
  var maxDepth = 9999999;
  var out = [];
  var i, addresses, addrs, depth, address, hash, coins, coin, ring;

  if (help || args.length > 3) {
    throw new RPCError('listunspent'
      + ' ( minconf maxconf  ["address",...] )');
  }

  if (args.length > 0)
    minDepth = toNumber(args[0], 1);

  if (args.length > 1)
    maxDepth = toNumber(args[1], maxDepth);

  if (args.length > 2)
    addrs = toArray(args[2]);

  if (addrs) {
    addresses = {};
    for (i = 0; i < addrs.length; i++) {
      address = toString(addrs[i]);
      hash = Address.getHash(address, 'hex');

      if (!hash)
        throw new RPCError('Invalid address.');

      if (addresses[hash])
        throw new RPCError('Duplicate address.');

      addresses[hash] = true;
    }
  }

  coins = yield wallet.getCoins();

  sortCoins(coins);

  for (i = 0; i < coins.length; i++ ) {
    coin = coins[i];
    depth = coin.getDepth(this.chain.height);

    if (!(depth >= minDepth && depth <= maxDepth))
      continue;

    address = coin.getAddress();

    if (!address)
      continue;

    hash = coin.getHash('hex');

    if (addresses) {
      if (!hash || !addresses[hash])
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
  var i, unlock, outputs, output, outpoint;

  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError('lockunspent'
      + ' unlock ([{"txid":"txid","vout":n},...])');
  }

  unlock = toBool(args[0]);

  if (args.length === 1) {
    if (unlock)
      wallet.unlockCoins();
    return true;
  }

  outputs = toArray(args[1]);

  if (!outputs)
    throw new RPCError('Invalid parameter.');

  for (i = 0; i < outputs.length; i++) {
    output = outputs[i];

    if (!output || typeof output !== 'object')
      throw new RPCError('Invalid parameter.');

    outpoint = new Outpoint();
    outpoint.hash = toHash(output.txid);
    outpoint.index = toNumber(output.vout);

    if (!outpoint.hash)
      throw new RPCError('Invalid parameter.');

    if (outpoint.index < 0)
      throw new RPCError('Invalid parameter.');

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

RPC.prototype._send = co(function* _send(account, address, amount, subtractFee) {
  var wallet = this.wallet;
  var tx, options;

  options = {
    account: account,
    subtractFee: subtractFee,
    rate: this.feeRate,
    outputs: [{
      address: address,
      value: amount
    }]
  };

  tx = yield wallet.send(options);

  return tx.txid();
});

RPC.prototype.sendfrom = co(function* sendfrom(args, help) {
  var account, address, amount;

  if (help || args.length < 3 || args.length > 6) {
    throw new RPCError('sendfrom'
      + ' "fromaccount" "tobitcoinaddress"'
      + ' amount ( minconf "comment" "comment-to" )');
  }

  account = toString(args[0]);
  address = Address.fromBase58(toString(args[1]), this.network);
  amount = toSatoshi(args[2]);

  if (!account)
    account = 'default';

  return yield this._send(account, address, amount, false);
});

RPC.prototype.sendmany = co(function* sendmany(args, help) {
  var wallet = this.wallet;
  var minconf = 1;
  var outputs = [];
  var uniq = {};
  var account, sendTo, comment, subtractFee;
  var i, keys, tx, key, value, address;
  var hash, output, options;

  if (help || args.length < 2 || args.length > 5) {
    throw new RPCError('sendmany'
      + ' "fromaccount" {"address":amount,...}'
      + ' ( minconf "comment" ["address",...] )');
  }

  account = toString(args[0]);
  sendTo = toObject(args[1]);

  if (!account)
    account = 'default';

  if (!sendTo)
    throw new RPCError('Invalid parameter.');

  if (args.length > 2)
    minconf = toNumber(args[2], 1);

  if (args.length > 3)
    comment = toString(args[3]);

  if (args.length > 4) {
    subtractFee = args[4];
    if (typeof subtractFee !== 'boolean') {
      if (!util.isNumber(subtractFee))
        throw new RPCError('Invalid parameter.');
    }
  }

  keys = Object.keys(sendTo);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    value = toSatoshi(sendTo[key]);
    address = Address.fromBase58(key, this.network);
    hash = address.getHash('hex');

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
    account: account,
    depth: minconf
  };

  tx = yield wallet.send(options);

  return tx.txid();
});

RPC.prototype.sendtoaddress = co(function* sendtoaddress(args, help) {
  var address, amount, subtractFee;

  if (help || args.length < 2 || args.length > 5) {
    throw new RPCError('sendtoaddress'
      + ' "bitcoinaddress" amount'
      + ' ( "comment" "comment-to"'
      + ' subtractfeefromamount )');
  }

  address = Address.fromBase58(toString(args[0]), this.network);
  amount = toSatoshi(args[1]);
  subtractFee = toBool(args[4]);

  return yield this._send(null, address, amount, subtractFee);
});

RPC.prototype.setaccount = co(function* setaccount(args, help) {
  if (help || args.length < 1 || args.length > 2)
    throw new RPCError('setaccount "bitcoinaddress" "account"');

  // Impossible to implement in bcoin:
  throw new Error('Not implemented.');
});

RPC.prototype.settxfee = co(function* settxfee(args, help) {
  if (help || args.length < 1 || args.length > 1)
    throw new RPCError('settxfee amount');

  this.feeRate = toSatoshi(args[0]);

  return true;
});

RPC.prototype.signmessage = co(function* signmessage(args, help) {
  var wallet = this.wallet;
  var address, msg, sig, ring;

  if (help || args.length !== 2)
    throw new RPCError('signmessage "bitcoinaddress" "message"');

  address = toString(args[0]);
  msg = toString(args[1]);

  address = Address.getHash(address, 'hex');

  if (!address)
    throw new RPCError('Invalid address.');

  ring = yield wallet.getKey(address);

  if (!ring)
    throw new RPCError('Address not found.');

  if (!wallet.master.key)
    throw new RPCError('Wallet is locked.');

  msg = new Buffer(RPC.magic + msg, 'utf8');
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
  var old, new_;

  if (help || (wallet.master.encrypted && args.length !== 2)) {
    throw new RPCError('walletpassphrasechange'
      + ' "oldpassphrase" "newpassphrase"');
  }

  if (!wallet.master.encrypted)
    throw new RPCError('Wallet is not encrypted.');

  old = toString(args[0]);
  new_ = toString(args[1]);

  if (old.length < 1 || new_.length < 1)
    throw new RPCError('Invalid parameter');

  yield wallet.setPassphrase(old, new_);

  return null;
});

RPC.prototype.walletpassphrase = co(function* walletpassphrase(args, help) {
  var wallet = this.wallet;
  var passphrase, timeout;

  if (help || (wallet.master.encrypted && args.length !== 2))
    throw new RPCError('walletpassphrase "passphrase" timeout');

  if (!wallet.master.encrypted)
    throw new RPCError('Wallet is not encrypted.');

  passphrase = toString(args[0]);
  timeout = toNumber(args[1]);

  if (passphrase.length < 1)
    throw new RPCError('Invalid parameter');

  if (timeout < 0)
    throw new RPCError('Invalid parameter');

  yield wallet.unlock(passphrase, timeout);

  return null;
});

RPC.prototype.importprunedfunds = co(function* importprunedfunds(args, help) {
  var tx, block, hash, label, height;

  if (help || args.length < 2 || args.length > 3) {
    throw new RPCError('importprunedfunds'
      + ' "rawtransaction" "txoutproof" ( "label" )');
  }

  tx = args[0];
  block = args[1];

  if (!util.isHex(tx) || !util.isHex(block))
    throw new RPCError('Invalid parameter.');

  tx = TX.fromRaw(tx, 'hex');
  block = MerkleBlock.fromRaw(block, 'hex');
  hash = block.hash('hex');

  if (args.length === 3)
    label = toString(args[2]);

  if (!block.verify())
    throw new RPCError('Invalid proof.');

  if (!block.hasTX(tx.hash('hex')))
    throw new RPCError('Invalid proof.');

  height = yield this.chain.db.getHeight(hash);

  if (height === -1)
    throw new RPCError('Invalid proof.');

  block = {
    hash: hash,
    ts: block.ts,
    height: height
  };

  if (!(yield this.walletdb.addTX(tx, block)))
    throw new RPCError('No tracked address for TX.');

  return null;
});

RPC.prototype.removeprunedfunds = co(function* removeprunedfunds(args, help) {
  var wallet = this.wallet;
  var hash;

  if (help || args.length !== 1)
    throw new RPCError('removeprunedfunds "txid"');

  hash = toHash(args[0]);

  if (!hash)
    throw new RPCError('Invalid parameter.');

  if (!(yield wallet.remove(hash)))
    throw new RPCError('Transaction not in wallet.');

  return null;
});

RPC.prototype.selectwallet = co(function* selectwallet(args, help) {
  var id, wallet;

  if (help || args.length !== 1)
    throw new RPCError('selectwallet "id"');

  id = toString(args[0]);
  wallet = yield this.walletdb.get(id);

  if (!wallet)
    throw new RPCError('Wallet not found.');

  this.wallet = wallet;

  return null;
});

/*
 * Helpers
 */

function RPCError(msg) {
  Error.call(this);

  if (Error.captureStackTrace)
    Error.captureStackTrace(this, RPCError);

  this.type = 'RPCError';
  this.message = msg;
}

util.inherits(RPCError, Error);

function toBool(obj, def) {
  if (typeof obj === 'boolean' || typeof obj === 'number')
    return !!obj;
  return def || false;
}

function toNumber(obj, def) {
  if (util.isNumber(obj))
    return obj;
  return def != null ? def : -1;
}

function toString(obj, def) {
  if (typeof obj === 'string')
    return obj;
  return def != null ? def : '';
}

function toArray(obj, def) {
  if (Array.isArray(obj))
    return obj;
  return def != null ? def : null;
}

function toObject(obj, def) {
  if (obj && typeof obj === 'object')
    return obj;
  return def != null ? def : null;
}

function toHash(obj) {
  if (!isHash(obj))
    return null;
  return util.revHex(obj);
}

function isHash(obj) {
  return util.isHex(obj) && obj.length === 64;
}

function toSatoshi(obj) {
  if (typeof obj !== 'number')
    throw new RPCError('Bad BTC amount.');
  return Amount.value(obj, true);
}

function sortTX(txs) {
  return txs.sort(function(a, b) {
    return a.ps - b.ps;
  });
}

function sortCoins(coins) {
  return coins.sort(function(a, b) {
    a = a.height === -1 ? 0x7fffffff : a.height;
    b = b.height === -1 ? 0x7fffffff : b.height;
    return a - b;
  });
}

/*
 * Expose
 */

module.exports = RPC;
