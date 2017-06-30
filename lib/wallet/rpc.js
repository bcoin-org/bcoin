/*!
 * rpc.js - bitcoind-compatible json rpc for bcoin.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const fs = require('../utils/fs');
const util = require('../utils/util');
const digest = require('../crypto/digest');
const Amount = require('../btc/amount');
const Script = require('../script/script');
const Address = require('../primitives/address');
const KeyRing = require('../primitives/keyring');
const MerkleBlock = require('../primitives/merkleblock');
const MTX = require('../primitives/mtx');
const Outpoint = require('../primitives/outpoint');
const Output = require('../primitives/output');
const TX = require('../primitives/tx');
const encoding = require('../utils/encoding');
const RPCBase = require('../http/rpcbase');
const pkg = require('../pkg');
const Validator = require('../utils/validator');
const common = require('./common');
const RPCError = RPCBase.RPCError;
const errs = RPCBase.errors;
const MAGIC_STRING = RPCBase.MAGIC_STRING;

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
  let json;

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
  let valid = new Validator([args]);
  let data = valid.buf(0);
  let options = valid.obj(1);
  let wallet = this.wallet;
  let rate = this.feeRate;
  let change, tx;

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
  let wallet = this.wallet;
  let hashes = [];
  let txs;

  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'resendwallettransactions');

  txs = await wallet.resend();

  for (let tx of txs)
    hashes.push(tx.txid());

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
  let valid = new Validator([args]);
  let dest = valid.str(0);

  if (help || args.length !== 1 || !dest)
    throw new RPCError(errs.MISC_ERROR, 'backupwallet "destination"');

  await this.wdb.backup(dest);

  return null;
};

RPC.prototype.dumpPrivKey = async function dumpPrivKey(args, help) {
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let addr = valid.str(0, '');
  let hash, ring;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'dumpprivkey "bitcoinaddress"');

  hash = parseHash(addr, this.network);
  ring = await wallet.getPrivateKey(hash);

  if (!ring)
    throw new RPCError(errs.MISC_ERROR, 'Key not found.');

  return ring.toSecret();
};

RPC.prototype.dumpWallet = async function dumpWallet(args, help) {
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let file = valid.str(0);
  let time = util.date();
  let tip, out, hashes;

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

  for (let hash of hashes) {
    let ring = await wallet.getPrivateKey(hash);
    let addr, fmt, str;

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let passphrase = valid.str(0, '');

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
  let valid = new Validator([args]);
  let wallet = this.wallet;
  let name = valid.str(0, '');
  let account;

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let addr = valid.str(0, '');
  let hash, path;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'getaccount "bitcoinaddress"');

  hash = parseHash(addr, this.network);
  path = await wallet.getPath(hash);

  if (!path)
    return '';

  return path.name;
};

RPC.prototype.getAddressesByAccount = async function getAddressesByAccount(args, help) {
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let name = valid.str(0, '');
  let addrs = [];
  let paths;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'getaddressesbyaccount "account"');

  if (name === '')
    name = 'default';

  paths = await wallet.getPaths(name);

  for (let path of paths) {
    let addr = path.toAddress();
    addrs.push(addr.toString(this.network));
  }

  return addrs;
};

RPC.prototype.getBalance = async function getBalance(args, help) {
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let name = valid.str(0);
  let minconf = valid.u32(1, 0);
  let watchOnly = valid.bool(2, false);
  let value, balance;

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let name = valid.str(0);
  let addr;

  if (help || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'getnewaddress ( "account" )');

  if (name === '')
    name = 'default';

  addr = await wallet.createReceive(name);

  return addr.getAddress('string');
};

RPC.prototype.getRawChangeAddress = async function getRawChangeAddress(args, help) {
  let wallet = this.wallet;
  let addr;

  if (help || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'getrawchangeaddress');

  addr = await wallet.createChange();

  return addr.getAddress('string');
};

RPC.prototype.getReceivedByAccount = async function getReceivedByAccount(args, help) {
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let name = valid.str(0);
  let minconf = valid.u32(0, 0);
  let height = this.wdb.state.height;
  let total = 0;
  let filter = {};
  let lastConf = -1;
  let paths, txs;

  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'getreceivedbyaccount "account" ( minconf )');
  }

  if (name === '')
    name = 'default';

  paths = await wallet.getPaths(name);

  for (let path of paths)
    filter[path.hash] = true;

  txs = await wallet.getHistory(name);

  for (let wtx of txs) {
    let conf = wtx.getDepth(height);

    if (conf < minconf)
      continue;

    if (lastConf === -1 || conf < lastConf)
      lastConf = conf;

    for (let output of wtx.tx.outputs) {
      let hash = output.getHash('hex');
      if (hash && filter[hash])
        total += output.value;
    }
  }

  return Amount.btc(total, true);
};

RPC.prototype.getReceivedByAddress = async function getReceivedByAddress(args, help) {
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let addr = valid.str(0, '');
  let minconf = valid.u32(1, 0);
  let height = this.wdb.state.height;
  let total = 0;
  let hash, txs;

  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'getreceivedbyaddress "bitcoinaddress" ( minconf )');
  }

  hash = parseHash(addr, this.network);
  txs = await wallet.getHistory();

  for (let wtx of txs) {
    if (wtx.getDepth(height) < minconf)
      continue;

    for (let output of wtx.tx.outputs) {
      if (output.getHash('hex') === hash)
        total += output.value;
    }
  }

  return Amount.btc(total, true);
};

RPC.prototype._toWalletTX = async function _toWalletTX(wtx) {
  let wallet = this.wallet;
  let details = await wallet.toDetails(wtx);
  let det = [];
  let sent = 0;
  let received = 0;
  let receive = true;

  if (!details)
    throw new RPCError(errs.WALLET_ERROR, 'TX not found.');

  for (let member of details.inputs) {
    if (member.path) {
      receive = false;
      break;
    }
  }

  for (let i = 0; i < details.outputs.length; i++) {
    let member = details.outputs[i];

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let hash = valid.hash(0);
  let watchOnly = valid.bool(1, false);
  let wtx;

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let hash = valid.hash(0);
  let result;

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
  let wallet = this.wallet;
  let balance;

  if (help || args.length > 0)
    throw new RPCError(errs.MISC_ERROR, 'getunconfirmedbalance');

  balance = await wallet.getBalance();

  return Amount.btc(balance.unconfirmed, true);
};

RPC.prototype.getWalletInfo = async function getWalletInfo(args, help) {
  let wallet = this.wallet;
  let balance;

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let secret = valid.str(0);
  let rescan = valid.bool(2, false);
  let key;

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let file = valid.str(0);
  let rescan = valid.bool(1, false);
  let keys = [];
  let data, lines;

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'importwallet "filename" ( rescan )');

  if (fs.unsupported)
    throw new RPCError(errs.INTERNAL_ERROR, 'FS not available.');

  data = await fs.readFile(file, 'utf8');

  lines = data.split(/\n+/);

  for (let line of lines) {
    let parts, secret;

    line = line.trim();

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

  for (let key of keys)
    await wallet.importKey(0, key);

  if (rescan)
    await this.wdb.rescan(0);

  return null;
};

RPC.prototype.importAddress = async function importAddress(args, help) {
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let addr = valid.str(0, '');
  let rescan = valid.bool(2, false);
  let p2sh = valid.bool(3, false);
  let script;

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let data = valid.buf(0);
  let rescan = valid.bool(2, false);
  let key;

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let minconf = valid.u32(0, 0);
  let watchOnly = valid.bool(1, false);
  let map = {};
  let accounts;

  if (help || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'listaccounts ( minconf includeWatchonly)');
  }

  accounts = await wallet.getAccounts();

  for (let account of accounts) {
    let balance = await wallet.getBalance(account);
    let value = balance.unconfirmed;

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
  let wallet = this.wallet;
  let out = [];
  let outpoints;

  if (help || args.length > 0)
    throw new RPCError(errs.MISC_ERROR, 'listlockunspent');

  outpoints = wallet.getLocked();

  for (let outpoint of outpoints) {
    out.push({
      txid: outpoint.txid(),
      vout: outpoint.index
    });
  }

  return out;
};

RPC.prototype.listReceivedByAccount = async function listReceivedByAccount(args, help) {
  let valid = new Validator([args]);
  let minconf = valid.u32(0, 0);
  let includeEmpty = valid.bool(1, false);
  let watchOnly = valid.bool(2, false);

  if (help || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'listreceivedbyaccount ( minconf includeempty includeWatchonly )');
  }

  return await this._listReceived(minconf, includeEmpty, watchOnly, true);
};

RPC.prototype.listReceivedByAddress = async function listReceivedByAddress(args, help) {
  let valid = new Validator([args]);
  let minconf = valid.u32(0, 0);
  let includeEmpty = valid.bool(1, false);
  let watchOnly = valid.bool(2, false);

  if (help || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'listreceivedbyaddress ( minconf includeempty includeWatchonly )');
  }

  return await this._listReceived(minconf, includeEmpty, watchOnly, false);
};

RPC.prototype._listReceived = async function _listReceived(minconf, empty, watchOnly, account) {
  let wallet = this.wallet;
  let paths = await wallet.getPaths();
  let height = this.wdb.state.height;
  let out = [];
  let result = [];
  let map = {};
  let txs, keys;

  for (let path of paths) {
    let addr = path.toAddress();
    map[path.hash] = {
      involvesWatchonly: wallet.watchOnly,
      address: addr.toString(this.network),
      account: path.name,
      amount: 0,
      confirmations: -1,
      label: '',
    };
  }

  txs = await wallet.getHistory();

  for (let wtx of txs) {
    let conf = wtx.getDepth(height);

    if (conf < minconf)
      continue;

    for (let output of wtx.tx.outputs) {
      let addr = output.getAddress();
      let hash, entry;

      if (!addr)
        continue;

      hash = addr.getHash('hex');
      entry = map[hash];

      if (entry) {
        if (entry.confirmations === -1 || conf < entry.confirmations)
          entry.confirmations = conf;
        entry.address = addr.toString(this.network);
        entry.amount += output.value;
      }
    }
  }

  keys = Object.keys(map);

  for (let key of keys) {
    let entry = map[key];
    out.push(entry);
  }

  if (account) {
    let map = {};

    for (let entry of out) {
      let item = map[entry.account];
      if (!item) {
        map[entry.account] = entry;
        entry.address = undefined;
        continue;
      }
      item.amount += entry.amount;
    }

    out = [];

    for (let key of Object.keys(map)) {
      let entry = map[key];
      out.push(entry);
    }
  }

  for (let entry of out) {
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
  let wallet = this.wallet;
  let chainHeight = this.wdb.state.height;
  let valid = new Validator([args]);
  let block = valid.hash(0);
  let minconf = valid.u32(1, 0);
  let watchOnly = valid.bool(2, false);
  let height = -1;
  let out = [];
  let txs, highest;

  if (help) {
    throw new RPCError(errs.MISC_ERROR,
      'listsinceblock ( "blockhash" target-confirmations includeWatchonly)');
  }

  if (wallet.watchOnly !== watchOnly)
    return out;

  if (block) {
    let entry = await this.client.getEntry(block);
    if (entry)
      height = entry.height;
  }

  if (height === -1)
    height = this.chain.height;

  txs = await wallet.getHistory();

  for (let wtx of txs) {
    let json;

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
  let wallet = this.wallet;
  let details = await wallet.toDetails(wtx);
  let sent = 0;
  let received = 0;
  let receive = true;
  let sendMember, recMember, sendIndex, recIndex;
  let member, index;

  if (!details)
    throw new RPCError(errs.WALLET_ERROR, 'TX not found.');

  for (let member of details.inputs) {
    if (member.path) {
      receive = false;
      break;
    }
  }

  for (let i = 0; i < details.outputs.length; i++) {
    let member = details.outputs[i];

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let name = valid.str(0);
  let count = valid.u32(1, 10);
  let from = valid.u32(2, 0);
  let watchOnly = valid.bool(3, false);
  let end = from + count;
  let out = [];
  let txs;

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

  for (let i = from; i < end; i++) {
    let wtx = txs[i];
    let json = await this._toListTX(wtx);
    out.push(json);
  }

  return out;
};

RPC.prototype.listUnspent = async function listUnspent(args, help) {
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let minDepth = valid.u32(0, 1);
  let maxDepth = valid.u32(1, 9999999);
  let addrs = valid.array(2);
  let height = this.wdb.state.height;
  let out = [];
  let map = {};
  let coins;

  if (help || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'listunspent ( minconf maxconf  ["address",...] )');
  }

  if (addrs) {
    let valid = new Validator([addrs]);
    for (let i = 0; i < addrs.length; i++) {
      let addr = valid.str(i, '');
      let hash = parseHash(addr, this.network);

      if (map[hash])
        throw new RPCError(errs.INVALID_PARAMETER, 'Duplicate address.');

      map[hash] = true;
    }
  }

  coins = await wallet.getCoins();

  common.sortCoins(coins);

  for (let coin of coins) {
    let depth = coin.getDepth(height);
    let addr, hash, ring;

    if (!(depth >= minDepth && depth <= maxDepth))
      continue;

    addr = coin.getAddress();

    if (!addr)
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
      address: addr ? addr.toString(this.network) : null,
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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let unlock = valid.bool(0, false);
  let outputs = valid.array(1);

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

  for (let output of outputs) {
    let valid = new Validator([output]);
    let hash = valid.hash('txid');
    let index = valid.u32('vout');
    let outpoint;

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let name = valid.str(0);
  let addr = valid.str(1);
  let value = valid.btc(2);
  let minconf = valid.u32(3, 0);
  let options, tx;

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let name = valid.str(0);
  let sendTo = valid.obj(1);
  let minconf = valid.u32(2, 1);
  let subtractFee = valid.bool(4, false);
  let outputs = [];
  let uniq = {};
  let keys, options, tx;

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

  for (let key of keys) {
    let value = valid.btc(key);
    let addr = parseAddress(key, this.network);
    let hash = addr.getHash('hex');
    let output;

    if (value == null)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid parameter.');

    if (uniq[hash])
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid parameter.');

    uniq[hash] = true;

    output = new Output();
    output.value = value;
    output.script.fromAddress(addr);
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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let addr = valid.str(0);
  let value = valid.btc(1);
  let subtractFee = valid.bool(4, false);
  let options, tx;

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
  let valid = new Validator([args]);
  let rate = valid.btc(0);

  if (help || args.length < 1 || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'settxfee amount');

  if (rate == null)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  this.feeRate = rate;

  return true;
};

RPC.prototype.signMessage = async function signMessage(args, help) {
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let addr = valid.str(0, '');
  let msg = valid.str(1, '');
  let sig, ring;

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
  msg = digest.hash256(msg);

  sig = ring.sign(msg);

  return sig.toString('base64');
};

RPC.prototype.walletLock = async function walletLock(args, help) {
  let wallet = this.wallet;

  if (help || (wallet.master.encrypted && args.length !== 0))
    throw new RPCError(errs.MISC_ERROR, 'walletlock');

  if (!wallet.master.encrypted)
    throw new RPCError(errs.WALLET_WRONG_ENC_STATE, 'Wallet is not encrypted.');

  await wallet.lock();

  return null;
};

RPC.prototype.walletPassphraseChange = async function walletPassphraseChange(args, help) {
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let old = valid.str(0, '');
  let new_ = valid.str(1, '');

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let passphrase = valid.str(0, '');
  let timeout = valid.u32(1);

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
  let valid = new Validator([args]);
  let tx = valid.buf(0);
  let block = valid.buf(1);
  let hash, height;

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
  let wallet = this.wallet;
  let valid = new Validator([args]);
  let hash = valid.hash(0);

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'removeprunedfunds "txid"');

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  if (!(await wallet.remove(hash)))
    throw new RPCError(errs.WALLET_ERROR, 'Transaction not in wallet.');

  return null;
};

RPC.prototype.selectWallet = async function selectWallet(args, help) {
  let valid = new Validator([args]);
  let id = valid.str(0);
  let wallet;

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
  let valid = new Validator([args]);
  let level = valid.str(0, '');

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'setloglevel "level"');

  this.logger.setLevel(level);

  return null;
};

/*
 * Helpers
 */

function parseHash(raw, network) {
  let addr = parseAddress(raw, network);
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
