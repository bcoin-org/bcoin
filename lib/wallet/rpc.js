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

  this.init();
}

Object.setPrototypeOf(RPC.prototype, RPCBase.prototype);

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

RPC.prototype.help = async function help(args, _help) {
  if (args.length === 0)
    return 'Select a command.';

  const json = {
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
  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'fundrawtransaction "hexstring" ( options )');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const data = valid.buf(0);
  const options = valid.obj(1);

  if (!data)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid hex string.');

  const tx = MTX.fromRaw(data);

  if (tx.outputs.length === 0) {
    throw new RPCError(errs.INVALID_PARAMETER,
      'TX must have at least one output.');
  }

  let rate = null;
  let change = null;

  if (options) {
    const valid = new Validator([options]);

    rate = valid.ufixed('feeRate', 8);
    change = valid.str('changeAddress');

    if (change)
      change = parseAddress(change, this.network);
  }

  await wallet.fund(tx, {
    rate: rate,
    changeAddress: change
  });

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
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'resendwallettransactions');

  const wallet = this.wallet;
  const txs = await wallet.resend();
  const hashes = [];

  for (const tx of txs)
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
  const valid = new Validator([args]);
  const dest = valid.str(0);

  if (help || args.length !== 1 || !dest)
    throw new RPCError(errs.MISC_ERROR, 'backupwallet "destination"');

  await this.wdb.backup(dest);

  return null;
};

RPC.prototype.dumpPrivKey = async function dumpPrivKey(args, help) {
  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'dumpprivkey "bitcoinaddress"');

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const addr = valid.str(0, '');

  const hash = parseHash(addr, this.network);
  const ring = await wallet.getPrivateKey(hash);

  if (!ring)
    throw new RPCError(errs.MISC_ERROR, 'Key not found.');

  return ring.toSecret();
};

RPC.prototype.dumpWallet = async function dumpWallet(args, help) {
  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'dumpwallet "filename"');

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const file = valid.str(0);

  if (!file)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  const tip = await this.wdb.getTip();
  const time = util.date();

  const out = [
    util.fmt('# Wallet Dump created by Bcoin %s', pkg.version),
    util.fmt('# * Created on %s', time),
    util.fmt('# * Best block at time of backup was %d (%s).',
      tip.height, util.revHex(tip.hash)),
    util.fmt('# * File: %s', file),
    ''
  ];

  const hashes = await wallet.getAddressHashes();

  for (const hash of hashes) {
    const ring = await wallet.getPrivateKey(hash);

    if (!ring)
      continue;

    const addr = ring.getAddress('string');

    let fmt = '%s %s label= addr=%s';

    if (ring.branch === 1)
      fmt = '%s %s change=1 addr=%s';

    const str = util.fmt(fmt, ring.toSecret(), time, addr);

    out.push(str);
  }

  out.push('');
  out.push('# End of dump');
  out.push('');

  const dump = out.join('\n');

  if (fs.unsupported)
    return dump;

  await fs.writeFile(file, dump, 'utf8');

  return null;
};

RPC.prototype.encryptWallet = async function encryptWallet(args, help) {
  const wallet = this.wallet;

  if (!wallet.master.encrypted && (help || args.length !== 1))
    throw new RPCError(errs.MISC_ERROR, 'encryptwallet "passphrase"');

  const valid = new Validator([args]);
  const passphrase = valid.str(0, '');

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
  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'getaccountaddress "account"');

  const wallet = this.wallet;
  const valid = new Validator([args]);
  let name = valid.str(0, '');

  if (!name)
    name = 'default';

  const account = await wallet.getAccount(name);

  if (!account)
    return '';

  return account.receive.getAddress('string');
};

RPC.prototype.getAccount = async function getAccount(args, help) {
  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'getaccount "bitcoinaddress"');

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const addr = valid.str(0, '');

  const hash = parseHash(addr, this.network);
  const path = await wallet.getPath(hash);

  if (!path)
    return '';

  return path.name;
};

RPC.prototype.getAddressesByAccount = async function getAddressesByAccount(args, help) {
  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'getaddressesbyaccount "account"');

  const wallet = this.wallet;
  const valid = new Validator([args]);
  let name = valid.str(0, '');
  const addrs = [];

  if (name === '')
    name = 'default';

  const paths = await wallet.getPaths(name);

  for (const path of paths) {
    const addr = path.toAddress();
    addrs.push(addr.toString(this.network));
  }

  return addrs;
};

RPC.prototype.getBalance = async function getBalance(args, help) {
  if (help || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'getbalance ( "account" minconf includeWatchonly )');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  let name = valid.str(0);
  const minconf = valid.u32(1, 1);
  const watchOnly = valid.bool(2, false);

  if (name === '')
    name = 'default';

  if (name === '*')
    name = null;

  if (wallet.watchOnly !== watchOnly)
    return 0;

  const balance = await wallet.getBalance(name);

  let value;
  if (minconf > 0)
    value = balance.confirmed;
  else
    value = balance.unconfirmed;

  return Amount.btc(value, true);
};

RPC.prototype.getNewAddress = async function getNewAddress(args, help) {
  if (help || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'getnewaddress ( "account" )');

  const wallet = this.wallet;
  const valid = new Validator([args]);
  let name = valid.str(0);

  if (name === '')
    name = 'default';

  const addr = await wallet.createReceive(name);

  return addr.getAddress('string');
};

RPC.prototype.getRawChangeAddress = async function getRawChangeAddress(args, help) {
  if (help || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'getrawchangeaddress');

  const wallet = this.wallet;
  const addr = await wallet.createChange();

  return addr.getAddress('string');
};

RPC.prototype.getReceivedByAccount = async function getReceivedByAccount(args, help) {
  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'getreceivedbyaccount "account" ( minconf )');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  let name = valid.str(0);
  const minconf = valid.u32(1, 0);
  const height = this.wdb.state.height;

  if (name === '')
    name = 'default';

  const paths = await wallet.getPaths(name);
  const filter = new Set();

  for (const path of paths)
    filter.add(path.hash);

  const txs = await wallet.getHistory(name);

  let total = 0;
  let lastConf = -1;

  for (const wtx of txs) {
    const conf = wtx.getDepth(height);

    if (conf < minconf)
      continue;

    if (lastConf === -1 || conf < lastConf)
      lastConf = conf;

    for (const output of wtx.tx.outputs) {
      const hash = output.getHash('hex');
      if (hash && filter.has(hash))
        total += output.value;
    }
  }

  return Amount.btc(total, true);
};

RPC.prototype.getReceivedByAddress = async function getReceivedByAddress(args, help) {
  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'getreceivedbyaddress "bitcoinaddress" ( minconf )');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const addr = valid.str(0, '');
  const minconf = valid.u32(1, 0);
  const height = this.wdb.state.height;

  const hash = parseHash(addr, this.network);
  const txs = await wallet.getHistory();

  let total = 0;

  for (const wtx of txs) {
    if (wtx.getDepth(height) < minconf)
      continue;

    for (const output of wtx.tx.outputs) {
      if (output.getHash('hex') === hash)
        total += output.value;
    }
  }

  return Amount.btc(total, true);
};

RPC.prototype._toWalletTX = async function _toWalletTX(wtx) {
  const wallet = this.wallet;
  const details = await wallet.toDetails(wtx);

  if (!details)
    throw new RPCError(errs.WALLET_ERROR, 'TX not found.');

  let receive = true;
  for (const member of details.inputs) {
    if (member.path) {
      receive = false;
      break;
    }
  }

  const det = [];
  let sent = 0;
  let received = 0;

  for (let i = 0; i < details.outputs.length; i++) {
    const member = details.outputs[i];

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
    blocktime: details.time,
    txid: util.revHex(details.hash),
    walletconflicts: [],
    time: details.mtime,
    timereceived: details.mtime,
    'bip125-replaceable': 'no',
    details: det,
    hex: details.tx.toRaw().toString('hex')
  };
};

RPC.prototype.getTransaction = async function getTransaction(args, help) {
  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'gettransaction "txid" ( includeWatchonly )');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const hash = valid.hash(0);
  const watchOnly = valid.bool(1, false);

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter');

  const wtx = await wallet.getTX(hash);

  if (!wtx)
    throw new RPCError(errs.WALLET_ERROR, 'TX not found.');

  return await this._toWalletTX(wtx, watchOnly);
};

RPC.prototype.abandonTransaction = async function abandonTransaction(args, help) {
  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'abandontransaction "txid"');

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const hash = valid.hash(0);

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  const result = await wallet.abandon(hash);

  if (!result)
    throw new RPCError(errs.WALLET_ERROR, 'Transaction not in wallet.');

  return null;
};

RPC.prototype.getUnconfirmedBalance = async function getUnconfirmedBalance(args, help) {
  if (help || args.length > 0)
    throw new RPCError(errs.MISC_ERROR, 'getunconfirmedbalance');

  const wallet = this.wallet;
  const balance = await wallet.getBalance();

  return Amount.btc(balance.unconfirmed, true);
};

RPC.prototype.getWalletInfo = async function getWalletInfo(args, help) {
  if (help || args.length !== 0)
    throw new RPCError(errs.MISC_ERROR, 'getwalletinfo');

  const wallet = this.wallet;
  const balance = await wallet.getBalance();

  return {
    walletid: wallet.id,
    walletversion: 6,
    balance: Amount.btc(balance.unconfirmed, true),
    unconfirmed_balance: Amount.btc(balance.unconfirmed, true),
    txcount: wallet.txdb.state.tx,
    keypoololdest: 0,
    keypoolsize: 0,
    unlocked_until: wallet.master.until,
    paytxfee: Amount.btc(this.wdb.feeRate, true)
  };
};

RPC.prototype.importPrivKey = async function importPrivKey(args, help) {
  if (help || args.length < 1 || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'importprivkey "bitcoinprivkey" ( "label" rescan )');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const secret = valid.str(0);
  const rescan = valid.bool(2, false);

  const key = parseSecret(secret, this.network);

  await wallet.importKey(0, key);

  if (rescan)
    await this.wdb.rescan(0);

  return null;
};

RPC.prototype.importWallet = async function importWallet(args, help) {
  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'importwallet "filename" ( rescan )');

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const file = valid.str(0);
  const rescan = valid.bool(1, false);

  if (fs.unsupported)
    throw new RPCError(errs.INTERNAL_ERROR, 'FS not available.');

  const data = await fs.readFile(file, 'utf8');
  const lines = data.split(/\n+/);
  const keys = [];

  for (let line of lines) {
    line = line.trim();

    if (line.length === 0)
      continue;

    if (/^\s*#/.test(line))
      continue;

    const parts = line.split(/\s+/);

    if (parts.length < 4)
      throw new RPCError(errs.DESERIALIZATION_ERROR, 'Malformed wallet.');

    const secret = parseSecret(parts[0], this.network);

    keys.push(secret);
  }

  for (const key of keys)
    await wallet.importKey(0, key);

  if (rescan)
    await this.wdb.rescan(0);

  return null;
};

RPC.prototype.importAddress = async function importAddress(args, help) {
  if (help || args.length < 1 || args.length > 4) {
    throw new RPCError(errs.MISC_ERROR,
      'importaddress "address" ( "label" rescan p2sh )');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  let addr = valid.str(0, '');
  const rescan = valid.bool(2, false);
  const p2sh = valid.bool(3, false);

  if (p2sh) {
    let script = valid.buf(0);

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
  if (help || args.length < 1 || args.length > 4) {
    throw new RPCError(errs.MISC_ERROR,
      'importpubkey "pubkey" ( "label" rescan )');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const data = valid.buf(0);
  const rescan = valid.bool(2, false);

  if (!data)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  const key = KeyRing.fromPublic(data, this.network);

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
  if (help || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'listaccounts ( minconf includeWatchonly)');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const minconf = valid.u32(0, 0);
  const watchOnly = valid.bool(1, false);

  const accounts = await wallet.getAccounts();
  const map = {};

  for (const account of accounts) {
    const balance = await wallet.getBalance(account);
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
  if (help || args.length > 0)
    throw new RPCError(errs.MISC_ERROR, 'listlockunspent');

  const wallet = this.wallet;
  const outpoints = wallet.getLocked();
  const out = [];

  for (const outpoint of outpoints) {
    out.push({
      txid: outpoint.txid(),
      vout: outpoint.index
    });
  }

  return out;
};

RPC.prototype.listReceivedByAccount = async function listReceivedByAccount(args, help) {
  if (help || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'listreceivedbyaccount ( minconf includeempty includeWatchonly )');
  }

  const valid = new Validator([args]);
  const minconf = valid.u32(0, 0);
  const includeEmpty = valid.bool(1, false);
  const watchOnly = valid.bool(2, false);

  return await this._listReceived(minconf, includeEmpty, watchOnly, true);
};

RPC.prototype.listReceivedByAddress = async function listReceivedByAddress(args, help) {
  if (help || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'listreceivedbyaddress ( minconf includeempty includeWatchonly )');
  }

  const valid = new Validator([args]);
  const minconf = valid.u32(0, 0);
  const includeEmpty = valid.bool(1, false);
  const watchOnly = valid.bool(2, false);

  return await this._listReceived(minconf, includeEmpty, watchOnly, false);
};

RPC.prototype._listReceived = async function _listReceived(minconf, empty, watchOnly, account) {
  const wallet = this.wallet;
  const paths = await wallet.getPaths();
  const height = this.wdb.state.height;

  const map = new Map();
  for (const path of paths) {
    const addr = path.toAddress();
    map.set(path.hash, {
      involvesWatchonly: wallet.watchOnly,
      address: addr.toString(this.network),
      account: path.name,
      amount: 0,
      confirmations: -1,
      label: ''
    });
  }

  const txs = await wallet.getHistory();

  for (const wtx of txs) {
    const conf = wtx.getDepth(height);

    if (conf < minconf)
      continue;

    for (const output of wtx.tx.outputs) {
      const addr = output.getAddress();

      if (!addr)
        continue;

      const hash = addr.getHash('hex');
      const entry = map.get(hash);

      if (entry) {
        if (entry.confirmations === -1 || conf < entry.confirmations)
          entry.confirmations = conf;
        entry.address = addr.toString(this.network);
        entry.amount += output.value;
      }
    }
  }

  let out = [];
  for (const entry of map.values())
    out.push(entry);

  if (account) {
    const map = new Map();

    for (const entry of out) {
      const item = map.get(entry.account);
      if (!item) {
        map.set(entry.account, entry);
        entry.address = undefined;
        continue;
      }
      item.amount += entry.amount;
    }

    out = [];

    for (const entry of map.values())
      out.push(entry);
  }

  const result = [];
  for (const entry of out) {
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
  const wallet = this.wallet;
  const chainHeight = this.wdb.state.height;
  const valid = new Validator([args]);
  const block = valid.hash(0);
  const minconf = valid.u32(1, 0);
  const watchOnly = valid.bool(2, false);

  if (help) {
    throw new RPCError(errs.MISC_ERROR,
      'listsinceblock ( "blockhash" target-confirmations includeWatchonly)');
  }

  if (wallet.watchOnly !== watchOnly)
    return [];

  let height = -1;
  if (block) {
    const entry = await this.client.getEntry(block);
    if (entry)
      height = entry.height;
  }

  if (height === -1)
    height = this.chain.height;

  const txs = await wallet.getHistory();

  const out = [];
  let highest;
  for (const wtx of txs) {
    if (wtx.height < height)
      continue;

    if (wtx.getDepth(chainHeight) < minconf)
      continue;

    if (!highest || wtx.height > highest)
      highest = wtx;

    const json = await this._toListTX(wtx);

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
  const wallet = this.wallet;
  const details = await wallet.toDetails(wtx);

  if (!details)
    throw new RPCError(errs.WALLET_ERROR, 'TX not found.');

  let receive = true;
  for (const member of details.inputs) {
    if (member.path) {
      receive = false;
      break;
    }
  }

  let sent = 0;
  let received = 0;
  let sendMember, recMember, sendIndex, recIndex;
  for (let i = 0; i < details.outputs.length; i++) {
    const member = details.outputs[i];

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

  let member, index;
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
    blocktime: details.time,
    txid: util.revHex(details.hash),
    walletconflicts: [],
    time: details.mtime,
    timereceived: details.mtime,
    'bip125-replaceable': 'no'
  };
};

RPC.prototype.listTransactions = async function listTransactions(args, help) {
  if (help || args.length > 4) {
    throw new RPCError(errs.MISC_ERROR,
      'listtransactions ( "account" count from includeWatchonly)');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  let name = valid.str(0);
  const count = valid.u32(1, 10);
  const from = valid.u32(2, 0);
  const watchOnly = valid.bool(3, false);

  if (wallet.watchOnly !== watchOnly)
    return [];

  if (name === '')
    name = 'default';

  const txs = await wallet.getHistory();

  common.sortTX(txs);

  const end = from + count;
  const to = Math.min(end, txs.length);
  const out = [];

  for (let i = from; i < to; i++) {
    const wtx = txs[i];
    const json = await this._toListTX(wtx);
    out.push(json);
  }

  return out;
};

RPC.prototype.listUnspent = async function listUnspent(args, help) {
  if (help || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'listunspent ( minconf maxconf  ["address",...] )');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const minDepth = valid.u32(0, 1);
  const maxDepth = valid.u32(1, 9999999);
  const addrs = valid.array(2);
  const height = this.wdb.state.height;

  const map = new Set();

  if (addrs) {
    const valid = new Validator([addrs]);
    for (let i = 0; i < addrs.length; i++) {
      const addr = valid.str(i, '');
      const hash = parseHash(addr, this.network);

      if (map.has(hash))
        throw new RPCError(errs.INVALID_PARAMETER, 'Duplicate address.');

      map.add(hash);
    }
  }

  const coins = await wallet.getCoins();

  common.sortCoins(coins);

  const out = [];

  for (const coin of coins) {
    const depth = coin.getDepth(height);

    if (depth < minDepth || depth > maxDepth)
      continue;

    const addr = coin.getAddress();

    if (!addr)
      continue;

    const hash = coin.getHash('hex');

    if (addrs) {
      if (!hash || !map.has(hash))
        continue;
    }

    const ring = await wallet.getKey(hash);

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
  if (help || args.length < 1 || args.length > 2) {
    throw new RPCError(errs.MISC_ERROR,
      'lockunspent unlock ([{"txid":"txid","vout":n},...])');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const unlock = valid.bool(0, false);
  const outputs = valid.array(1);

  if (args.length === 1) {
    if (unlock)
      wallet.unlockCoins();
    return true;
  }

  if (!outputs)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  for (const output of outputs) {
    const valid = new Validator([output]);
    const hash = valid.hash('txid');
    const index = valid.u32('vout');

    if (hash == null || index == null)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid parameter.');

    const outpoint = new Outpoint(hash, index);

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
  if (help || args.length < 3 || args.length > 6) {
    throw new RPCError(errs.MISC_ERROR,
      'sendfrom "fromaccount" "tobitcoinaddress"'
      + ' amount ( minconf "comment" "comment-to" )');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  let name = valid.str(0);
  const str = valid.str(1);
  const value = valid.ufixed(2, 8);
  const minconf = valid.u32(3, 0);

  const addr = parseAddress(str, this.network);

  if (!addr || value == null)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  if (name === '')
    name = 'default';

  const options = {
    account: name,
    depth: minconf,
    outputs: [{
      address: addr,
      value: value
    }]
  };

  const tx = await wallet.send(options);

  return tx.txid();
};

RPC.prototype.sendMany = async function sendMany(args, help) {
  if (help || args.length < 2 || args.length > 5) {
    throw new RPCError(errs.MISC_ERROR,
      'sendmany "fromaccount" {"address":amount,...}'
      + ' ( minconf "comment" ["address",...] )');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  let name = valid.str(0);
  const sendTo = valid.obj(1);
  const minconf = valid.u32(2, 1);
  const subtract = valid.bool(4, false);

  if (name === '')
    name = 'default';

  if (!sendTo)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  const to = new Validator([sendTo]);
  const uniq = new Set();
  const outputs = [];

  for (const key of Object.keys(sendTo)) {
    const value = to.ufixed(key, 8);
    const addr = parseAddress(key, this.network);
    const hash = addr.getHash('hex');

    if (value == null)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid parameter.');

    if (uniq.has(hash))
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid parameter.');

    uniq.add(hash);

    const output = new Output();
    output.value = value;
    output.script.fromAddress(addr);
    outputs.push(output);
  }

  const options = {
    outputs: outputs,
    subtractFee: subtract,
    account: name,
    depth: minconf
  };

  const tx = await wallet.send(options);

  return tx.txid();
};

RPC.prototype.sendToAddress = async function sendToAddress(args, help) {
  if (help || args.length < 2 || args.length > 5) {
    throw new RPCError(errs.MISC_ERROR,
      'sendtoaddress "bitcoinaddress" amount'
      + ' ( "comment" "comment-to" subtractfeefromamount )');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const str = valid.str(0);
  const value = valid.ufixed(1, 8);
  const subtract = valid.bool(4, false);

  const addr = parseAddress(str, this.network);

  if (!addr || value == null)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  const options = {
    subtractFee: subtract,
    outputs: [{
      address: addr,
      value: value
    }]
  };

  const tx = await wallet.send(options);

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
  const valid = new Validator([args]);
  const rate = valid.ufixed(0, 8);

  if (help || args.length < 1 || args.length > 1)
    throw new RPCError(errs.MISC_ERROR, 'settxfee amount');

  if (rate == null)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  this.wdb.feeRate = rate;

  return true;
};

RPC.prototype.signMessage = async function signMessage(args, help) {
  if (help || args.length !== 2) {
    throw new RPCError(errs.MISC_ERROR,
      'signmessage "bitcoinaddress" "message"');
  }

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const b58 = valid.str(0, '');
  const str = valid.str(1, '');

  const addr = parseHash(b58, this.network);

  const ring = await wallet.getKey(addr);

  if (!ring)
    throw new RPCError(errs.WALLET_ERROR, 'Address not found.');

  if (!wallet.master.key)
    throw new RPCError(errs.WALLET_UNLOCK_NEEDED, 'Wallet is locked.');

  const msg = Buffer.from(MAGIC_STRING + str, 'utf8');
  const hash = digest.hash256(msg);

  const sig = ring.sign(hash);

  return sig.toString('base64');
};

RPC.prototype.walletLock = async function walletLock(args, help) {
  const wallet = this.wallet;

  if (help || (wallet.master.encrypted && args.length !== 0))
    throw new RPCError(errs.MISC_ERROR, 'walletlock');

  if (!wallet.master.encrypted)
    throw new RPCError(errs.WALLET_WRONG_ENC_STATE, 'Wallet is not encrypted.');

  await wallet.lock();

  return null;
};

RPC.prototype.walletPassphraseChange = async function walletPassphraseChange(args, help) {
  const wallet = this.wallet;

  if (help || (wallet.master.encrypted && args.length !== 2)) {
    throw new RPCError(errs.MISC_ERROR, 'walletpassphrasechange'
      + ' "oldpassphrase" "newpassphrase"');
  }

  const valid = new Validator([args]);
  const old = valid.str(0, '');
  const new_ = valid.str(1, '');

  if (!wallet.master.encrypted)
    throw new RPCError(errs.WALLET_WRONG_ENC_STATE, 'Wallet is not encrypted.');

  if (old.length < 1 || new_.length < 1)
    throw new RPCError(errs.INVALID_PARAMETER, 'Invalid parameter');

  await wallet.setPassphrase(old, new_);

  return null;
};

RPC.prototype.walletPassphrase = async function walletPassphrase(args, help) {
  const wallet = this.wallet;
  const valid = new Validator([args]);
  const passphrase = valid.str(0, '');
  const timeout = valid.u32(1);

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
  if (help || args.length < 2 || args.length > 3) {
    throw new RPCError(errs.MISC_ERROR,
      'importprunedfunds "rawtransaction" "txoutproof" ( "label" )');
  }

  const valid = new Validator([args]);
  const txRaw = valid.buf(0);
  const blockRaw = valid.buf(1);

  if (!txRaw || !blockRaw)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  const tx = TX.fromRaw(txRaw);
  const block = MerkleBlock.fromRaw(blockRaw);
  const hash = block.hash('hex');

  if (!block.verify())
    throw new RPCError(errs.VERIFY_ERROR, 'Invalid proof.');

  if (!block.hasTX(tx.hash('hex')))
    throw new RPCError(errs.VERIFY_ERROR, 'Invalid proof.');

  const height = await this.client.getEntry(hash);

  if (height === -1)
    throw new RPCError(errs.VERIFY_ERROR, 'Invalid proof.');

  const entry = {
    hash: hash,
    time: block.time,
    height: height
  };

  if (!await this.wdb.addTX(tx, entry))
    throw new RPCError(errs.WALLET_ERROR, 'No tracked address for TX.');

  return null;
};

RPC.prototype.removePrunedFunds = async function removePrunedFunds(args, help) {
  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'removeprunedfunds "txid"');

  const wallet = this.wallet;
  const valid = new Validator([args]);
  const hash = valid.hash(0);

  if (!hash)
    throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

  if (!await wallet.remove(hash))
    throw new RPCError(errs.WALLET_ERROR, 'Transaction not in wallet.');

  return null;
};

RPC.prototype.selectWallet = async function selectWallet(args, help) {
  const valid = new Validator([args]);
  const id = valid.str(0);

  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'selectwallet "id"');

  const wallet = await this.wdb.get(id);

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
  if (help || args.length !== 1)
    throw new RPCError(errs.MISC_ERROR, 'setloglevel "level"');

  const valid = new Validator([args]);
  const level = valid.str(0, '');

  this.logger.setLevel(level);

  return null;
};

/*
 * Helpers
 */

function parseHash(raw, network) {
  const addr = parseAddress(raw, network);
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
