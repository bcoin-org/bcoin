/*!
 * rpc.js - bitcoind-compatible json rpc for bcoin.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const {format} = require('util');
const bweb = require('bweb');
const {Lock} = require('bmutex');
const fs = require('bfile');
const Validator = require('bval');
const hash256 = require('bcrypto/lib/hash256');
const util = require('../utils/util');
const Amount = require('../btc/amount');
const Script = require('../script/script');
const Address = require('../primitives/address');
const KeyRing = require('../primitives/keyring');
const MerkleBlock = require('../primitives/merkleblock');
const MTX = require('../primitives/mtx');
const Outpoint = require('../primitives/outpoint');
const Output = require('../primitives/output');
const TX = require('../primitives/tx');
const consensus = require('../protocol/consensus');
const pkg = require('../pkg');
const common = require('./common');
const RPCBase = bweb.RPC;
const RPCError = bweb.RPCError;

/*
 * Constants
 */

const errs = {
  // Standard JSON-RPC 2.0 errors
  INVALID_REQUEST: bweb.errors.INVALID_REQUEST,
  METHOD_NOT_FOUND: bweb.errors.METHOD_NOT_FOUND,
  INVALID_PARAMS: bweb.errors.INVALID_PARAMS,
  INTERNAL_ERROR: bweb.errors.INTERNAL_ERROR,
  PARSE_ERROR: bweb.errors.PARSE_ERROR,

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

const MAGIC_STRING = 'Bitcoin Signed Message:\n';

/**
 * Wallet RPC
 * @alias module:wallet.RPC
 * @extends bweb.RPC
 */

class RPC extends RPCBase {
  /**
   * Create an RPC.
   * @param {WalletDB} wdb
   */

  constructor(node) {
    super();

    assert(node, 'RPC requires a WalletDB.');

    this.wdb = node.wdb;
    this.network = node.network;
    this.logger = node.logger.context('rpc');
    this.client = node.client;
    this.locker = new Lock();

    this.wallet = null;

    this.init();
  }

  getCode(err) {
    switch (err.type) {
      case 'RPCError':
        return err.code;
      case 'ValidationError':
        return errs.TYPE_ERROR;
      case 'EncodingError':
        return errs.DESERIALIZATION_ERROR;
      case 'FundingError':
        return errs.WALLET_INSUFFICIENT_FUNDS;
      default:
        return errs.INTERNAL_ERROR;
    }
  }

  init() {
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
  }

  async help(args, _help) {
    if (args.length === 0)
      return 'Select a command.';

    const json = {
      method: args[0],
      params: []
    };

    return await this.execute(json, true);
  }

  async stop(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'stop');

    this.wdb.close();

    return 'Stopping.';
  }

  async fundRawTransaction(args, help) {
    if (help || args.length < 1 || args.length > 2) {
      throw new RPCError(errs.MISC_ERROR,
        'fundrawtransaction "hexstring" ( options )');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
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
      const valid = new Validator(options);

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
  }

  /*
   * Wallet
   */

  async resendWalletTransactions(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'resendwallettransactions');

    const wallet = this.wallet;
    const txs = await wallet.resend();
    const hashes = [];

    for (const tx of txs)
      hashes.push(tx.txid());

    return hashes;
  }

  async addMultisigAddress(args, help) {
    if (help || args.length < 2 || args.length > 3) {
      throw new RPCError(errs.MISC_ERROR,
        'addmultisigaddress nrequired ["key",...] ( "account" )');
    }

    // Impossible to implement in bcoin (no address book).
    throw new Error('Not implemented.');
  }

  async addWitnessAddress(args, help) {
    if (help || args.length < 1 || args.length > 1)
      throw new RPCError(errs.MISC_ERROR, 'addwitnessaddress "address"');

    // Unlikely to be implemented.
    throw new Error('Not implemented.');
  }

  async backupWallet(args, help) {
    const valid = new Validator(args);
    const dest = valid.str(0);

    if (help || args.length !== 1 || !dest)
      throw new RPCError(errs.MISC_ERROR, 'backupwallet "destination"');

    await this.wdb.backup(dest);

    return null;
  }

  async dumpPrivKey(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'dumpprivkey "bitcoinaddress"');

    const wallet = this.wallet;
    const valid = new Validator(args);
    const addr = valid.str(0, '');

    const hash = parseHash(addr, this.network);
    const ring = await wallet.getPrivateKey(hash);

    if (!ring)
      throw new RPCError(errs.MISC_ERROR, 'Key not found.');

    return ring.toSecret(this.network);
  }

  async dumpWallet(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'dumpwallet "filename"');

    const wallet = this.wallet;
    const valid = new Validator(args);
    const file = valid.str(0);

    if (!file)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

    const tip = await this.wdb.getTip();
    const time = util.date();

    const out = [
      format('# Wallet Dump created by Bcoin %s', pkg.version),
      format('# * Created on %s', time),
      format('# * Best block at time of backup was %d (%s).',
        tip.height, util.revHex(tip.hash)),
      format('# * File: %s', file),
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

      const str = format(fmt, ring.toSecret(this.network), time, addr);

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
  }

  async encryptWallet(args, help) {
    const wallet = this.wallet;

    if (!wallet.master.encrypted && (help || args.length !== 1))
      throw new RPCError(errs.MISC_ERROR, 'encryptwallet "passphrase"');

    const valid = new Validator(args);
    const passphrase = valid.str(0, '');

    if (wallet.master.encrypted) {
      throw new RPCError(errs.WALLET_WRONG_ENC_STATE,
        'Already running with an encrypted wallet.');
    }

    if (passphrase.length < 1)
      throw new RPCError(errs.MISC_ERROR, 'encryptwallet "passphrase"');

    try {
      await wallet.encrypt(passphrase);
    } catch (e) {
      throw new RPCError(errs.WALLET_ENCRYPTION_FAILED, 'Encryption failed.');
    }

    return 'wallet encrypted; we do not need to stop!';
  }

  async getAccountAddress(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'getaccountaddress "account"');

    const wallet = this.wallet;
    const valid = new Validator(args);
    let name = valid.str(0, '');

    if (!name)
      name = 'default';

    const addr = await wallet.receiveAddress(name);

    if (!addr)
      return '';

    return addr.toString(this.network);
  }

  async getAccount(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'getaccount "bitcoinaddress"');

    const wallet = this.wallet;
    const valid = new Validator(args);
    const addr = valid.str(0, '');

    const hash = parseHash(addr, this.network);
    const path = await wallet.getPath(hash);

    if (!path)
      return '';

    return path.name;
  }

  async getAddressesByAccount(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'getaddressesbyaccount "account"');

    const wallet = this.wallet;
    const valid = new Validator(args);
    let name = valid.str(0, '');
    const addrs = [];

    if (name === '')
      name = 'default';

    let paths;
    try {
      paths = await wallet.getPaths(name);
    } catch (e) {
      if (e.message === 'Account not found.')
        return [];
      throw e;
    }

    for (const path of paths) {
      const addr = path.toAddress();
      addrs.push(addr.toString(this.network));
    }

    return addrs;
  }

  async getBalance(args, help) {
    if (help || args.length > 3) {
      throw new RPCError(errs.MISC_ERROR,
        'getbalance ( "account" minconf includeWatchonly )');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
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
  }

  async getNewAddress(args, help) {
    if (help || args.length > 1)
      throw new RPCError(errs.MISC_ERROR, 'getnewaddress ( "account" )');

    const wallet = this.wallet;
    const valid = new Validator(args);
    let name = valid.str(0);

    if (name === '')
      name = 'default';

    const addr = await wallet.createReceive(name);

    return addr.getAddress('string');
  }

  async getRawChangeAddress(args, help) {
    if (help || args.length > 1)
      throw new RPCError(errs.MISC_ERROR, 'getrawchangeaddress');

    const wallet = this.wallet;
    const addr = await wallet.createChange();

    return addr.getAddress('string');
  }

  async getReceivedByAccount(args, help) {
    if (help || args.length < 1 || args.length > 2) {
      throw new RPCError(errs.MISC_ERROR,
        'getreceivedbyaccount "account" ( minconf )');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
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
  }

  async getReceivedByAddress(args, help) {
    if (help || args.length < 1 || args.length > 2) {
      throw new RPCError(errs.MISC_ERROR,
        'getreceivedbyaddress "bitcoinaddress" ( minconf )');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
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
  }

  async _toWalletTX(wtx) {
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
  }

  async getTransaction(args, help) {
    if (help || args.length < 1 || args.length > 2) {
      throw new RPCError(errs.MISC_ERROR,
        'gettransaction "txid" ( includeWatchonly )');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
    const hash = valid.rhash(0);
    const watchOnly = valid.bool(1, false);

    if (!hash)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter');

    const wtx = await wallet.getTX(hash);

    if (!wtx)
      throw new RPCError(errs.WALLET_ERROR, 'TX not found.');

    return await this._toWalletTX(wtx, watchOnly);
  }

  async abandonTransaction(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'abandontransaction "txid"');

    const wallet = this.wallet;
    const valid = new Validator(args);
    const hash = valid.rhash(0);

    if (!hash)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

    const result = await wallet.abandon(hash);

    if (!result)
      throw new RPCError(errs.WALLET_ERROR, 'Transaction not in wallet.');

    return null;
  }

  async getUnconfirmedBalance(args, help) {
    if (help || args.length > 0)
      throw new RPCError(errs.MISC_ERROR, 'getunconfirmedbalance');

    const wallet = this.wallet;
    const balance = await wallet.getBalance();

    return Amount.btc(balance.unconfirmed, true);
  }

  async getWalletInfo(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getwalletinfo');

    const wallet = this.wallet;
    const balance = await wallet.getBalance();

    return {
      walletid: wallet.id,
      walletversion: 6,
      balance: Amount.btc(balance.unconfirmed, true),
      unconfirmed_balance: Amount.btc(balance.unconfirmed, true),
      txcount: balance.tx,
      keypoololdest: 0,
      keypoolsize: 0,
      unlocked_until: wallet.master.until,
      paytxfee: Amount.btc(this.wdb.feeRate, true)
    };
  }

  async importPrivKey(args, help) {
    if (help || args.length < 1 || args.length > 3) {
      throw new RPCError(errs.MISC_ERROR,
        'importprivkey "bitcoinprivkey" ( "label" rescan )');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
    const secret = valid.str(0);
    const rescan = valid.bool(2, false);

    const key = parseSecret(secret, this.network);

    await wallet.importKey(0, key);

    if (rescan)
      await this.wdb.rescan(0);

    return null;
  }

  async importWallet(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'importwallet "filename" ( rescan )');

    const wallet = this.wallet;
    const valid = new Validator(args);
    const file = valid.str(0);
    const rescan = valid.bool(1, false);

    if (fs.unsupported)
      throw new RPCError(errs.INTERNAL_ERROR, 'FS not available.');

    let data;
    try {
      data = await fs.readFile(file, 'utf8');
    } catch (e) {
      throw new RPCError(errs.INTERNAL_ERROR, e.code || '');
    }

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
  }

  async importAddress(args, help) {
    if (help || args.length < 1 || args.length > 4) {
      throw new RPCError(errs.MISC_ERROR,
        'importaddress "address" ( "label" rescan p2sh )');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
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

    try {
      await wallet.importAddress(0, addr);
    } catch (e) {
      if (e.message !== 'Address already exists.')
        throw e;
    }

    if (rescan)
      await this.wdb.rescan(0);

    return null;
  }

  async importPubkey(args, help) {
    if (help || args.length < 1 || args.length > 4) {
      throw new RPCError(errs.MISC_ERROR,
        'importpubkey "pubkey" ( "label" rescan )');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
    const data = valid.buf(0);
    const rescan = valid.bool(2, false);

    if (!data)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

    const key = KeyRing.fromPublic(data, this.network);

    await wallet.importKey(0, key);

    if (rescan)
      await this.wdb.rescan(0);

    return null;
  }

  async keyPoolRefill(args, help) {
    if (help || args.length > 1)
      throw new RPCError(errs.MISC_ERROR, 'keypoolrefill ( newsize )');
    return null;
  }

  async listAccounts(args, help) {
    if (help || args.length > 2) {
      throw new RPCError(errs.MISC_ERROR,
        'listaccounts ( minconf includeWatchonly)');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
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
  }

  async listAddressGroupings(args, help) {
    if (help)
      throw new RPCError(errs.MISC_ERROR, 'listaddressgroupings');
    throw new Error('Not implemented.');
  }

  async listLockUnspent(args, help) {
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
  }

  async listReceivedByAccount(args, help) {
    if (help || args.length > 3) {
      throw new RPCError(errs.MISC_ERROR,
        'listreceivedbyaccount ( minconf includeempty includeWatchonly )');
    }

    const valid = new Validator(args);
    const minconf = valid.u32(0, 0);
    const includeEmpty = valid.bool(1, false);
    const watchOnly = valid.bool(2, false);

    return await this._listReceived(minconf, includeEmpty, watchOnly, true);
  }

  async listReceivedByAddress(args, help) {
    if (help || args.length > 3) {
      throw new RPCError(errs.MISC_ERROR,
        'listreceivedbyaddress ( minconf includeempty includeWatchonly )');
    }

    const valid = new Validator(args);
    const minconf = valid.u32(0, 0);
    const includeEmpty = valid.bool(1, false);
    const watchOnly = valid.bool(2, false);

    return await this._listReceived(minconf, includeEmpty, watchOnly, false);
  }

  async _listReceived(minconf, empty, watchOnly, account) {
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
  }

  async listSinceBlock(args, help) {
    const wallet = this.wallet;
    const chainHeight = this.wdb.state.height;
    const valid = new Validator(args);
    const block = valid.rhash(0);
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

    let highest = null;

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
        : consensus.NULL_HASH
    };
  }

  async _toListTX(wtx) {
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
    let sendMember = null;
    let recMember = null;
    let sendIndex = -1;
    let recIndex = -1;

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

    let member = null;
    let index = -1;

    if (receive) {
      assert(recMember);
      member = recMember;
      index = recIndex;
    } else {
      if (sendMember) {
        member = sendMember;
        index = sendIndex;
      } else {
        // In the odd case where we send to ourselves.
        receive = true;
        received = 0;
        member = recMember;
        index = recIndex;
      }
    }

    let rbf = false;

    if (wtx.height === -1 && wtx.tx.isRBF())
      rbf = true;

    return {
      account: member.path ? member.path.name : '',
      address: member.address
        ? member.address.toString(this.network)
        : null,
      category: receive ? 'receive' : 'send',
      amount: Amount.btc(receive ? received : -sent, true),
      label: member.path ? member.path.name : undefined,
      vout: index,
      confirmations: details.getDepth(this.wdb.height),
      blockhash: details.block ? util.revHex(details.block) : null,
      blockindex: -1,
      blocktime: details.time,
      blockheight: details.height,
      txid: util.revHex(details.hash),
      walletconflicts: [],
      time: details.mtime,
      timereceived: details.mtime,
      'bip125-replaceable': rbf ? 'yes' : 'no'
    };
  }

  async listTransactions(args, help) {
    if (help || args.length > 4) {
      throw new RPCError(errs.MISC_ERROR,
        'listtransactions ( "account" count from includeWatchonly)');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
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
  }

  async listUnspent(args, help) {
    if (help || args.length > 3) {
      throw new RPCError(errs.MISC_ERROR,
        'listunspent ( minconf maxconf  ["address",...] )');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
    const minDepth = valid.u32(0, 1);
    const maxDepth = valid.u32(1, 9999999);
    const addrs = valid.array(2);
    const height = this.wdb.state.height;

    const map = new Set();

    if (addrs) {
      const valid = new Validator(addrs);
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
  }

  async lockUnspent(args, help) {
    if (help || args.length < 1 || args.length > 2) {
      throw new RPCError(errs.MISC_ERROR,
        'lockunspent unlock ([{"txid":"txid","vout":n},...])');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
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
      const valid = new Validator(output);
      const hash = valid.rhash('txid');
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
  }

  async move(args, help) {
    // Not implementing: stupid and deprecated.
    throw new Error('Not implemented.');
  }

  async sendFrom(args, help) {
    if (help || args.length < 3 || args.length > 6) {
      throw new RPCError(errs.MISC_ERROR,
        'sendfrom "fromaccount" "tobitcoinaddress"'
        + ' amount ( minconf "comment" "comment-to" )');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
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
  }

  async sendMany(args, help) {
    if (help || args.length < 2 || args.length > 5) {
      throw new RPCError(errs.MISC_ERROR,
        'sendmany "fromaccount" {"address":amount,...}'
        + ' ( minconf "comment" ["address",...] )');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
    let name = valid.str(0);
    const sendTo = valid.obj(1);
    const minconf = valid.u32(2, 1);
    const subtract = valid.bool(4, false);

    if (name === '')
      name = 'default';

    if (!sendTo)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

    const to = new Validator(sendTo);
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
  }

  async sendToAddress(args, help) {
    if (help || args.length < 2 || args.length > 5) {
      throw new RPCError(errs.MISC_ERROR,
        'sendtoaddress "bitcoinaddress" amount'
        + ' ( "comment" "comment-to" subtractfeefromamount )');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
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
  }

  async setAccount(args, help) {
    if (help || args.length < 1 || args.length > 2) {
      throw new RPCError(errs.MISC_ERROR,
        'setaccount "bitcoinaddress" "account"');
    }

    // Impossible to implement in bcoin:
    throw new Error('Not implemented.');
  }

  async setTXFee(args, help) {
    const valid = new Validator(args);
    const rate = valid.ufixed(0, 8);

    if (help || args.length < 1 || args.length > 1)
      throw new RPCError(errs.MISC_ERROR, 'settxfee amount');

    if (rate == null)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

    this.wdb.feeRate = rate;

    return true;
  }

  async signMessage(args, help) {
    if (help || args.length !== 2) {
      throw new RPCError(errs.MISC_ERROR,
        'signmessage "bitcoinaddress" "message"');
    }

    const wallet = this.wallet;
    const valid = new Validator(args);
    const b58 = valid.str(0, '');
    const str = valid.str(1, '');

    const addr = parseHash(b58, this.network);

    const ring = await wallet.getKey(addr);

    if (!ring)
      throw new RPCError(errs.WALLET_ERROR, 'Address not found.');

    if (!wallet.master.key)
      throw new RPCError(errs.WALLET_UNLOCK_NEEDED, 'Wallet is locked.');

    const msg = Buffer.from(MAGIC_STRING + str, 'utf8');
    const hash = hash256.digest(msg);

    const sig = ring.sign(hash);

    return sig.toString('base64');
  }

  async walletLock(args, help) {
    const wallet = this.wallet;

    if (help || (wallet.master.encrypted && args.length !== 0))
      throw new RPCError(errs.MISC_ERROR, 'walletlock');

    if (!wallet.master.encrypted) {
      throw new RPCError(
        errs.WALLET_WRONG_ENC_STATE,
        'Wallet is not encrypted.');
    }

    await wallet.lock();

    return null;
  }

  async walletPassphraseChange(args, help) {
    const wallet = this.wallet;

    if (help || (wallet.master.encrypted && args.length !== 2)) {
      throw new RPCError(errs.MISC_ERROR, 'walletpassphrasechange'
        + ' "oldpassphrase" "newpassphrase"');
    }

    const valid = new Validator(args);
    const old = valid.str(0, '');
    const passphrase = valid.str(1, '');

    if (!wallet.master.encrypted) {
      throw new RPCError(
        errs.WALLET_WRONG_ENC_STATE,
        'Wallet is not encrypted.');
    }

    if (old.length < 1 || passphrase.length < 1)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid parameter');

    await wallet.setPassphrase(passphrase, old);

    return null;
  }

  async walletPassphrase(args, help) {
    const wallet = this.wallet;
    const valid = new Validator(args);
    const passphrase = valid.str(0, '');
    const timeout = valid.u32(1);

    if (help || (wallet.master.encrypted && args.length !== 2)) {
      throw new RPCError(errs.MISC_ERROR,
        'walletpassphrase "passphrase" timeout');
    }

    if (!wallet.master.encrypted) {
      throw new RPCError(
        errs.WALLET_WRONG_ENC_STATE,
        'Wallet is not encrypted.');
    }

    if (passphrase.length < 1)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid parameter');

    if (timeout == null)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter');

    await wallet.unlock(passphrase, timeout);

    return null;
  }

  async importPrunedFunds(args, help) {
    if (help || args.length < 2 || args.length > 3) {
      throw new RPCError(errs.MISC_ERROR,
        'importprunedfunds "rawtransaction" "txoutproof" ( "label" )');
    }

    const valid = new Validator(args);
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
  }

  async removePrunedFunds(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'removeprunedfunds "txid"');

    const wallet = this.wallet;
    const valid = new Validator(args);
    const hash = valid.rhash(0);

    if (!hash)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid parameter.');

    if (!await wallet.remove(hash))
      throw new RPCError(errs.WALLET_ERROR, 'Transaction not in wallet.');

    return null;
  }

  async selectWallet(args, help) {
    const valid = new Validator(args);
    const id = valid.str(0);

    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'selectwallet "id"');

    const wallet = await this.wdb.get(id);

    if (!wallet)
      throw new RPCError(errs.WALLET_ERROR, 'Wallet not found.');

    this.wallet = wallet;

    return null;
  }

  async getMemoryInfo(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getmemoryinfo');

    return this.logger.memoryUsage();
  }

  async setLogLevel(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'setloglevel "level"');

    const valid = new Validator(args);
    const level = valid.str(0, '');

    this.logger.setLevel(level);

    return null;
  }
}

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
