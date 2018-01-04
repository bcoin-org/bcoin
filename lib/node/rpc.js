/*!
 * rpc.js - bitcoind-compatible json rpc for bcoin.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const bweb = require('bweb');
const {Lock} = require('bmutex');
const IP = require('binet');
const Validator = require('bval');
const hash160 = require('bcrypto/lib/hash160');
const hash256 = require('bcrypto/lib/hash256');
const ccmp = require('bcrypto/lib/ccmp');
const secp256k1 = require('bcrypto/lib/secp256k1');
const util = require('../utils/util');
const common = require('../blockchain/common');
const Amount = require('../btc/amount');
const NetAddress = require('../net/netaddress');
const Script = require('../script/script');
const Address = require('../primitives/address');
const Block = require('../primitives/block');
const Headers = require('../primitives/headers');
const Input = require('../primitives/input');
const KeyRing = require('../primitives/keyring');
const MerkleBlock = require('../primitives/merkleblock');
const MTX = require('../primitives/mtx');
const Network = require('../protocol/network');
const Outpoint = require('../primitives/outpoint');
const Output = require('../primitives/output');
const TX = require('../primitives/tx');
const consensus = require('../protocol/consensus');
const pkg = require('../pkg');
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

  // P2P client errors
  CLIENT_NOT_CONNECTED: -9,
  CLIENT_IN_INITIAL_DOWNLOAD: -10,
  CLIENT_NODE_ALREADY_ADDED: -23,
  CLIENT_NODE_NOT_ADDED: -24,
  CLIENT_NODE_NOT_CONNECTED: -29,
  CLIENT_INVALID_IP_OR_SUBNET: -30,
  CLIENT_P2P_DISABLED: -31
};

const MAGIC_STRING = 'Bitcoin Signed Message:\n';

/**
 * Bitcoin RPC
 * @alias module:http.RPC
 * @extends bweb.RPC
 */

class RPC extends RPCBase {
  /**
   * Create RPC.
   * @param {Node} node
   */

  constructor(node) {
    super();

    assert(node, 'RPC requires a Node.');

    this.node = node;
    this.network = node.network;
    this.workers = node.workers;
    this.chain = node.chain;
    this.mempool = node.mempool;
    this.pool = node.pool;
    this.fees = node.fees;
    this.miner = node.miner;
    this.logger = node.logger.context('rpc');
    this.locker = new Lock();

    this.mining = false;
    this.procLimit = 0;
    this.attempt = null;
    this.lastActivity = 0;
    this.boundChain = false;
    this.nonce1 = 0;
    this.nonce2 = 0;
    this.merkleMap = new Map();
    this.pollers = [];

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
      default:
        return errs.INTERNAL_ERROR;
    }
  }

  handleCall(cmd, query) {
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
  }

  handleError(err) {
    this.logger.error('RPC internal error.');
    this.logger.error(err);
  }

  init() {
    this.add('stop', this.stop);
    this.add('help', this.help);

    this.add('getblockchaininfo', this.getBlockchainInfo);
    this.add('getbestblockhash', this.getBestBlockHash);
    this.add('getblockcount', this.getBlockCount);
    this.add('getblock', this.getBlock);
    this.add('getblockbyheight', this.getBlockByHeight);
    this.add('getblockhash', this.getBlockHash);
    this.add('getblockheader', this.getBlockHeader);
    this.add('getchaintips', this.getChainTips);
    this.add('getdifficulty', this.getDifficulty);
    this.add('getmempoolancestors', this.getMempoolAncestors);
    this.add('getmempooldescendants', this.getMempoolDescendants);
    this.add('getmempoolentry', this.getMempoolEntry);
    this.add('getmempoolinfo', this.getMempoolInfo);
    this.add('getrawmempool', this.getRawMempool);
    this.add('gettxout', this.getTXOut);
    this.add('gettxoutsetinfo', this.getTXOutSetInfo);
    this.add('pruneblockchain', this.pruneBlockchain);
    this.add('verifychain', this.verifyChain);

    this.add('invalidateblock', this.invalidateBlock);
    this.add('reconsiderblock', this.reconsiderBlock);

    this.add('getnetworkhashps', this.getNetworkHashPS);
    this.add('getmininginfo', this.getMiningInfo);
    this.add('prioritisetransaction', this.prioritiseTransaction);
    this.add('getwork', this.getWork);
    this.add('getworklp', this.getWorkLongpoll);
    this.add('getblocktemplate', this.getBlockTemplate);
    this.add('submitblock', this.submitBlock);
    this.add('verifyblock', this.verifyBlock);

    this.add('setgenerate', this.setGenerate);
    this.add('getgenerate', this.getGenerate);
    this.add('generate', this.generate);
    this.add('generatetoaddress', this.generateToAddress);

    this.add('estimatefee', this.estimateFee);
    this.add('estimatepriority', this.estimatePriority);
    this.add('estimatesmartfee', this.estimateSmartFee);
    this.add('estimatesmartpriority', this.estimateSmartPriority);

    this.add('getinfo', this.getInfo);
    this.add('validateaddress', this.validateAddress);
    this.add('createmultisig', this.createMultisig);
    this.add('createwitnessaddress', this.createWitnessAddress);
    this.add('verifymessage', this.verifyMessage);
    this.add('signmessagewithprivkey', this.signMessageWithPrivkey);

    this.add('setmocktime', this.setMockTime);

    this.add('getconnectioncount', this.getConnectionCount);
    this.add('ping', this.ping);
    this.add('getpeerinfo', this.getPeerInfo);
    this.add('addnode', this.addNode);
    this.add('disconnectnode', this.disconnectNode);
    this.add('getaddednodeinfo', this.getAddedNodeInfo);
    this.add('getnettotals', this.getNetTotals);
    this.add('getnetworkinfo', this.getNetworkInfo);
    this.add('setban', this.setBan);
    this.add('listbanned', this.listBanned);
    this.add('clearbanned', this.clearBanned);

    this.add('getrawtransaction', this.getRawTransaction);
    this.add('createrawtransaction', this.createRawTransaction);
    this.add('decoderawtransaction', this.decodeRawTransaction);
    this.add('decodescript', this.decodeScript);
    this.add('sendrawtransaction', this.sendRawTransaction);
    this.add('signrawtransaction', this.signRawTransaction);

    this.add('gettxoutproof', this.getTXOutProof);
    this.add('verifytxoutproof', this.verifyTXOutProof);

    this.add('getmemoryinfo', this.getMemoryInfo);
    this.add('setloglevel', this.setLogLevel);
  }

  /*
   * Overall control/query calls
   */

  async getInfo(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getinfo');

    return {
      version: pkg.version,
      protocolversion: this.pool.options.version,
      walletversion: 0,
      balance: 0,
      blocks: this.chain.height,
      timeoffset: this.network.time.offset,
      connections: this.pool.peers.size(),
      proxy: '',
      difficulty: toDifficulty(this.chain.tip.bits),
      testnet: this.network !== Network.main,
      keypoololdest: 0,
      keypoolsize: 0,
      unlocked_until: 0,
      paytxfee: Amount.btc(this.network.feeRate, true),
      relayfee: Amount.btc(this.network.minRelay, true),
      errors: ''
    };
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

    this.node.close().catch((err) => {
      setImmediate(() => {
        throw err;
      });
    });

    return 'Stopping.';
  }

  /*
   * P2P networking
   */

  async getNetworkInfo(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getnetworkinfo');

    const hosts = this.pool.hosts;
    const locals = [];

    for (const local of hosts.local.values()) {
      locals.push({
        address: local.addr.host,
        port: local.addr.port,
        score: local.score
      });
    }

    return {
      version: pkg.version,
      subversion: this.pool.options.agent,
      protocolversion: this.pool.options.version,
      localservices: hex32(this.pool.options.services),
      localrelay: !this.pool.options.noRelay,
      timeoffset: this.network.time.offset,
      networkactive: this.pool.connected,
      connections: this.pool.peers.size(),
      networks: [],
      relayfee: Amount.btc(this.network.minRelay, true),
      incrementalfee: 0,
      localaddresses: locals,
      warnings: ''
    };
  }

  async addNode(args, help) {
    if (help || args.length !== 2)
      throw new RPCError(errs.MISC_ERROR, 'addnode "node" "add|remove|onetry"');

    const valid = new Validator(args);
    const node = valid.str(0, '');
    const cmd = valid.str(1, '');

    switch (cmd) {
      case 'add': {
        this.pool.hosts.addNode(node);
        ; // fall through
      }
      case 'onetry': {
        const addr = parseNetAddress(node, this.network);

        if (!this.pool.peers.get(addr.hostname)) {
          const peer = this.pool.createOutbound(addr);
          this.pool.peers.add(peer);
        }

        break;
      }
      case 'remove': {
        this.pool.hosts.removeNode(node);
        break;
      }
    }

    return null;
  }

  async disconnectNode(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'disconnectnode "node"');

    const valid = new Validator(args);
    const str = valid.str(0, '');

    const addr = parseIP(str, this.network);
    const peer = this.pool.peers.get(addr.hostname);

    if (peer)
      peer.destroy();

    return null;
  }

  async getAddedNodeInfo(args, help) {
    if (help || args.length > 1)
      throw new RPCError(errs.MISC_ERROR, 'getaddednodeinfo ( "node" )');

    const hosts = this.pool.hosts;
    const valid = new Validator(args);
    const addr = valid.str(0, '');

    let target;
    if (args.length === 1)
      target = parseIP(addr, this.network);

    const result = [];

    for (const node of hosts.nodes) {
      if (target) {
        if (node.host !== target.host)
          continue;

        if (node.port !== target.port)
          continue;
      }

      const peer = this.pool.peers.get(node.hostname);

      if (!peer || !peer.connected) {
        result.push({
          addednode: node.hostname,
          connected: false,
          addresses: []
        });
        continue;
      }

      result.push({
        addednode: node.hostname,
        connected: peer.connected,
        addresses: [
          {
            address: peer.hostname(),
            connected: peer.outbound
              ? 'outbound'
              : 'inbound'
          }
        ]
      });
    }

    if (target && result.length === 0) {
      throw new RPCError(errs.CLIENT_NODE_NOT_ADDED,
        'Node has not been added.');
    }

    return result;
  }

  async getConnectionCount(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getconnectioncount');

    return this.pool.peers.size();
  }

  async getNetTotals(args, help) {
    let sent = 0;
    let recv = 0;

    if (help || args.length > 0)
      throw new RPCError(errs.MISC_ERROR, 'getnettotals');

    for (let peer = this.pool.peers.head(); peer; peer = peer.next) {
      sent += peer.socket.bytesWritten;
      recv += peer.socket.bytesRead;
    }

    return {
      totalbytesrecv: recv,
      totalbytessent: sent,
      timemillis: Date.now()
    };
  }

  async getPeerInfo(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getpeerinfo');

    const peers = [];

    for (let peer = this.pool.peers.head(); peer; peer = peer.next) {
      const offset = this.network.time.known.get(peer.hostname()) || 0;
      const hashes = [];

      for (const hash in peer.blockMap.keys()) {
        const str = util.revHex(hash);
        hashes.push(str);
      }

      peer.getName();

      peers.push({
        id: peer.id,
        addr: peer.hostname(),
        addrlocal: !peer.local.isNull()
          ? peer.local.hostname
          : undefined,
        name: peer.name || undefined,
        services: hex32(peer.services),
        relaytxes: !peer.noRelay,
        lastsend: peer.lastSend / 1000 | 0,
        lastrecv: peer.lastRecv / 1000 | 0,
        bytessent: peer.socket.bytesWritten,
        bytesrecv: peer.socket.bytesRead,
        conntime: peer.time !== 0 ? (Date.now() - peer.time) / 1000 | 0 : 0,
        timeoffset: offset,
        pingtime: peer.lastPong !== -1
          ? (peer.lastPong - peer.lastPing) / 1000
          : -1,
        minping: peer.minPing !== -1 ? peer.minPing / 1000 : -1,
        version: peer.version,
        subver: peer.agent,
        inbound: !peer.outbound,
        startingheight: peer.height,
        besthash: peer.bestHash ? util.revHex(peer.bestHash) : null,
        bestheight: peer.bestHeight,
        banscore: peer.banScore,
        inflight: hashes,
        whitelisted: false
      });
    }

    return peers;
  }

  async ping(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'ping');

    for (let peer = this.pool.peers.head(); peer; peer = peer.next)
      peer.sendPing();

    return null;
  }

  async setBan(args, help) {
    const valid = new Validator(args);
    const str = valid.str(0, '');
    const action = valid.str(1, '');

    if (help
        || args.length < 2
        || (action !== 'add' && action !== 'remove')) {
      throw new RPCError(errs.MISC_ERROR,
        'setban "ip(/netmask)" "add|remove" (bantime) (absolute)');
    }

    const addr = parseNetAddress(str, this.network);

    switch (action) {
      case 'add':
        this.pool.ban(addr);
        break;
      case 'remove':
        this.pool.unban(addr);
        break;
    }

    return null;
  }

  async listBanned(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'listbanned');

    const banned = [];

    for (const [host, time] of this.pool.hosts.banned) {
      banned.push({
        address: host,
        banned_until: time + this.pool.options.banTime,
        ban_created: time,
        ban_reason: ''
      });
    }

    return banned;
  }

  async clearBanned(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'clearbanned');

    this.pool.hosts.clearBanned();

    return null;
  }

  /* Block chain and UTXO */
  async getBlockchainInfo(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getblockchaininfo');

    return {
      chain: this.network.type !== 'testnet'
        ? this.network.type
        : 'test',
      blocks: this.chain.height,
      headers: this.chain.height,
      bestblockhash: this.chain.tip.rhash(),
      difficulty: toDifficulty(this.chain.tip.bits),
      mediantime: await this.chain.getMedianTime(this.chain.tip),
      verificationprogress: this.chain.getProgress(),
      chainwork: this.chain.tip.chainwork.toString('hex', 64),
      pruned: this.chain.options.prune,
      softforks: this.getSoftforks(),
      bip9_softforks: await this.getBIP9Softforks(),
      pruneheight: this.chain.options.prune
        ? Math.max(0, this.chain.height - this.network.block.keepBlocks)
        : null
    };
  }

  async getBestBlockHash(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getbestblockhash');

    return this.chain.tip.rhash();
  }

  async getBlockCount(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getblockcount');

    return this.chain.tip.height;
  }

  async getBlock(args, help) {
    if (help || args.length < 1 || args.length > 3)
      throw new RPCError(errs.MISC_ERROR, 'getblock "hash" ( verbose )');

    const valid = new Validator(args);
    const hash = valid.rhash(0);
    const verbose = valid.bool(1, true);
    const details = valid.bool(2, false);

    if (!hash)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid block hash.');

    const entry = await this.chain.getEntry(hash);

    if (!entry)
      throw new RPCError(errs.MISC_ERROR, 'Block not found');

    const block = await this.chain.getBlock(entry.hash);

    if (!block) {
      if (this.chain.options.spv)
        throw new RPCError(errs.MISC_ERROR, 'Block not available (spv mode)');

      if (this.chain.options.prune) {
        throw new RPCError(errs.MISC_ERROR,
          'Block not available (pruned data)');
      }

      throw new RPCError(errs.MISC_ERROR, 'Can\'t read block from disk');
    }

    if (!verbose)
      return block.toRaw().toString('hex');

    return await this.blockToJSON(entry, block, details);
  }

  async getBlockByHeight(args, help) {
    if (help || args.length < 1 || args.length > 3) {
      throw new RPCError(errs.MISC_ERROR,
        'getblockbyheight "height" ( verbose )');
    }

    const valid = new Validator(args);
    const height = valid.u32(0, -1);
    const verbose = valid.bool(1, true);
    const details = valid.bool(2, false);

    if (height === -1)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid block height.');

    const entry = await this.chain.getEntry(height);

    if (!entry)
      throw new RPCError(errs.MISC_ERROR, 'Block not found');

    const block = await this.chain.getBlock(entry.hash);

    if (!block) {
      if (this.chain.options.spv)
        throw new RPCError(errs.MISC_ERROR, 'Block not available (spv mode)');

      if (this.chain.options.prune) {
        throw new RPCError(errs.MISC_ERROR,
          'Block not available (pruned data)');
      }

      throw new RPCError(errs.DATABASE_ERROR, 'Can\'t read block from disk');
    }

    if (!verbose)
      return block.toRaw().toString('hex');

    return await this.blockToJSON(entry, block, details);
  }

  async getBlockHash(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'getblockhash index');

    const valid = new Validator(args);
    const height = valid.u32(0);

    if (height == null || height > this.chain.height)
      throw new RPCError(errs.INVALID_PARAMETER, 'Block height out of range.');

    const hash = await this.chain.getHash(height);

    if (!hash)
      throw new RPCError(errs.MISC_ERROR, 'Not found.');

    return util.revHex(hash);
  }

  async getBlockHeader(args, help) {
    if (help || args.length < 1 || args.length > 2)
      throw new RPCError(errs.MISC_ERROR, 'getblockheader "hash" ( verbose )');

    const valid = new Validator(args);
    const hash = valid.rhash(0);
    const verbose = valid.bool(1, true);

    if (!hash)
      throw new RPCError(errs.MISC_ERROR, 'Invalid block hash.');

    const entry = await this.chain.getEntry(hash);

    if (!entry)
      throw new RPCError(errs.MISC_ERROR, 'Block not found');

    if (!verbose)
      return entry.toRaw().toString('hex', 0, 80);

    return await this.headerToJSON(entry);
  }

  async getChainTips(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getchaintips');

    const tips = await this.chain.getTips();
    const result = [];

    for (const hash of tips) {
      const entry = await this.chain.getEntry(hash);

      assert(entry);

      const fork = await this.findFork(entry);
      const main = await this.chain.isMainChain(entry);

      result.push({
        height: entry.height,
        hash: entry.rhash(),
        branchlen: entry.height - fork.height,
        status: main ? 'active' : 'valid-headers'
      });
    }

    return result;
  }

  async getDifficulty(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getdifficulty');

    return toDifficulty(this.chain.tip.bits);
  }

  async getMempoolInfo(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getmempoolinfo');

    if (!this.mempool)
      throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

    return {
      size: this.mempool.map.size,
      bytes: this.mempool.getSize(),
      usage: this.mempool.getSize(),
      maxmempool: this.mempool.options.maxSize,
      mempoolminfee: Amount.btc(this.mempool.options.minRelay, true)
    };
  }

  async getMempoolAncestors(args, help) {
    if (help || args.length < 1 || args.length > 2)
      throw new RPCError(errs.MISC_ERROR, 'getmempoolancestors txid (verbose)');

    const valid = new Validator(args);
    const hash = valid.rhash(0);
    const verbose = valid.bool(1, false);

    if (!this.mempool)
      throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

    if (!hash)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID.');

    const entry = this.mempool.getEntry(hash);

    if (!entry)
      throw new RPCError(errs.MISC_ERROR, 'Transaction not in mempool.');

    const entries = this.mempool.getAncestors(entry);
    const out = [];

    if (verbose) {
      for (const entry of entries)
        out.push(this.entryToJSON(entry));
    } else {
      for (const entry of entries)
        out.push(entry.txid());
    }

    return out;
  }

  async getMempoolDescendants(args, help) {
    if (help || args.length < 1 || args.length > 2) {
      throw new RPCError(errs.MISC_ERROR,
        'getmempooldescendants txid (verbose)');
    }

    const valid = new Validator(args);
    const hash = valid.rhash(0);
    const verbose = valid.bool(1, false);

    if (!this.mempool)
      throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

    if (!hash)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID.');

    const entry = this.mempool.getEntry(hash);

    if (!entry)
      throw new RPCError(errs.MISC_ERROR, 'Transaction not in mempool.');

    const entries = this.mempool.getDescendants(entry);
    const out = [];

    if (verbose) {
      for (const entry of entries)
        out.push(this.entryToJSON(entry));
    } else {
      for (const entry of entries)
        out.push(entry.txid());
    }

    return out;
  }

  async getMempoolEntry(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'getmempoolentry txid');

    const valid = new Validator(args);
    const hash = valid.rhash(0);

    if (!this.mempool)
      throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

    if (!hash)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID.');

    const entry = this.mempool.getEntry(hash);

    if (!entry)
      throw new RPCError(errs.MISC_ERROR, 'Transaction not in mempool.');

    return this.entryToJSON(entry);
  }

  async getRawMempool(args, help) {
    if (help || args.length > 1)
      throw new RPCError(errs.MISC_ERROR, 'getrawmempool ( verbose )');

    const valid = new Validator(args);
    const verbose = valid.bool(0, false);

    if (!this.mempool)
      throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

    if (verbose) {
      const out = {};

      for (const entry of this.mempool.map.values())
        out[entry.txid()] = this.entryToJSON(entry);

      return out;
    }

    const hashes = this.mempool.getSnapshot();

    return hashes.map(util.revHex);
  }

  async getTXOut(args, help) {
    if (help || args.length < 2 || args.length > 3) {
      throw new RPCError(errs.MISC_ERROR,
        'gettxout "txid" n ( includemempool )');
    }

    const valid = new Validator(args);
    const hash = valid.rhash(0);
    const index = valid.u32(1);
    const mempool = valid.bool(2, true);

    if (this.chain.options.spv)
      throw new RPCError(errs.MISC_ERROR, 'Cannot get coins in SPV mode.');

    if (this.chain.options.prune)
      throw new RPCError(errs.MISC_ERROR, 'Cannot get coins when pruned.');

    if (!hash || index == null)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid outpoint.');

    let coin;
    if (mempool) {
      if (!this.mempool)
        throw new RPCError(errs.MISC_ERROR, 'No mempool available.');
      coin = this.mempool.getCoin(hash, index);
    }

    if (!coin)
      coin = await this.chain.getCoin(hash, index);

    if (!coin)
      return null;

    return {
      bestblock: this.chain.tip.rhash(),
      confirmations: coin.getDepth(this.chain.height),
      value: Amount.btc(coin.value, true),
      scriptPubKey: this.scriptToJSON(coin.script, true),
      version: coin.version,
      coinbase: coin.coinbase
    };
  }

  async getTXOutProof(args, help) {
    if (help || (args.length !== 1 && args.length !== 2)) {
      throw new RPCError(errs.MISC_ERROR,
        'gettxoutproof ["txid",...] ( blockhash )');
    }

    const valid = new Validator(args);
    const txids = valid.array(0);
    const hash = valid.rhash(1);

    if (this.chain.options.spv)
      throw new RPCError(errs.MISC_ERROR, 'Cannot get coins in SPV mode.');

    if (this.chain.options.prune)
      throw new RPCError(errs.MISC_ERROR, 'Cannot get coins when pruned.');

    if (!txids || txids.length === 0)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid TXIDs.');

    const items = new Validator(txids);
    const set = new Set();
    const hashes = [];

    let last = null;

    for (let i = 0; i < txids.length; i++) {
      const hash = items.rhash(i);

      if (!hash)
        throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID.');

      if (set.has(hash))
        throw new RPCError(errs.INVALID_PARAMETER, 'Duplicate txid.');

      set.add(hash);
      hashes.push(hash);

      last = hash;
    }

    let block = null;

    if (hash) {
      block = await this.chain.getBlock(hash);
    } else if (this.chain.options.indexTX) {
      const tx = await this.chain.getMeta(last);
      if (tx)
        block = await this.chain.getBlock(tx.block);
    } else {
      const coin = await this.chain.getCoin(last, 0);
      if (coin)
        block = await this.chain.getBlock(coin.height);
    }

    if (!block)
      throw new RPCError(errs.MISC_ERROR, 'Block not found.');

    for (const hash of hashes) {
      if (!block.hasTX(hash)) {
        throw new RPCError(errs.VERIFY_ERROR,
          'Block does not contain all txids.');
      }
    }

    block = MerkleBlock.fromHashes(block, hashes);

    return block.toRaw().toString('hex');
  }

  async verifyTXOutProof(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'verifytxoutproof "proof"');

    const valid = new Validator(args);
    const data = valid.buf(0);

    if (!data)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid hex string.');

    const block = MerkleBlock.fromRaw(data);

    if (!block.verify())
      return [];

    const entry = await this.chain.getEntry(block.hash('hex'));

    if (!entry)
      throw new RPCError(errs.MISC_ERROR, 'Block not found in chain.');

    const tree = block.getTree();
    const out = [];

    for (const hash of tree.matches)
      out.push(util.revHex(hash.toString('hex')));

    return out;
  }

  async getTXOutSetInfo(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'gettxoutsetinfo');

    if (this.chain.options.spv) {
      throw new RPCError(errs.MISC_ERROR,
        'Chainstate not available (SPV mode).');
    }

    return {
      height: this.chain.height,
      bestblock: this.chain.tip.rhash(),
      transactions: this.chain.db.state.tx,
      txouts: this.chain.db.state.coin,
      bytes_serialized: 0,
      hash_serialized: 0,
      total_amount: Amount.btc(this.chain.db.state.value, true)
    };
  }

  async pruneBlockchain(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'pruneblockchain');

    if (this.chain.options.spv)
      throw new RPCError(errs.MISC_ERROR, 'Cannot prune chain in SPV mode.');

    if (this.chain.options.prune)
      throw new RPCError(errs.MISC_ERROR, 'Chain is already pruned.');

    if (this.chain.height < this.network.block.pruneAfterHeight)
      throw new RPCError(errs.MISC_ERROR, 'Chain is too short for pruning.');

    try {
      await this.chain.prune();
    } catch (e) {
      throw new RPCError(errs.DATABASE_ERROR, e.message);
    }
  }

  async verifyChain(args, help) {
    if (help || args.length > 2) {
      throw new RPCError(errs.MISC_ERROR,
        'verifychain ( checklevel numblocks )');
    }

    const valid = new Validator(args);
    const level = valid.u32(0);
    const blocks = valid.u32(1);

    if (level == null || blocks == null)
      throw new RPCError(errs.TYPE_ERROR, 'Missing parameters.');

    if (this.chain.options.spv)
      throw new RPCError(errs.MISC_ERROR, 'Cannot verify chain in SPV mode.');

    if (this.chain.options.prune)
      throw new RPCError(errs.MISC_ERROR, 'Cannot verify chain when pruned.');

    return null;
  }

  /*
   * Mining
   */

  async submitWork(data) {
    const unlock = await this.locker.lock();
    try {
      return await this._submitWork(data);
    } finally {
      unlock();
    }
  }

  async _submitWork(data) {
    const attempt = this.attempt;

    if (!attempt)
      return false;

    if (data.length !== 128)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid work size.');

    const raw = data.slice(0, 80);
    swap32(raw);

    const header = Headers.fromHead(raw);

    if (header.prevBlock !== attempt.prevBlock
        || header.bits !== attempt.bits) {
      return false;
    }

    if (!header.verify())
      return false;

    const nonces = this.merkleMap.get(header.merkleRoot);

    if (!nonces)
      return false;

    const [n1, n2] = nonces;
    const nonce = header.nonce;
    const time = header.time;

    const proof = attempt.getProof(n1, n2, time, nonce);

    if (!proof.verify(attempt.target))
      return false;

    const block = attempt.commit(proof);

    let entry;
    try {
      entry = await this.chain.add(block);
    } catch (err) {
      if (err.type === 'VerifyError') {
        this.logger.warning('RPC block rejected: %s (%s).',
          block.rhash(), err.reason);
        return false;
      }
      throw err;
    }

    if (!entry) {
      this.logger.warning('RPC block rejected: %s (bad-prevblk).',
        block.rhash());
      return false;
    }

    return true;
  }

  async createWork(data) {
    const unlock = await this.locker.lock();
    try {
      return await this._createWork(data);
    } finally {
      unlock();
    }
  }

  async _createWork() {
    const attempt = await this.updateWork();
    const n1 = this.nonce1;
    const n2 = this.nonce2;
    const time = attempt.time;

    const data = Buffer.allocUnsafe(128);
    data.fill(0);

    const root = attempt.getRoot(n1, n2);
    const head = attempt.getHeader(root, time, 0);

    head.copy(data, 0);

    data[80] = 0x80;
    data.writeUInt32BE(80 * 8, data.length - 4, true);

    swap32(data);

    return {
      data: data.toString('hex'),
      target: attempt.target.toString('hex'),
      height: attempt.height
    };
  }

  async getWorkLongpoll(args, help) {
    await this.longpoll();
    return await this.createWork();
  }

  async getWork(args, help) {
    if (args.length > 1)
      throw new RPCError(errs.MISC_ERROR, 'getwork ( "data" )');

    if (args.length === 1) {
      const valid = new Validator(args);
      const data = valid.buf(0);

      if (!data)
        throw new RPCError(errs.TYPE_ERROR, 'Invalid work data.');

      return await this.submitWork(data);
    }

    return await this.createWork();
  }

  async submitBlock(args, help) {
    if (help || args.length < 1 || args.length > 2) {
      throw new RPCError(errs.MISC_ERROR,
        'submitblock "hexdata" ( "jsonparametersobject" )');
    }

    const valid = new Validator(args);
    const data = valid.buf(0);

    const block = Block.fromRaw(data);

    return await this.addBlock(block);
  }

  async getBlockTemplate(args, help) {
    if (help || args.length > 1) {
      throw new RPCError(errs.MISC_ERROR,
        'getblocktemplate ( "jsonrequestobject" )');
    }

    const validator = new Validator(args);
    const options = validator.obj(0, {});
    const valid = new Validator(options);
    const mode = valid.str('mode', 'template');

    if (mode !== 'template' && mode !== 'proposal')
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid mode.');

    if (mode === 'proposal') {
      const data = valid.buf('data');

      if (!data)
        throw new RPCError(errs.TYPE_ERROR, 'Missing data parameter.');

      const block = Block.fromRaw(data);

      if (block.prevBlock !== this.chain.tip.hash)
        return 'inconclusive-not-best-prevblk';

      try {
        await this.chain.verifyBlock(block);
      } catch (e) {
        if (e.type === 'VerifyError')
          return e.reason;
        throw e;
      }

      return null;
    }

    let maxVersion = valid.u32('maxversion', -1);
    let rules = valid.array('rules');

    if (rules)
      maxVersion = -1;

    const capabilities = valid.array('capabilities');
    let coinbase = false;

    if (capabilities) {
      let txnCap = false;
      let valueCap = false;

      for (const capability of capabilities) {
        if (typeof capability !== 'string')
          throw new RPCError(errs.TYPE_ERROR, 'Invalid capability.');

        switch (capability) {
          case 'coinbasetxn':
            txnCap = true;
            break;
          case 'coinbasevalue':
            // Prefer value if they support it.
            valueCap = true;
            break;
        }
      }

      // BIP22 states that we can't have coinbasetxn
      // _and_ coinbasevalue in the same template.
      // The problem is, many clients _say_ they
      // support coinbasetxn when they don't (ckpool).
      // To make matters worse, some clients will
      // parse an undefined `coinbasevalue` as zero.
      // Because of all of this, coinbasetxn is
      // disabled for now.
      valueCap = true;

      if (txnCap && !valueCap) {
        if (this.miner.addresses.length === 0) {
          throw new RPCError(errs.MISC_ERROR,
            'No addresses available for coinbase.');
        }
        coinbase = true;
      }
    }

    if (!this.network.selfConnect) {
      if (this.pool.peers.size() === 0) {
        throw new RPCError(errs.CLIENT_NOT_CONNECTED,
          'Bitcoin is not connected!');
      }

      if (!this.chain.synced) {
        throw new RPCError(errs.CLIENT_IN_INITIAL_DOWNLOAD,
          'Bitcoin is downloading blocks...');
      }
    }

    const lpid = valid.str('longpollid');

    if (lpid)
      await this.handleLongpoll(lpid);

    if (!rules)
      rules = [];

    return await this.createTemplate(maxVersion, coinbase, rules);
  }

  async createTemplate(maxVersion, coinbase, rules) {
    const unlock = await this.locker.lock();
    try {
      return await this._createTemplate(maxVersion, coinbase, rules);
    } finally {
      unlock();
    }
  }

  async _createTemplate(maxVersion, coinbase, rules) {
    const attempt = await this.getTemplate();
    const scale = attempt.witness ? 1 : consensus.WITNESS_SCALE_FACTOR;

    // Default mutable fields.
    const mutable = ['time', 'transactions', 'prevblock'];

    // The miner doesn't support
    // versionbits. Force them to
    // encode our version.
    if (maxVersion >= 2)
      mutable.push('version/force');

    // Allow the miner to change
    // our provided coinbase.
    // Note that these are implied
    // without `coinbasetxn`.
    if (coinbase) {
      mutable.push('coinbase');
      mutable.push('coinbase/append');
      mutable.push('generation');
    }

    // Build an index of every transaction.
    const index = new Map();
    for (let i = 0; i < attempt.items.length; i++) {
      const entry = attempt.items[i];
      index.set(entry.hash, i + 1);
    }

    // Calculate dependencies for each transaction.
    const txs = [];
    for (let i = 0; i < attempt.items.length; i++) {
      const entry = attempt.items[i];
      const tx = entry.tx;
      const deps = [];

      for (let j = 0; j < tx.inputs.length; j++) {
        const input = tx.inputs[j];
        const dep = index.get(input.prevout.hash);

        if (dep == null)
          continue;

        if (deps.indexOf(dep) === -1) {
          assert(dep < i + 1);
          deps.push(dep);
        }
      }

      txs.push({
        data: tx.toRaw().toString('hex'),
        txid: tx.txid(),
        hash: tx.wtxid(),
        depends: deps,
        fee: entry.fee,
        sigops: entry.sigops / scale | 0,
        weight: tx.getWeight()
      });
    }

    if (this.chain.options.bip91) {
      rules.push('segwit');
      rules.push('segsignal');
    }

    if (this.chain.options.bip148)
      rules.push('segwit');

    // Calculate version based on given rules.
    let version = attempt.version;
    const vbavailable = {};
    const vbrules = [];

    for (const deploy of this.network.deploys) {
      const state = await this.chain.getState(this.chain.tip, deploy);
      let name = deploy.name;

      switch (state) {
        case common.thresholdStates.DEFINED:
        case common.thresholdStates.FAILED:
          break;
        case common.thresholdStates.LOCKED_IN:
          version |= 1 << deploy.bit;
        case common.thresholdStates.STARTED:
          if (!deploy.force) {
            if (rules.indexOf(name) === -1)
              version &= ~(1 << deploy.bit);
            if (deploy.required)
              name = '!' + name;
          }
          vbavailable[name] = deploy.bit;
          break;
        case common.thresholdStates.ACTIVE:
          if (!deploy.force && deploy.required) {
            if (rules.indexOf(name) === -1) {
              throw new RPCError(errs.INVALID_PARAMETER,
                `Client must support ${name}.`);
            }
            name = '!' + name;
          }
          vbrules.push(name);
          break;
        default:
          assert(false, 'Bad state.');
          break;
      }
    }

    version >>>= 0;

    const json = {
      capabilities: ['proposal'],
      mutable: mutable,
      version: version,
      rules: vbrules,
      vbavailable: vbavailable,
      vbrequired: 0,
      height: attempt.height,
      previousblockhash: util.revHex(attempt.prevBlock),
      target: util.revHex(attempt.target.toString('hex')),
      bits: hex32(attempt.bits),
      noncerange: '00000000ffffffff',
      curtime: attempt.time,
      mintime: attempt.mtp + 1,
      maxtime: attempt.time + 7200,
      expires: attempt.time + 7200,
      sigoplimit: consensus.MAX_BLOCK_SIGOPS_COST / scale | 0,
      sizelimit: consensus.MAX_BLOCK_SIZE,
      weightlimit: undefined,
      longpollid: this.chain.tip.rhash() + hex32(this.totalTX()),
      submitold: false,
      coinbaseaux: {
        flags: attempt.coinbaseFlags.toString('hex')
      },
      coinbasevalue: undefined,
      coinbasetxn: undefined,
      default_witness_commitment: undefined,
      transactions: txs
    };

    // See:
    // bitcoin/bitcoin#9fc7f0bce94f1cea0239b1543227f22a3f3b9274
    if (attempt.witness) {
      json.sizelimit = consensus.MAX_RAW_BLOCK_SIZE;
      json.weightlimit = consensus.MAX_BLOCK_WEIGHT;
    }

    // The client wants a coinbasetxn
    // instead of a coinbasevalue.
    if (coinbase) {
      const tx = attempt.toCoinbase();
      const input = tx.inputs[0];

      // Pop off the nonces.
      input.script.pop();
      input.script.compile();

      if (attempt.witness) {
        // We don't include the commitment
        // output (see bip145).
        const output = tx.outputs.pop();
        assert(output.script.isCommitment());

        // Also not including the witness nonce.
        input.witness.clear();
      }

      tx.refresh();

      json.coinbasetxn = {
        data: tx.toRaw().toString('hex'),
        txid: tx.txid(),
        hash: tx.wtxid(),
        depends: [],
        fee: 0,
        sigops: tx.getSigopsCost() / scale | 0,
        weight: tx.getWeight()
      };
    } else {
      json.coinbasevalue = attempt.getReward();
    }

    if (rules.indexOf('segwit') !== -1)
      json.default_witness_commitment = attempt.getWitnessScript().toJSON();

    return json;
  }

  async getMiningInfo(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getmininginfo');

    const attempt = this.attempt;

    let size = 0;
    let weight = 0;
    let txs = 0;
    let diff = 0;

    if (attempt) {
      weight = attempt.weight;
      txs = attempt.items.length + 1;
      diff = attempt.getDifficulty();
      size = 1000;
      for (const item of attempt.items)
        size += item.tx.getBaseSize();
    }

    return {
      blocks: this.chain.height,
      currentblocksize: size,
      currentblockweight: weight,
      currentblocktx: txs,
      difficulty: diff,
      errors: '',
      genproclimit: this.procLimit,
      networkhashps: await this.getHashRate(120),
      pooledtx: this.totalTX(),
      testnet: this.network !== Network.main,
      chain: this.network.type !== 'testnet'
        ? this.network.type
        : 'test',
      generate: this.mining
    };
  }

  async getNetworkHashPS(args, help) {
    if (help || args.length > 2)
      throw new RPCError(errs.MISC_ERROR, 'getnetworkhashps ( blocks height )');

    const valid = new Validator(args);
    const lookup = valid.u32(0, 120);
    const height = valid.u32(1);

    return await this.getHashRate(lookup, height);
  }

  async prioritiseTransaction(args, help) {
    if (help || args.length !== 3) {
      throw new RPCError(errs.MISC_ERROR,
        'prioritisetransaction <txid> <priority delta> <fee delta>');
    }

    const valid = new Validator(args);
    const hash = valid.rhash(0);
    const pri = valid.i64(1);
    const fee = valid.i64(2);

    if (!this.mempool)
      throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

    if (!hash)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID');

    if (pri == null || fee == null)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid fee or priority.');

    const entry = this.mempool.getEntry(hash);

    if (!entry)
      throw new RPCError(errs.MISC_ERROR, 'Transaction not in mempool.');

    this.mempool.prioritise(entry, pri, fee);

    return true;
  }

  async verifyBlock(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'verifyblock "block-hex"');

    const valid = new Validator(args);
    const data = valid.buf(0);

    if (!data)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid block hex.');

    if (this.chain.options.spv)
      throw new RPCError(errs.MISC_ERROR, 'Cannot verify block in SPV mode.');

    const block = Block.fromRaw(data);

    try {
      await this.chain.verifyBlock(block);
    } catch (e) {
      if (e.type === 'VerifyError')
        return e.reason;
      throw e;
    }

    return null;
  }

  /*
   * Coin generation
   */

  async getGenerate(args, help) {
    if (help || args.length !== 0)
      throw new RPCError(errs.MISC_ERROR, 'getgenerate');
    return this.mining;
  }

  async setGenerate(args, help) {
    if (help || args.length < 1 || args.length > 2)
      throw new RPCError(errs.MISC_ERROR, 'setgenerate mine ( proclimit )');

    const valid = new Validator(args);
    const mine = valid.bool(0, false);
    const limit = valid.u32(1, 0);

    if (mine && this.miner.addresses.length === 0) {
      throw new RPCError(errs.MISC_ERROR,
        'No addresses available for coinbase.');
    }

    this.mining = mine;
    this.procLimit = limit;

    if (mine) {
      this.miner.cpu.start();
      return true;
    }

    await this.miner.cpu.stop();

    return false;
  }

  async generate(args, help) {
    if (help || args.length < 1 || args.length > 2)
      throw new RPCError(errs.MISC_ERROR, 'generate numblocks ( maxtries )');

    const valid = new Validator(args);
    const blocks = valid.u32(0, 1);
    const tries = valid.u32(1);

    if (this.miner.addresses.length === 0) {
      throw new RPCError(errs.MISC_ERROR,
        'No addresses available for coinbase.');
    }

    return await this.mineBlocks(blocks, null, tries);
  }

  async generateToAddress(args, help) {
    if (help || args.length < 2 || args.length > 3) {
      throw new RPCError(errs.MISC_ERROR,
        'generatetoaddress numblocks address ( maxtries )');
    }

    const valid = new Validator(args);
    const blocks = valid.u32(0, 1);
    const str = valid.str(1, '');
    const tries = valid.u32(2);

    const addr = parseAddress(str, this.network);

    return await this.mineBlocks(blocks, addr, tries);
  }

  /*
   * Raw transactions
   */

  async createRawTransaction(args, help) {
    if (help || args.length < 2 || args.length > 3) {
      throw new RPCError(errs.MISC_ERROR,
        'createrawtransaction'
        + ' [{"txid":"id","vout":n},...]'
        + ' {"address":amount,"data":"hex",...}'
        + ' ( locktime )');
    }

    const valid = new Validator(args);
    const inputs = valid.array(0);
    const sendTo = valid.obj(1);
    const locktime = valid.u32(2);

    if (!inputs || !sendTo) {
      throw new RPCError(errs.TYPE_ERROR,
        'Invalid parameters (inputs and sendTo).');
    }

    const tx = new MTX();

    if (locktime != null)
      tx.locktime = locktime;

    for (const obj of inputs) {
      const valid = new Validator(obj);
      const hash = valid.rhash('txid');
      const index = valid.u32('vout');
      let sequence = valid.u32('sequence', 0xffffffff);

      if (tx.locktime)
        sequence--;

      if (!hash || index == null)
        throw new RPCError(errs.TYPE_ERROR, 'Invalid outpoint.');

      const input = new Input();
      input.prevout.hash = hash;
      input.prevout.index = index;
      input.sequence = sequence;

      tx.inputs.push(input);
    }

    const sends = new Validator(sendTo);
    const uniq = new Set();

    for (const key of Object.keys(sendTo)) {
      if (key === 'data') {
        const value = sends.buf(key);

        if (!value)
          throw new RPCError(errs.TYPE_ERROR, 'Invalid nulldata..');

        const output = new Output();
        output.value = 0;
        output.script.fromNulldata(value);
        tx.outputs.push(output);

        continue;
      }

      const addr = parseAddress(key, this.network);
      const b58 = addr.toString(this.network);

      if (uniq.has(b58))
        throw new RPCError(errs.INVALID_PARAMETER, 'Duplicate address');

      uniq.add(b58);

      const value = sends.ufixed(key, 8);

      if (value == null)
        throw new RPCError(errs.TYPE_ERROR, 'Invalid output value.');

      const output = new Output();
      output.value = value;
      output.script.fromAddress(addr);

      tx.outputs.push(output);
    }

    return tx.toRaw().toString('hex');
  }

  async decodeRawTransaction(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'decoderawtransaction "hexstring"');

    const valid = new Validator(args);
    const data = valid.buf(0);

    if (!data)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid hex string.');

    const tx = TX.fromRaw(data);

    return this.txToJSON(tx);
  }

  async decodeScript(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'decodescript "hex"');

    const valid = new Validator(args);
    const data = valid.buf(0);

    let script = new Script();

    if (data)
      script = Script.fromRaw(data);

    const addr = Address.fromScripthash(script.hash160());

    const json = this.scriptToJSON(script);
    json.p2sh = addr.toString(this.network);

    return json;
  }

  async getRawTransaction(args, help) {
    if (help || args.length < 1 || args.length > 2) {
      throw new RPCError(errs.MISC_ERROR,
        'getrawtransaction "txid" ( verbose )');
    }

    const valid = new Validator(args);
    const hash = valid.rhash(0);
    const verbose = valid.bool(1, false);

    if (!hash)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid TXID.');

    const meta = await this.node.getMeta(hash);

    if (!meta)
      throw new RPCError(errs.MISC_ERROR, 'Transaction not found.');

    const tx = meta.tx;

    if (!verbose)
      return tx.toRaw().toString('hex');

    let entry;
    if (meta.block)
      entry = await this.chain.getEntry(meta.block);

    const json = this.txToJSON(tx, entry);
    json.time = meta.mtime;
    json.hex = tx.toRaw().toString('hex');

    return json;
  }

  async sendRawTransaction(args, help) {
    if (help || args.length < 1 || args.length > 2) {
      throw new RPCError(errs.MISC_ERROR,
        'sendrawtransaction "hexstring" ( allowhighfees )');
    }

    const valid = new Validator(args);
    const data = valid.buf(0);

    if (!data)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid hex string.');

    const tx = TX.fromRaw(data);

    this.node.relay(tx);

    return tx.txid();
  }

  async signRawTransaction(args, help) {
    if (help || args.length < 1 || args.length > 4) {
      throw new RPCError(errs.MISC_ERROR,
        'signrawtransaction'
        + ' "hexstring" ('
        + ' [{"txid":"id","vout":n,"scriptPubKey":"hex",'
        + 'redeemScript":"hex"},...] ["privatekey1",...]'
        + ' sighashtype )');
    }

    const valid = new Validator(args);
    const data = valid.buf(0);
    const prevout = valid.array(1);
    const secrets = valid.array(2);
    const sighash = valid.str(3);

    if (!data)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid hex string.');

    if (!this.mempool)
      throw new RPCError(errs.MISC_ERROR, 'No mempool available.');

    const tx = MTX.fromRaw(data);
    tx.view = await this.mempool.getSpentView(tx);

    const map = new Map();
    const keys = [];

    if (secrets) {
      const valid = new Validator(secrets);
      for (let i = 0; i < secrets.length; i++) {
        const secret = valid.str(i, '');
        const key = parseSecret(secret, this.network);
        map.set(key.getPublicKey('hex'), key);
        keys.push(key);
      }
    }

    if (prevout) {
      for (const prev of prevout) {
        const valid = new Validator(prev);
        const hash = valid.rhash('txid');
        const index = valid.u32('vout');
        const scriptRaw = valid.buf('scriptPubKey');
        const value = valid.ufixed('amount', 8);
        const redeemRaw = valid.buf('redeemScript');

        if (!hash || index == null || !scriptRaw || value == null)
          throw new RPCError(errs.INVALID_PARAMETER, 'Invalid UTXO.');

        const outpoint = new Outpoint(hash, index);

        const script = Script.fromRaw(scriptRaw);
        const coin = Output.fromScript(script, value);

        tx.view.addOutput(outpoint, coin);

        if (keys.length === 0 || !redeemRaw)
          continue;

        if (!script.isScripthash() && !script.isWitnessScripthash())
          continue;

        if (!redeemRaw) {
          throw new RPCError(errs.INVALID_PARAMETER,
            'P2SH requires redeem script.');
        }

        const redeem = Script.fromRaw(redeemRaw);

        for (const op of redeem.code) {
          if (!op.data)
            continue;

          const key = map.get(op.data.toString('hex'));

          if (key) {
            key.script = redeem;
            key.witness = script.isWitnessScripthash();
            key.refresh();
            break;
          }
        }
      }
    }

    let type = Script.hashType.ALL;
    if (sighash) {
      const parts = sighash.split('|');

      if (parts.length < 1 || parts.length > 2)
        throw new RPCError(errs.INVALID_PARAMETER, 'Invalid sighash type.');

      type = Script.hashType[parts[0]];

      if (type == null)
        throw new RPCError(errs.INVALID_PARAMETER, 'Invalid sighash type.');

      if (parts.length === 2) {
        if (parts[1] !== 'ANYONECANPAY')
          throw new RPCError(errs.INVALID_PARAMETER, 'Invalid sighash type.');
        type |= Script.hashType.ANYONECANPAY;
      }
    }

    await tx.signAsync(keys, type, this.workers);

    return {
      hex: tx.toRaw().toString('hex'),
      complete: tx.isSigned()
    };
  }

  /*
   * Utility Functions
   */

  async createMultisig(args, help) {
    if (help || args.length < 2 || args.length > 2) {
      throw new RPCError(errs.MISC_ERROR,
        'createmultisig nrequired ["key",...]');
    }

    const valid = new Validator(args);
    const keys = valid.array(1, []);
    const m = valid.u32(0, 0);
    const n = keys.length;

    if (m < 1 || n < m || n > 16)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid m and n values.');

    const items = new Validator(keys);

    for (let i = 0; i < keys.length; i++) {
      const key = items.buf(i);

      if (!key)
        throw new RPCError(errs.TYPE_ERROR, 'Invalid key.');

      if (!secp256k1.publicKeyVerify(key))
        throw new RPCError(errs.INVALID_ADDRESS_OR_KEY, 'Invalid key.');

      keys[i] = key;
    }

    const script = Script.fromMultisig(m, n, keys);

    if (script.getSize() > consensus.MAX_SCRIPT_PUSH) {
      throw new RPCError(errs.VERIFY_ERROR,
        'Redeem script exceeds size limit.');
    }

    const addr = script.getAddress();

    return {
      address: addr.toString(this.network),
      redeemScript: script.toJSON()
    };
  }

  async createWitnessAddress(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'createwitnessaddress "script"');

    const valid = new Validator(args);
    const raw = valid.buf(0);

    if (!raw)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid script hex.');

    const script = Script.fromRaw(raw);
    const program = script.forWitness();
    const addr = program.getAddress();

    return {
      address: addr.toString(this.network),
      witnessScript: program.toJSON()
    };
  }

  async validateAddress(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'validateaddress "bitcoinaddress"');

    const valid = new Validator(args);
    const str = valid.str(0, '');

    let addr;
    try {
      addr = Address.fromString(str, this.network);
    } catch (e) {
      return {
        isvalid: false
      };
    }

    const script = Script.fromAddress(addr);

    return {
      isvalid: true,
      address: addr.toString(this.network),
      scriptPubKey: script.toJSON(),
      ismine: false,
      iswatchonly: false
    };
  }

  async verifyMessage(args, help) {
    if (help || args.length !== 3) {
      throw new RPCError(errs.MISC_ERROR,
        'verifymessage "bitcoinaddress" "signature" "message"');
    }

    const valid = new Validator(args);
    const b58 = valid.str(0, '');
    const sig = valid.buf(1, null, 'base64');
    const str = valid.str(2);

    if (!sig || !str)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid parameters.');

    const addr = parseAddress(b58, this.network);
    const msg = Buffer.from(MAGIC_STRING + str, 'utf8');
    const hash = hash256.digest(msg);

    const key = secp256k1.recoverDER(hash, sig, 0, true);

    if (!key)
      return false;

    return ccmp(hash160.digest(key), addr.hash);
  }

  async signMessageWithPrivkey(args, help) {
    if (help || args.length !== 2) {
      throw new RPCError(errs.MISC_ERROR,
        'signmessagewithprivkey "privkey" "message"');
    }

    const valid = new Validator(args);
    const wif = valid.str(0, '');
    const str = valid.str(1, '');

    const key = parseSecret(wif, this.network);
    const msg = Buffer.from(MAGIC_STRING + str, 'utf8');
    const hash = hash256.digest(msg);
    const sig = key.sign(hash);

    return sig.toString('base64');
  }

  async estimateFee(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'estimatefee nblocks');

    const valid = new Validator(args);
    const blocks = valid.u32(0, 1);

    if (!this.fees)
      throw new RPCError(errs.MISC_ERROR, 'Fee estimation not available.');

    const fee = this.fees.estimateFee(blocks, false);

    if (fee === 0)
      return -1;

    return Amount.btc(fee, true);
  }

  async estimatePriority(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'estimatepriority nblocks');

    const valid = new Validator(args);
    const blocks = valid.u32(0, 1);

    if (!this.fees)
      throw new RPCError(errs.MISC_ERROR, 'Priority estimation not available.');

    return this.fees.estimatePriority(blocks, false);
  }

  async estimateSmartFee(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'estimatesmartfee nblocks');

    const valid = new Validator(args);
    const blocks = valid.u32(0, 1);

    if (!this.fees)
      throw new RPCError(errs.MISC_ERROR, 'Fee estimation not available.');

    let fee = this.fees.estimateFee(blocks, true);

    if (fee === 0)
      fee = -1;
    else
      fee = Amount.btc(fee, true);

    return {
      fee: fee,
      blocks: blocks
    };
  }

  async estimateSmartPriority(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'estimatesmartpriority nblocks');

    const valid = new Validator(args);
    const blocks = valid.u32(0, 1);

    if (!this.fees)
      throw new RPCError(errs.MISC_ERROR, 'Priority estimation not available.');

    const pri = this.fees.estimatePriority(blocks, true);

    return {
      priority: pri,
      blocks: blocks
    };
  }

  async invalidateBlock(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'invalidateblock "hash"');

    const valid = new Validator(args);
    const hash = valid.rhash(0);

    if (!hash)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid block hash.');

    await this.chain.invalidate(hash);

    return null;
  }

  async reconsiderBlock(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'reconsiderblock "hash"');

    const valid = new Validator(args);
    const hash = valid.rhash(0);

    if (!hash)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid block hash.');

    this.chain.removeInvalid(hash);

    return null;
  }

  async setMockTime(args, help) {
    if (help || args.length !== 1)
      throw new RPCError(errs.MISC_ERROR, 'setmocktime timestamp');

    const valid = new Validator(args);
    const time = valid.u32(0);

    if (time == null)
      throw new RPCError(errs.TYPE_ERROR, 'Invalid timestamp.');

    this.network.time.offset = 0;

    const delta = this.network.now() - time;

    this.network.time.offset = -delta;

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

  /*
   * Helpers
   */

  async handleLongpoll(lpid) {
    if (lpid.length !== 72)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid longpoll ID.');

    const watched = lpid.slice(0, 64);
    const lastTX = parseInt(lpid.slice(64, 72), 16);

    if ((lastTX >>> 0) !== lastTX)
      throw new RPCError(errs.INVALID_PARAMETER, 'Invalid longpoll ID.');

    const hash = util.revHex(watched);

    if (this.chain.tip.hash !== hash)
      return;

    await this.longpoll();
  }

  longpoll() {
    return new Promise((resolve, reject) => {
      this.pollers.push({ resolve, reject });
    });
  }

  refreshBlock() {
    const pollers = this.pollers;

    this.attempt = null;
    this.lastActivity = 0;
    this.merkleMap.clear();
    this.nonce1 = 0;
    this.nonce2 = 0;
    this.pollers = [];

    for (const job of pollers)
      job.resolve();
  }

  bindChain() {
    if (this.boundChain)
      return;

    this.boundChain = true;

    this.node.on('connect', () => {
      if (!this.attempt)
        return;

      this.refreshBlock();
    });

    if (!this.mempool)
      return;

    this.node.on('tx', () => {
      if (!this.attempt)
        return;

      if (util.now() - this.lastActivity > 10)
        this.refreshBlock();
    });
  }

  async getTemplate() {
    this.bindChain();

    let attempt = this.attempt;

    if (attempt) {
      this.miner.updateTime(attempt);
    } else {
      attempt = await this.miner.createBlock();
      this.attempt = attempt;
      this.lastActivity = util.now();
    }

    return attempt;
  }

  async updateWork() {
    this.bindChain();

    let attempt = this.attempt;

    if (attempt) {
      if (attempt.address.isNull()) {
        throw new RPCError(errs.MISC_ERROR,
          'No addresses available for coinbase.');
      }

      this.miner.updateTime(attempt);

      if (++this.nonce2 === 0x100000000) {
        this.nonce2 = 0;
        this.nonce1++;
      }

      const n1 = this.nonce1;
      const n2 = this.nonce2;

      const root = attempt.getRoot(n1, n2);
      const hash = root.toString('hex');

      this.merkleMap.set(hash, [n1, n2]);

      return attempt;
    }

    if (this.miner.addresses.length === 0) {
      throw new RPCError(errs.MISC_ERROR,
        'No addresses available for coinbase.');
    }

    attempt = await this.miner.createBlock();

    const n1 = this.nonce1;
    const n2 = this.nonce2;

    const root = attempt.getRoot(n1, n2);
    const hash = root.toString('hex');

    this.attempt = attempt;
    this.lastActivity = util.now();
    this.merkleMap.set(hash, [n1, n2]);

    return attempt;
  }

  async addBlock(block) {
    const unlock1 = await this.locker.lock();
    const unlock2 = await this.chain.locker.lock();
    try {
      return await this._addBlock(block);
    } finally {
      unlock2();
      unlock1();
    }
  }

  async _addBlock(block) {
    this.logger.info('Handling submitted block: %s.', block.rhash());

    const prev = await this.chain.getEntry(block.prevBlock);

    if (prev) {
      const state = await this.chain.getDeployments(block.time, prev);

      // Fix eloipool bug (witness nonce is not present).
      if (state.hasWitness() && block.getCommitmentHash()) {
        const tx = block.txs[0];
        const input = tx.inputs[0];
        if (!tx.hasWitness()) {
          this.logger.warning('Submitted block had no witness nonce.');
          this.logger.debug(tx);

          // Recreate witness nonce (all zeroes).
          input.witness.push(consensus.ZERO_HASH);
          input.witness.compile();

          tx.refresh();
          block.refresh();
        }
      }
    }

    let entry;
    try {
      entry = await this.chain._add(block);
    } catch (err) {
      if (err.type === 'VerifyError') {
        this.logger.warning('RPC block rejected: %s (%s).',
          block.rhash(), err.reason);
        return `rejected: ${err.reason}`;
      }
      throw err;
    }

    if (!entry) {
      this.logger.warning('RPC block rejected: %s (bad-prevblk).',
        block.rhash());
      return 'rejected: bad-prevblk';
    }

    return null;
  }

  totalTX() {
    return this.mempool ? this.mempool.map.size : 0;
  }

  getSoftforks() {
    return [
      toDeployment('bip34', 2, this.chain.state.hasBIP34()),
      toDeployment('bip66', 3, this.chain.state.hasBIP66()),
      toDeployment('bip65', 4, this.chain.state.hasCLTV())
    ];
  }

  async getBIP9Softforks() {
    const tip = this.chain.tip;
    const forks = {};

    for (const deployment of this.network.deploys) {
      const state = await this.chain.getState(tip, deployment);
      let status;

      switch (state) {
        case common.thresholdStates.DEFINED:
          status = 'defined';
          break;
        case common.thresholdStates.STARTED:
          status = 'started';
          break;
        case common.thresholdStates.LOCKED_IN:
          status = 'locked_in';
          break;
        case common.thresholdStates.ACTIVE:
          status = 'active';
          break;
        case common.thresholdStates.FAILED:
          status = 'failed';
          break;
        default:
          assert(false, 'Bad state.');
          break;
      }

      forks[deployment.name] = {
        status: status,
        bit: deployment.bit,
        startTime: deployment.startTime,
        timeout: deployment.timeout
      };
    }

    return forks;
  }

  async getHashRate(lookup, height) {
    let tip = this.chain.tip;

    if (height != null)
      tip = await this.chain.getEntry(height);

    if (!tip)
      return 0;

    assert(typeof lookup === 'number');
    assert(lookup >= 0);

    if (lookup === 0)
      lookup = tip.height % this.network.pow.retargetInterval + 1;

    if (lookup > tip.height)
      lookup = tip.height;

    let min = tip.time;
    let max = min;
    let entry = tip;

    for (let i = 0; i < lookup; i++) {
      entry = await this.chain.getPrevious(entry);

      if (!entry)
        throw new RPCError(errs.DATABASE_ERROR, 'Not found.');

      min = Math.min(entry.time, min);
      max = Math.max(entry.time, max);
    }

    const diff = max - min;

    if (diff === 0)
      return 0;

    const work = tip.chainwork.sub(entry.chainwork);

    return Number(work.toString()) / diff;
  }

  async mineBlocks(blocks, addr, tries) {
    const unlock = await this.locker.lock();
    try {
      return await this._mineBlocks(blocks, addr, tries);
    } finally {
      unlock();
    }
  }

  async _mineBlocks(blocks, addr, tries) {
    const hashes = [];

    for (let i = 0; i < blocks; i++) {
      const block = await this.miner.mineBlock(null, addr);
      const entry = await this.chain.add(block);
      assert(entry);
      hashes.push(entry.rhash());
    }

    return hashes;
  }

  async findFork(entry) {
    while (entry) {
      if (await this.chain.isMainChain(entry))
        return entry;
      entry = await this.chain.getPrevious(entry);
    }
    throw new Error('Fork not found.');
  }

  txToJSON(tx, entry) {
    let height = -1;
    let time = 0;
    let hash = null;
    let conf = 0;

    if (entry) {
      height = entry.height;
      time = entry.time;
      hash = entry.rhash();
      conf = this.chain.height - height + 1;
    }

    const vin = [];

    for (const input of tx.inputs) {
      const json = {
        coinbase: undefined,
        txid: undefined,
        scriptSig: undefined,
        txinwitness: undefined,
        sequence: input.sequence
      };

      if (tx.isCoinbase()) {
        json.coinbase = input.script.toJSON();
      } else {
        json.txid = input.prevout.txid();
        json.vout = input.prevout.index;
        json.scriptSig = {
          asm: input.script.toASM(),
          hex: input.script.toJSON()
        };
      }

      if (input.witness.items.length > 0) {
        json.txinwitness = input.witness.items.map((item) => {
          return item.toString('hex');
        });
      }

      vin.push(json);
    }

    const vout = [];

    for (let i = 0; i < tx.outputs.length; i++) {
      const output = tx.outputs[i];
      vout.push({
        value: Amount.btc(output.value, true),
        n: i,
        scriptPubKey: this.scriptToJSON(output.script, true)
      });
    }

    return {
      txid: tx.txid(),
      hash: tx.wtxid(),
      size: tx.getSize(),
      vsize: tx.getVirtualSize(),
      version: tx.version,
      locktime: tx.locktime,
      vin: vin,
      vout: vout,
      blockhash: hash,
      confirmations: conf,
      time: time,
      blocktime: time,
      hex: undefined
    };
  }

  scriptToJSON(script, hex) {
    const type = script.getType();

    const json = {
      asm: script.toASM(),
      hex: undefined,
      type: Script.typesByVal[type],
      reqSigs: 1,
      addresses: [],
      p2sh: undefined
    };

    if (hex)
      json.hex = script.toJSON();

    const [m] = script.getMultisig();

    if (m !== -1)
      json.reqSigs = m;

    const addr = script.getAddress();

    if (addr) {
      const str = addr.toString(this.network);
      json.addresses.push(str);
    }

    return json;
  }

  async headerToJSON(entry) {
    const mtp = await this.chain.getMedianTime(entry);
    const next = await this.chain.getNextHash(entry.hash);

    return {
      hash: entry.rhash(),
      confirmations: this.chain.height - entry.height + 1,
      height: entry.height,
      version: entry.version,
      versionHex: hex32(entry.version),
      merkleroot: util.revHex(entry.merkleRoot),
      time: entry.time,
      mediantime: mtp,
      bits: entry.bits,
      difficulty: toDifficulty(entry.bits),
      chainwork: entry.chainwork.toString('hex', 64),
      previousblockhash: entry.prevBlock !== consensus.NULL_HASH
        ? util.revHex(entry.prevBlock)
        : null,
      nextblockhash: next ? util.revHex(next) : null
    };
  }

  async blockToJSON(entry, block, details) {
    const mtp = await this.chain.getMedianTime(entry);
    const next = await this.chain.getNextHash(entry.hash);
    const txs = [];

    for (const tx of block.txs) {
      if (details) {
        const json = this.txToJSON(tx, entry);
        txs.push(json);
        continue;
      }
      txs.push(tx.txid());
    }

    return {
      hash: entry.rhash(),
      confirmations: this.chain.height - entry.height + 1,
      strippedsize: block.getBaseSize(),
      size: block.getSize(),
      weight: block.getWeight(),
      height: entry.height,
      version: entry.version,
      versionHex: hex32(entry.version),
      merkleroot: util.revHex(entry.merkleRoot),
      coinbase: block.txs[0].inputs[0].script.toJSON(),
      tx: txs,
      time: entry.time,
      mediantime: mtp,
      bits: entry.bits,
      difficulty: toDifficulty(entry.bits),
      chainwork: entry.chainwork.toString('hex', 64),
      previousblockhash: entry.prevBlock !== consensus.NULL_HASH
        ? util.revHex(entry.prevBlock)
        : null,
      nextblockhash: next ? util.revHex(next) : null
    };
  }

  entryToJSON(entry) {
    return {
      size: entry.size,
      fee: Amount.btc(entry.deltaFee, true),
      modifiedfee: 0,
      time: entry.time,
      height: entry.height,
      startingpriority: entry.priority,
      currentpriority: entry.getPriority(this.chain.height),
      descendantcount: this.mempool.countDescendants(entry),
      descendantsize: entry.descSize,
      descendantfees: entry.descFee,
      ancestorcount: this.mempool.countAncestors(entry),
      ancestorsize: 0,
      ancestorfees: 0,
      depends: this.mempool.getDepends(entry.tx).map(util.revHex)
    };
  }
}

/*
 * Helpers
 */

function swap32(data) {
  for (let i = 0; i < data.length; i += 4) {
    const field = data.readUInt32LE(i, true);
    data.writeUInt32BE(field, i, true);
  }
  return data;
}

function toDeployment(id, version, status) {
  return {
    id: id,
    version: version,
    reject: {
      status: status
    }
  };
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

function parseIP(addr, network) {
  try {
    return IP.fromHostname(addr, network.port);
  } catch (e) {
    throw new RPCError(errs.CLIENT_INVALID_IP_OR_SUBNET,
      'Invalid IP address or subnet.');
  }
}

function parseNetAddress(addr, network) {
  try {
    return NetAddress.fromHostname(addr, network);
  } catch (e) {
    throw new RPCError(errs.CLIENT_INVALID_IP_OR_SUBNET,
      'Invalid IP address or subnet.');
  }
}

function toDifficulty(bits) {
  let shift = (bits >>> 24) & 0xff;
  let diff = 0x0000ffff / (bits & 0x00ffffff);

  while (shift < 29) {
    diff *= 256.0;
    shift++;
  }

  while (shift > 29) {
    diff /= 256.0;
    shift--;
  }

  return diff;
}

function hex32(num) {
  assert(num >= 0);

  num = num.toString(16);

  assert(num.length <= 8);

  while (num.length < 8)
    num = '0' + num;

  return num;
}

/*
 * Expose
 */

module.exports = RPC;
