/*!
 * fullnode.js - full node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const Chain = require('../blockchain/chain');
const Fees = require('../mempool/fees');
const Mempool = require('../mempool/mempool');
const Pool = require('../net/pool');
const Miner = require('../mining/miner');
const Node = require('./node');
const HTTP = require('./http');
const RPC = require('./rpc');
const blockstore = require('../blockstore');
const TXIndexer = require('../indexer/txindexer');
const AddrIndexer = require('../indexer/addrindexer');
const FilterIndexer = require('../indexer/filterindexer');

/**
 * Full Node
 * Respresents a fullnode complete with a
 * chain, mempool, miner, etc.
 * @alias module:node.FullNode
 * @extends Node
 */

class FullNode extends Node {
  /**
   * Create a full node.
   * @constructor
   * @param {Object?} options
   */

  constructor(options) {
    super('bcoin', 'bcoin.conf', 'debug.log', options);

    this.opened = false;

    // SPV flag.
    this.spv = false;

    // Instantiate block storage.
    this.blocks = blockstore.create({
      network: this.network,
      logger: this.logger,
      prefix: this.config.prefix,
      cacheSize: this.config.mb('block-cache-size'),
      memory: this.memory
    });

    // Chain needs access to blocks.
    this.chain = new Chain({
      network: this.network,
      logger: this.logger,
      blocks: this.blocks,
      workers: this.workers,
      memory: this.config.bool('memory'),
      prefix: this.config.prefix,
      maxFiles: this.config.uint('max-files'),
      cacheSize: this.config.mb('cache-size'),
      forceFlags: this.config.bool('force-flags'),
      bip91: this.config.bool('bip91'),
      bip148: this.config.bool('bip148'),
      prune: this.config.bool('prune'),
      checkpoints: this.config.bool('checkpoints'),
      entryCache: this.config.uint('entry-cache'),
      indexTX: this.config.bool('index-tx'),
      indexAddress: this.config.bool('index-address')
    });

    // Fee estimation.
    this.fees = new Fees(this.logger);
    this.fees.init();

    // Mempool needs access to the chain.
    this.mempool = new Mempool({
      network: this.network,
      logger: this.logger,
      workers: this.workers,
      chain: this.chain,
      fees: this.fees,
      memory: this.memory,
      prefix: this.config.prefix,
      persistent: this.config.bool('persistent-mempool'),
      maxSize: this.config.mb('mempool-size'),
      limitFree: this.config.bool('limit-free'),
      limitFreeRelay: this.config.uint('limit-free-relay'),
      requireStandard: this.config.bool('require-standard'),
      rejectAbsurdFees: this.config.bool('reject-absurd-fees'),
      replaceByFee: this.config.bool('replace-by-fee'),
      indexAddress: this.config.bool('index-address')
    });

    // Indexers
    if (this.config.bool('index-tx')) {
      this.txindex = new TXIndexer({
        network: this.network,
        logger: this.logger,
        blocks: this.blocks,
        chain: this.chain,
        prune: this.config.bool('prune'),
        memory: this.memory,
        prefix: this.config.str('index-prefix', this.config.prefix)
      });
    }

    if (this.config.bool('index-address')) {
      this.addrindex = new AddrIndexer({
        network: this.network,
        logger: this.logger,
        blocks: this.blocks,
        chain: this.chain,
        prune: this.config.bool('prune'),
        memory: this.memory,
        prefix: this.config.str('index-prefix', this.config.prefix),
        maxTxs: this.config.uint('max-txs')
      });
    }

    if (this.config.bool('index-filter')) {
      this.filterIndexers.set(
        'BASIC',
        new FilterIndexer({
          network: this.network,
          logger: this.logger,
          blocks: this.blocks,
          chain: this.chain,
          memory: this.config.bool('memory'),
          prefix: this.config.str('index-prefix', this.config.prefix),
          filterType: 'BASIC'
        })
      );
    }

    // Pool needs access to the chain and mempool.
    this.pool = new Pool({
      network: this.network,
      logger: this.logger,
      chain: this.chain,
      mempool: this.mempool,
      prefix: this.config.prefix,
      filterIndexers: this.filterIndexers,
      selfish: this.config.bool('selfish'),
      compact: this.config.bool('compact'),
      bip37: this.config.bool('bip37'),
      maxOutbound: this.config.uint('max-outbound'),
      maxInbound: this.config.uint('max-inbound'),
      createSocket: this.config.func('create-socket'),
      proxy: this.config.str('proxy'),
      onion: this.config.bool('onion'),
      upnp: this.config.bool('upnp'),
      seeds: this.config.array('seeds'),
      nodes: this.config.array('nodes'),
      only: this.config.array('only'),
      publicHost: this.config.str('public-host'),
      publicPort: this.config.uint('public-port'),
      host: this.config.str('host'),
      port: this.config.uint('port'),
      listen: this.config.bool('listen'),
      memory: this.memory,
      bip157: this.config.bool('bip157')
  });

    // Miner needs access to the chain and mempool.
    this.miner = new Miner({
      network: this.network,
      logger: this.logger,
      workers: this.workers,
      chain: this.chain,
      mempool: this.mempool,
      address: this.config.array('coinbase-address'),
      coinbaseFlags: this.config.str('coinbase-flags'),
      preverify: this.config.bool('preverify'),
      maxWeight: this.config.uint('max-weight'),
      reservedWeight: this.config.uint('reserved-weight'),
      reservedSigops: this.config.uint('reserved-sigops')
    });

    // RPC needs access to the node.
    this.rpc = new RPC(this);

    // HTTP needs access to the node.
    this.http = new HTTP({
      network: this.network,
      logger: this.logger,
      node: this,
      prefix: this.config.prefix,
      ssl: this.config.bool('ssl'),
      keyFile: this.config.path('ssl-key'),
      certFile: this.config.path('ssl-cert'),
      host: this.config.str('http-host'),
      port: this.config.uint('http-port'),
      apiKey: this.config.str('api-key'),
      noAuth: this.config.bool('no-auth'),
      cors: this.config.bool('cors'),
      maxTxs: this.config.uint('max-txs')
    });

    this.init();
  }

  /**
   * Initialize the node.
   * @private
   */

  init() {
    // Bind to errors
    this.chain.on('error', err => this.error(err));
    this.mempool.on('error', err => this.error(err));
    this.pool.on('error', err => this.error(err));
    this.miner.on('error', err => this.error(err));

    if (this.txindex)
      this.txindex.on('error', err => this.error(err));

    if (this.addrindex)
      this.addrindex.on('error', err => this.error(err));

    if (this.filterIndexers) {
      for (const filterindex of this.filterIndexers.values()) {
        filterindex.on('error', err => this.error(err));
      }
    }

    if (this.http)
      this.http.on('error', err => this.error(err));

    this.mempool.on('tx', (tx) => {
      this.miner.cpu.notifyEntry();
      this.emit('tx', tx);
    });

    this.chain.on('connect', async (entry, block) => {
      try {
        await this.mempool._addBlock(entry, block.txs);
      } catch (e) {
        this.error(e);
      }
      this.emit('block', block);
      this.emit('connect', entry, block);
    });

    this.chain.on('disconnect', async (entry, block) => {
      try {
        await this.mempool._removeBlock(entry, block.txs);
      } catch (e) {
        this.error(e);
      }
      this.emit('disconnect', entry, block);
    });

    this.chain.on('reorganize', async (tip, competitor) => {
      try {
        await this.mempool._handleReorg();
      } catch (e) {
        this.error(e);
      }
      this.emit('reorganize', tip, competitor);
    });

    this.chain.on('reset', async (tip) => {
      try {
        await this.mempool._reset();
      } catch (e) {
        this.error(e);
      }
      this.emit('reset', tip);
    });

    this.loadPlugins();
  }

  /**
   * Open the node and all its child objects,
   * wait for the database to load.
   * @alias FullNode#open
   * @returns {Promise}
   */

  async open() {
    assert(!this.opened, 'FullNode is already open.');
    this.opened = true;

    await this.handlePreopen();
    await this.blocks.open();
    await this.chain.open();
    await this.mempool.open();
    await this.miner.open();
    await this.pool.open();

    if (this.txindex)
      await this.txindex.open();

    if (this.addrindex)
      await this.addrindex.open();

    if (this.filterIndexers) {
      for (const filterindex of this.filterIndexers.values()) {
        await filterindex.open();
      }
    }

    await this.openPlugins();

    await this.http.open();
    await this.handleOpen();

    this.logger.info('Node is loaded.');
  }

  /**
   * Close the node, wait for the database to close.
   * @alias FullNode#close
   * @returns {Promise}
   */

  async close() {
    assert(this.opened, 'FullNode is not open.');
    this.opened = false;

    await this.handlePreclose();
    await this.http.close();

    if (this.txindex)
      await this.txindex.close();

    if (this.addrindex)
      await this.addrindex.close();

    if (this.filterIndexers) {
      for (const filterindex of this.filterIndexers.values()) {
        await filterindex.close();
      }
    }

    await this.closePlugins();

    await this.pool.close();
    await this.miner.close();
    await this.mempool.close();
    await this.chain.close();
    await this.blocks.close();

    await this.handleClose();
  }

  /**
   * Rescan for any missed transactions.
   * @param {Number|Hash} start - Start block.
   * @param {BloomFilter} filter
   * @param {Function} iter - Iterator.
   * @returns {Promise}
   */

  scan(start, filter, iter) {
    return this.chain.scan(start, filter, iter);
  }

  /**
   * Broadcast a transaction (note that this will _not_ be verified
   * by the mempool - use with care, lest you get banned from
   * bitcoind nodes).
   * @param {TX|Block} item
   * @returns {Promise}
   */

  async broadcast(item) {
    try {
      await this.pool.broadcast(item);
    } catch (e) {
      this.emit('error', e);
    }
  }

  /**
   * Add transaction to mempool, broadcast.
   * @param {TX} tx
   * @returns {Promise}
   */

  async sendTX(tx) {
    let missing;

    try {
      missing = await this.mempool.addTX(tx);
    } catch (err) {
      if (err.type === 'VerifyError' && err.score === 0) {
        this.error(err);
        this.logger.warning('Verification failed for tx: %h.', tx.hash());
        this.logger.warning('Attempting to broadcast anyway...');
        this.broadcast(tx);
        return;
      }
      throw err;
    }

    if (missing) {
      this.logger.warning('TX was orphaned in mempool: %h.', tx.hash());
      this.logger.warning('Attempting to broadcast anyway...');
      this.broadcast(tx);
      return;
    }

    // We need to announce by hand if
    // we're running in selfish mode.
    if (this.pool.options.selfish)
      this.broadcast(tx);
  }

  /**
   * Add transaction to mempool, broadcast. Silence errors.
   * @param {TX} tx
   * @returns {Promise}
   */

  async relay(tx) {
    try {
      await this.sendTX(tx);
    } catch (e) {
      this.error(e);
    }
  }

  /**
   * Connect to the network.
   * @returns {Promise}
   */

  connect() {
    return this.pool.connect();
  }

  /**
   * Disconnect from the network.
   * @returns {Promise}
   */

  disconnect() {
    return this.pool.disconnect();
  }

  /**
   * Start the blockchain sync.
   */

  startSync() {
    if (this.txindex)
      this.txindex.sync();

    if (this.addrindex)
      this.addrindex.sync();

    if (this.filterIndexers) {
      for (const filterindex of this.filterIndexers.values()) {
        filterindex.sync();
      }
    }

    return this.pool.startSync();
  }

  /**
   * Stop syncing the blockchain.
   */

  stopSync() {
    return this.pool.stopSync();
  }

  /**
   * Retrieve a block from the chain database.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Block}.
   */

  getBlock(hash) {
    return this.chain.getBlock(hash);
  }

  /**
   * Retrieve a coin from the mempool or chain database.
   * Takes into account spent coins in the mempool.
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise} - Returns {@link Coin}.
   */

  async getCoin(hash, index) {
    const coin = this.mempool.getCoin(hash, index);

    if (coin)
      return coin;

    if (this.mempool.isSpent(hash, index))
      return null;

    return this.chain.getCoin(hash, index);
  }

  /**
   * Retrieve transactions pertaining to an
   * address from the mempool or chain database.
   * @param {Address} addr
   * @param {Object} options
   * @param {Number} options.limit
   * @param {Number} options.reverse
   * @param {Buffer} options.after
   * @returns {Promise} - Returns {@link TXMeta}[].
   */

  async getMetaByAddress(addr, options = {}) {
    if (!this.txindex || !this.addrindex)
      return [];

    const {reverse, after} = options;
    let {limit} = options;

    let metas = [];

    const confirmed = async () => {
      const hashes = await this.addrindex.getHashesByAddress(
        addr, {limit, reverse, after});

      for (const hash of hashes) {
        const mtx = await this.txindex.getMeta(hash);
        assert(mtx);
        metas.push(mtx);
      }
    };

    const unconfirmed = () => {
      const mempool = this.mempool.getMetaByAddress(
        addr, {limit, reverse, after});

      metas = metas.concat(mempool);
    };

    if (reverse)
      unconfirmed();
    else
      await confirmed();

    if (metas.length > 0)
      limit -= metas.length;

    if (limit <= 0)
      return metas;

    if (reverse)
      await confirmed();
    else
      unconfirmed();

    return metas;
  }

  /**
   * Retrieve a transaction from the mempool or chain database.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link TXMeta}.
   */

  async getMeta(hash) {
    const meta = this.mempool.getMeta(hash);

    if (meta)
      return meta;

    if (this.txindex)
      return this.txindex.getMeta(hash);

    return null;
  }

  /**
   * Retrieve a spent coin viewpoint from mempool or chain database.
   * @param {TXMeta} meta
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async getMetaView(meta) {
    if (meta.height === -1)
      return this.mempool.getSpentView(meta.tx);

    if (this.txindex)
      return this.txindex.getSpentView(meta.tx);

    return null;
  }

  /**
   * Retrieve transactions pertaining to an
   * address from the mempool or chain database.
   * @param {Address} addr
   * @param {Object} options
   * @param {Number} options.limit
   * @param {Number} options.reverse
   * @param {Buffer} options.after
   * @returns {Promise} - Returns {@link TX}[].
   */

  async getTXByAddress(addr, options = {}) {
    const mtxs = await this.getMetaByAddress(addr, options);
    const out = [];

    for (const mtx of mtxs)
      out.push(mtx.tx);

    return out;
  }

  /**
   * Retrieve a transaction from the mempool or chain database.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link TX}.
   */

  async getTX(hash) {
    const mtx = await this.getMeta(hash);

    if (!mtx)
      return null;

    return mtx.tx;
  }

  /**
   * Test whether the mempool or chain contains a transaction.
   * @param {Hash} hash
   * @returns {Promise} - Returns Boolean.
   */

  async hasTX(hash) {
    if (this.mempool.hasEntry(hash))
      return true;

    if (this.txindex)
      return this.txindex.hasTX(hash);

    return false;
  }

  /**
   * Retrieve compact filter by hash.
   * @param {Hash | Number} hash
   * @param {Number} type
   * @returns {Promise} - Returns {@link Buffer}.
   */

  async getBlockFilter(hash, filterType) {
    const Indexer = this.filterIndexers.get(filterType);

    if (!Indexer)
      return null;

    if (typeof hash === 'number')
      hash = await this.chain.getHash(hash);

    if (!hash)
      return null;

    return Indexer.getFilter(hash);
  }
}

/*
 * Expose
 */

module.exports = FullNode;
