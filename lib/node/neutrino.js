'use strict';

const Chain = require('../blockchain/chain');
const {SPVNode} = require('./index');
const {Pool} = require('../net');
const {RPC} = require('bweb');
const HTTP = require('http');
const blockstore = require('../blockstore');

/**
 * Neutrino Node
 * Create a neutrino node which only maintains
 * a chain, a pool, and an http server.
 * @alias module:node.Neutrino
 * @extends Node
 */

class Neutrino extends SPVNode {
  /**
   * Create Neutrino node.
   * @constructor
   * @param {Object?} options
   * @param {Buffer?} options.sslKey
   * @param {Buffer?} options.sslCert
   * @param {Number?} options.httpPort
   * @param {String?} options.httpHost
   */
  constructor(options) {
    super('bcoin', 'bcoin.conf', 'debug.log', options);

    this.opened = false;

    // SPV flag.
    this.spv = true;

    this.blocks = blockstore.create({
      network: this.network,
      logger: this.logger,
      prefix: this.config.prefix,
      cacheSize: this.config.mb('block-cache-size'),
      memory: this.memory
    });

    this.chain = new Chain({
      network: this.network,
      logger: this.logger,
      prefix: this.config.prefix,
      memory: this.memory,
      maxFiles: this.config.uint('max-files'),
      cacheSize: this.config.mb('cache-size'),
      entryCache: this.config.uint('entry-cache'),
      forceFlags: this.config.bool('force-flags'),
      checkpoints: this.config.bool('checkpoints'),
      bip91: this.config.bool('bip91'),
      bip148: this.config.bool('bip148'),
      spv: true
    });

    this.pool = new Pool({
      network: this.network,
      logger: this.logger,
      chain: this.chain,
      prefix: this.config.prefix,
      proxy: this.config.str('proxy'),
      onion: this.config.bool('onion'),
      upnp: this.config.bool('upnp'),
      seeds: this.config.array('seeds'),
      nodes: this.config.array('nodes'),
      only: this.config.array('only'),
      maxOutbound: this.config.uint('max-outbound'),
      createSocket: this.config.func('create-socket'),
      memory: this.memory,
      selfish: true,
      listen: false
    });

    this.rpc = new RPC(this);

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
      cors: this.config.bool('cors')
    });

    this.init();
  }

  init() {
    // Bind to errors
    this.chain.on('error', err => this.error(err));
    this.pool.on('error', err => this.error(err));

    if (this.http)
      this.http.on('error', err => this.error(err));

    this.pool.on('tx', (tx) => {
      this.emit('tx', tx);
    });

    this.chain.on('block', (block) => {
      this.emit('block', block);
    });

    this.chain.on('connect', async (entry, block) => {
      this.emit('connect', entry, block);
    });

    this.chain.on('disconnect', (entry, block) => {
      this.emit('disconnect', entry, block);
    });

    this.chain.on('reorganize', (tip, competitor) => {
      this.emit('reorganize', tip, competitor);
    });

    this.chain.on('reset', (tip) => {
      this.emit('reset', tip);
    });

    this.loadPlugins();
  }
}

module.exports = Neutrino;
