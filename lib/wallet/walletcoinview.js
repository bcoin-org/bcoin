/*!
 * walletcoinview.js - wallet coin viewpoint object for hsd
 * Copyright (c) 2019, Boyma Fahnbulleh (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

const assert = require('bsert');
const {BufferMap} = require('buffer-map');
const Paths = require('./paths');
const CoinView = require('../coins/coinview');

/**
 * Wallet Coin View
 * Represents a wallet, coin viewpoint: a snapshot of {@link Coins} objects
 * and the HD paths for their associated keys.
 * @alias module:wallet.WalletCoinView
 * @property {Object} map
 * @property {Object} paths
 * @property {UndoCoins} undo
 */

class WalletCoinView extends CoinView {
  /**
   * Create a wallet coin view.
   * @constructor
   */

  constructor() {
    super();
    this.paths = new BufferMap();
  }

  /**
   * Inject properties from coin view object.
   * @private
   * @param {CoinView} view
   */

  fromCoinView(view) {
    assert(view instanceof CoinView, 'View must be instance of CoinView');
    this.map = view.map;
    this.undo = view.undo;
    this.bits = view.bits;
    return this;
  }

  /**
   * Instantiate wallet coin view from coin view.
   * @param {CoinView} view
   * @returns {WalletCoinView}
   */

  static fromCoinView(view) {
    return new this().fromCoinView(view);
  }

  /**
   * Add paths to the collection.
   * @param {Hash} hash
   * @param {Paths} path
   * @returns {Paths|null}
   */

  addPaths(hash, paths) {
    this.paths.set(hash, paths);
    return paths;
  }

  /**
   * Get paths.
   * @param {Hash} hash
   * @returns {Paths} paths
   */

  getPaths(hash) {
    return this.paths.get(hash);
  }

  /**
   * Test whether the view has a paths entry.
   * @param {Hash} hash
   * @returns {Boolean}
   */

  hasPaths(hash) {
    return this.paths.has(hash);
  }

  /**
   * Ensure existence of paths object in the collection.
   * @param {Hash} hash
   * @returns {Coins}
   */

  ensurePaths(hash) {
    const paths = this.paths.get(hash);

    if (paths)
      return paths;

    return this.addPaths(hash, new Paths());
  }

  /**
   * Remove paths from the collection.
   * @param {Paths} paths
   * @returns {Paths|null}
   */

  removePaths(hash) {
    const paths = this.paths.get(hash);

    if (!paths)
      return null;

    this.paths.delete(hash);

    return paths;
  }

  /**
   * Add an HD path to the collection.
   * @param {Outpoint} prevout
   * @param {Path} path
   * @returns {Path|null}
   */

  addPath(prevout, path) {
    const {hash, index} = prevout;
    const paths = this.ensurePaths(hash);
    return paths.add(index, path);
  }

  /**
   * Get an HD path by prevout.
   * @param {Outpoint} prevout
   * @returns {Path|null}
   */

  getPath(prevout) {
    const {hash, index} = prevout;
    const paths = this.getPaths(hash);

    if (!paths)
      return null;

    return paths.get(index);
  }

  /**
   * Remove an HD path.
   * @param {Outpoint} prevout
   * @returns {Path|null}
   */

  removePath(prevout) {
    const {hash, index} = prevout;
    const paths = this.getPaths(hash);

    if (!paths)
      return null;

    return paths.remove(index);
  }

  /**
   * Test whether the view has a path by prevout.
   * @param {Outpoint} prevout
   * @returns {Boolean}
   */

  hasPath(prevout) {
    const {hash, index} = prevout;
    const paths = this.getPaths(hash);

    if (!paths)
      return false;

    return paths.has(index);
  }

  /**
   * Get a single path by input.
   * @param {Input} input
   * @returns {Path|null}
   */

  getPathFor(input) {
    return this.getPath(input.prevout);
  }
}

/*
 * Expose
 */

module.exports = WalletCoinView;
