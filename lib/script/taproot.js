/*!
* taproot.js - taproot interpreter for bcoin
* https://github.com/bcoin-org/bcoin
*/

'use strict';

const bio = require('bufio');
const assert = require('assert');
const { strcmp } = require('../utils/util');

const {
  TapLeafHash,
  TapBranchHash,
  TapTweakHash
} = require('../utils/taggedhash');

/**
 * TapLeaf
 */

class TapLeaf {
  /**
   * Create a leaf in taproot tree.
   * @constructor
   * @param {Script} script
   * @param {Number} leafVersion
   */

  constructor(script, leafVersion) {
    assert(script);
    assert(leafVersion !== null);
    this.script = script;
    this.leafVersion = leafVersion;
  }

  getLeafHash() {
    const size = this.script.getVarSize();
    const bw = bio.write(size + 1);
    bw.writeU8(this.leafVersion);
    bw.writeVarBytes(this.script.raw);
    const data = bw.render();
    return TapLeafHash.digest(data);
  };
}

/**
 * Create tree root from array of scripts
 * @param {[TapLeaf]} scripts
 * scripts: a list of items; each item is either:
 *  - a TapLeaf
 *  - another list of items (with the same structure)
 * @returns {Buffer} tree root
 */

const taprootTreeHelper = (scripts) => {
  if (scripts.length === 0) {
    return null;
  } else if (scripts.length === 1) {
    const tapleaf = scripts[0];
    if (Array.isArray(tapleaf))
      return taprootTreeHelper(tapleaf);

    return tapleaf.getLeafHash();
  } else {
    const middle = scripts.length / 2;
    const left = scripts.slice(0, middle);
    const right = scripts.slice(middle);

    let leftHash = taprootTreeHelper(left);
    let rightHash = taprootTreeHelper(right);

    const bw = bio.write(64);
    if (strcmp(leftHash, rightHash) > 0) {
      [leftHash, rightHash] = [rightHash, leftHash];
    }
    bw.writeHash(leftHash);
    bw.writeHash(rightHash);
    return TapBranchHash.digest(bw.render());
  }
};

/**
 * @param {Buffer} pubkey internalPubkey
 * @param {Buffer} treeRoot merkleRoot
 * @returns {Buffer} tweak
 */

const getTapTweak = (pubkey, treeRoot) => {
  const tapTweak = bio.write(treeRoot ? 64 : 32);
  tapTweak.writeBytes(pubkey);
  if (treeRoot)
    tapTweak.writeBytes(treeRoot);
  return TapTweakHash.digest(tapTweak.render());
};

exports.TapLeaf = TapLeaf;
exports.taprootTreeHelper = taprootTreeHelper;
exports.getTapTweak = getTapTweak;
