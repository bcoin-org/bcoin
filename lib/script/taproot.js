/*!
* taproot.js - taproot interpreter for bcoin
* https://github.com/bcoin-org/bcoin
*/

'use strict';

const bio = require('bufio');
const common = require('./common');
const { strcmp } = require('../utils/util');

const {
  TapLeafHash,
  TapBranchHash
} = require('../utils/taggedhash');

/**
 * TapLeaf
 */

class TapLeaf {
  /**
   * Create a leaf in taproot tree.
   * @constructor
   * @param {Script} script
   * @param {Number} version
   * @param {String} name
   */

  constructor(script, version=common.LEAF_VERSION_TAPSCRIPT, name='') {
    this.script = script;
    this.version = version;
    this.name = name;
  }
}

const getLeafHash = (script, version) => {
  const size = script.getVarSize();
  const bw = bio.write(size + 1);
  bw.writeU8(version);
  bw.writeVarBytes(script.raw);
  const data = bw.render();
  return TapLeafHash.digest(data);
};

/**
 * Create tree root from array of scripts
 * @param {[TapLeaf]} scripts
 * scripts: a list of items; each item is either:
    - a TapLeaf
    - another list of items (with the same structure)
 * @returns {Buffer} tree root
 */
const taprootTreeHelper = (scripts) => {
   if (scripts.length === 0) { // No script path
    return Buffer.alloc(0);
  } else if (scripts.length === 1) { // Only one script, it's a leaf
    const tapleaf = scripts[0];
    if (Array.isArray(tapleaf))
      return taprootTreeHelper(tapleaf);

    const code = tapleaf.script;
    const version = tapleaf.version;

    return getLeafHash(code, version);
  } else { // Multiple scripts, hash into tree
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

// const taprootConstruct = (pubkey, scripts) => {
//   h = taprootTreeHelper(scripts)
//   tweak = TapTweakHash(pubkey + h)
//   tweaked, sign = schnorr.publicKeyTweakSum(pubkey, tweak)
// };

exports.taprootTreeHelper = taprootTreeHelper;
exports.TapLeaf = TapLeaf;
// exports.taprootConstruct = taprootConstruct;
