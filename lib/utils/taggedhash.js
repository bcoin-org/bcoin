/*!
 * taggedhash.js - tagged hash writer
 * Copyright (c) 2019, Matthew Zipkin (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const sha256 = require('bcrypto/lib/sha256');

class TaggedHash {
  constructor(tag, bytes) {
    assert(typeof tag === 'string');

    const tagBytes = Buffer.from(tag, 'utf-8');
    const tagHash = sha256.digest(tagBytes);
    this.prefix = Buffer.concat([tagHash, tagHash]);

    if (bytes != null) {
      return this.digest(bytes);
    }
  }

  digest(bytes) {
    assert(Buffer.isBuffer(bytes));
    const input = Buffer.concat([this.prefix, bytes]);
    return sha256.digest(input);
  }
}

exports.TaggedHash = TaggedHash;
exports.TapSighashHash = new TaggedHash('TapSighash');
exports.TapLeafHash = new TaggedHash('TapLeaf');
exports.TapBranchHash = new TaggedHash('TapBranch');
exports.TapTweakHash = new TaggedHash('TapTweak');
