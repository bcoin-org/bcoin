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

const getLeafHash = (script, version) => {
    const size = script.getVarSize();
    const bw = bio.write(size + 1);
    bw.writeU8(version);
    bw.writeVarBytes(script.raw);
    const data = bw.render();
    return TapLeafHash.digest(data);
};

const taprootTreeHelper = (scripts) => {
    if (scripts.length === 0) { // No script path
        return Buffer.alloc(0);
    } else if (scripts.length === 1) { // Only one script, it's a leaf
        const script = scripts[0];
        if (Array.isArray(script))
            return taprootTreeHelper(script);

        const code = script.script;
        let version = common.LEAF_VERSION_TAPSCRIPT;
        if ('version' in script)
            version = script.version;

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

exports.taprootTreeHelper = taprootTreeHelper;
