'use strict';

const fs = require('fs');

const bcoincli = require.resolve('bclient/bin/bcoin-cli');
const bwalletcli = require.resolve('bclient/bin/bwallet-cli');

fs.unlink('./bin/bcoin-cli', () => {
    fs.symlinkSync(bcoincli, './bin/bcoin-cli');
});

fs.unlink('./bin/bwallet-cli', () => {
  fs.symlinkSync(bwalletcli, './bin/bwallet-cli');
});
