'use strict';

const LocalStore = require('./localstore');
const LDBStore = require('./ldbstore');
const FlatStore = require('./flatstore');

module.exports = function store(db, options) {
  if (!options.location || options.spv)
    return new LocalStore(db, options);

  if (options.flat)
    return new FlatStore(db, options);

  return new LDBStore(db, options);
};
