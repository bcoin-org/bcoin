/**
 * Javascript bitcoin library. Exposes the global environment.
 * @module bcoin
 * @see {Environment}
 * @license
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

'use strict';

var env = require('./env');
var util = require('./utils/util');
var global = util.global;

/*
 * Expose bcoin globally in the
 * browser. Necessary for workers.
 */

if (util.isBrowser)
  global.bcoin = env;

module.exports = env;
