/*!
 * bcoin.js - a javascript bitcoin library.
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

'use strict';

/**
 * Exposes the global environment.
 * An instance of {@link Environment}.
 * @module bcoin
 * @see {Environment}
 * @license
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var env = require('./env');
var util = require('./utils/util');
var global = util.global;

/*
 * Expose bcoin globally in the
 * browser. Necessary for workers.
 */

if (util.isBrowser)
  global.bcoin = env;

/*
 * Expose
 */

module.exports = env;
