/*!
 * backend.js - backend selection for bfile
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bfile
 */

'use strict';

const features = require('./features');

/*
 * Expose
 */

if (features.HAS_ALL)
  module.exports = require('./modern');
else
  module.exports = require('./legacy');
