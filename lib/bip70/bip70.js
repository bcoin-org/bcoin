/*!
 * bip70.js - bip70 for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var lazy = require('../utils/lazy')(require, exports);

lazy('PaymentRequest', './paymentrequest');
lazy('PaymentDetails', './paymentdetails');
lazy('Payment', './payment');
lazy('PaymentACK', './paymentack');
lazy('asn1', './asn1');
lazy('x509', './x509');
lazy('pk', './pk');
