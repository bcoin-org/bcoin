/*!
 * upnp-browser.js - upnp for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * UPNP
 */

class UPNP {
  /**
   * Create a UPNP context.
   * @constructor
   * @param {String?} host - Multicast IP.
   * @param {Number?} port - Multicast port.
   * @param {String?} gateway - Gateway name.
   */

  constructor(host, port, gateway) {
    throw new Error('UPNP not supported.');
  }

  /**
   * Discover gateway and resolve service.
   * @param {String?} host - Multicast IP.
   * @param {Number?} port - Multicast port.
   * @param {String?} gateway - Gateway type.
   * @param {String[]?} targets - Target service types.
   * @returns {Promise} Service.
   */

  static async discover(host, port, gateway, targets) {
    throw new Error('UPNP not supported.');
  }
}

UPNP.unsupported = true;

/*
 * Expose
 */

module.exports = UPNP;
