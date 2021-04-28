/*!
 * upnp.js - upnp for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const dgram = require('dgram');
const url = require('url');
const brq = require('brq');
const IP = require('binet');

/**
 * UPNP
 */

class UPNP {
  /**
   * Create a UPNP context.
   * @constructor
   * @param {String} [host=239.255.255.250] - Multicast IP.
   * @param {Number} [port=1900] - Multicast port.
   * @param {String?} gateway - Gateway name.
   */

  constructor(host, port, gateway) {
    this.host = host || '239.255.255.250';
    this.port = port || 1900;
    this.gateway = gateway || UPNP.INTERNET_GATEWAY;
    this.timeout = null;
    this.job = null;
  }

  /**
   * Clean up current job.
   * @private
   * @returns {Job}
   */

  cleanupJob() {
    const job = this.job;

    assert(this.socket);
    assert(this.job);

    this.job = null;

    this.socket.close();
    this.socket = null;

    this.stopTimeout();

    return job;
  }

  /**
   * Reject current job.
   * @private
   * @param {Error} err
   */

  rejectJob(err) {
    const job = this.cleanupJob();
    job.reject(err);
  }

  /**
   * Resolve current job.
   * @private
   * @param {Object} result
   */

  resolveJob(result) {
    const job = this.cleanupJob();
    job.resolve(result);
  }

  /**
   * Start gateway timeout.
   * @private
   */

  startTimeout() {
    this.stopTimeout();
    this.timeout = setTimeout(() => {
      this.timeout = null;
      this.rejectJob(new Error('Request timed out.'));
    }, UPNP.RESPONSE_TIMEOUT);
  }

  /**
   * Stop gateway timeout.
   * @private
   */

  stopTimeout() {
    if (this.timeout != null) {
      clearTimeout(this.timeout);
      this.timeout = null;
    }
  }

  /**
   * Discover gateway.
   * @private
   * @returns {Promise} Location string.
   */

  async discover() {
    if (this.job)
      throw new Error('Job already in progress.');

    const socket = dgram.createSocket('udp4');

    socket.on('error', (err) => {
      this.rejectJob(err);
    });

    socket.on('message', (data, rinfo) => {
      const msg = data.toString('utf8');
      this.handleMsg(msg);
    });

    this.socket = socket;
    this.startTimeout();

    const msg = ''
      + 'M-SEARCH * HTTP/1.1\r\n'
      + `HOST: ${this.host}:${this.port}\r\n`
      + 'MAN: ssdp:discover\r\n'
      + 'MX: 10\r\n'
      + 'ST: ssdp:all\r\n';

    socket.send(msg, this.port, this.host);

    return new Promise((resolve, reject) => {
      this.job = { resolve, reject };
    });
  }

  /**
   * Handle incoming UDP message.
   * @private
   * @param {String} msg
   * @returns {Promise}
   */

  async handleMsg(msg) {
    if (!this.socket)
      return;

    let headers;
    try {
      headers = UPNP.parseHeader(msg);
    } catch (e) {
      return;
    }

    if (!headers.location)
      return;

    if (headers.st !== this.gateway)
      return;

    this.resolveJob(headers.location);
  }

  /**
   * Resolve service parameters from location.
   * @param {String} location
   * @param {String[]} targets - Target services.
   * @returns {Promise}
   */

  async resolve(location, targets) {
    const host = parseHost(location);

    if (!targets)
      targets = UPNP.WAN_SERVICES;

    const res = await brq({
      method: 'GET',
      url: location,
      timeout: UPNP.RESPONSE_TIMEOUT,
      expect: 'xml'
    });

    const xml = XMLElement.fromRaw(res.text());

    const services = parseServices(xml);
    assert(services.length > 0, 'No services found.');

    const service = extractServices(services, targets);
    assert(service, 'No service found.');
    assert(service.serviceId, 'No service ID found.');
    assert(service.serviceId.length > 0, 'No service ID found.');
    assert(service.controlURL, 'No control URL found.');
    assert(service.controlURL.length > 0, 'No control URL found.');

    service.controlURL = prependHost(host, service.controlURL);

    if (service.eventSubURL)
      service.eventSubURL = prependHost(host, service.eventSubURL);

    if (service.SCPDURL)
      service.SCPDURL = prependHost(host, service.SCPDURL);

    return service;
  }

  /**
   * Parse UPNP datagram.
   * @private
   * @param {String} str
   * @returns {Object}
   */

  static parseHeader(str) {
    const lines = str.split(/\r?\n/);
    const headers = Object.create(null);

    for (let line of lines) {
      line = line.trim();

      if (line.length === 0)
        continue;

      const index = line.indexOf(':');

      if (index === -1) {
        const left = line.toLowerCase();
        headers[left] = '';
        continue;
      }

      let left = line.substring(0, index);
      let right = line.substring(index + 1);

      left = left.trim();
      right = right.trim();

      left = left.toLowerCase();

      headers[left] = right;
    }

    return headers;
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
    const upnp = new this(host, port, gateway);
    const location = await upnp.discover();
    const service = await upnp.resolve(location, targets);
    return new UPNPService(service);
  }
}

/**
 * Default internet gateway string.
 * @const {String}
 * @default
 */

UPNP.INTERNET_GATEWAY = 'urn:schemas-upnp-org:device:InternetGatewayDevice:1';

/**
 * Default service types.
 * @const {String[]}
 * @default
 */

UPNP.WAN_SERVICES = [
  'urn:schemas-upnp-org:service:WANIPConnection:1',
  'urn:schemas-upnp-org:service:WANPPPConnection:1'
];

/**
 * Timeout before killing request.
 * @const {Number}
 * @default
 */

UPNP.RESPONSE_TIMEOUT = 1000;

/**
 * Unsupported flag.
 * @const {Boolean}
 * @default
 */

UPNP.unsupported = false;

/**
 * UPNP Service
 */

class UPNPService {
  /**
   * Create a gateway service.
   * @constructor
   * @param {Object} options - Service parameters.
   */

  constructor(options) {
    this.serviceType = options.serviceType;
    this.serviceId = options.serviceId;
    this.controlURL = options.controlURL;
    this.eventSubURL = options.eventSubURL;
    this.SCPDURL = options.SCPDURL;
  }

  /**
   * Compile SOAP request.
   * @private
   * @param {String} action
   * @param {String[]} args
   * @returns {String}
   */

  createRequest(action, args) {
    const type = JSON.stringify(this.serviceType);

    let params = '';

    for (const [key, value] of args) {
      params += `<${key}>`;
      if (value != null)
        params += value;
      params += `</${key}>`;
    }

    return ''
      + '<?xml version="1.0"?>'
      + '<s:Envelope'
      + ' xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
      + ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
      + '<s:Body>'
      + `<u:${action} xmlns:u=${type}>`
      + `${params}`
      + `</u:${action}>`
      + '</s:Body>'
      + '</s:Envelope>';
  }

  /**
   * Send SOAP request and parse XML response.
   * @private
   * @param {String} action
   * @param {String[]} args
   * @returns {XMLElement}
   */

  async soapRequest(action, args) {
    const type = this.serviceType;
    const req = this.createRequest(action, args);

    const res = await brq({
      method: 'POST',
      url: this.controlURL,
      timeout: UPNP.RESPONSE_TIMEOUT,
      expect: 'xml',
      headers: {
        'Content-Type': 'text/xml; charset="utf-8"',
        'Content-Length': Buffer.byteLength(req, 'utf8').toString(10),
        'Connection': 'close',
        'SOAPAction': JSON.stringify(`${type}#${action}`)
      },
      body: req
    });

    const xml = XMLElement.fromRaw(res.text());
    const err = findError(xml);

    if (err)
      throw err;

    return xml;
  }

  /**
   * Attempt to get external IP from service (wan).
   * @returns {Promise}
   */

  async getExternalIP() {
    const action = 'GetExternalIPAddress';
    const xml = await this.soapRequest(action, []);
    const ip = findIP(xml);

    if (!ip)
      throw new Error('Could not find external IP.');

    return ip;
  }

  /**
   * Attempt to add port mapping to local IP.
   * @param {String} remote - Remote IP.
   * @param {Number} src - Remote port.
   * @param {Number} dest - Local port.
   * @returns {Promise}
   */

  async addPortMapping(remote, src, dest) {
    const action = 'AddPortMapping';
    const local = IP.getPrivate();

    if (local.length === 0)
      throw new Error('Cannot determine local IP.');

    const xml = await this.soapRequest(action, [
      ['NewRemoteHost', remote],
      ['NewExternalPort', src],
      ['NewProtocol', 'TCP'],
      ['NewInternalClient', local[0]],
      ['NewInternalPort', dest],
      ['NewEnabled', 'True'],
      ['NewPortMappingDescription', 'upnp:nodejs'],
      ['NewLeaseDuration', 0]
    ]);

    const child = xml.find('AddPortMappingResponse');

    if (!child)
      throw new Error('Port mapping failed.');

    return child.text;
  }

  /**
   * Attempt to remove port mapping from local IP.
   * @param {String} remote - Remote IP.
   * @param {Number} port - Remote port.
   * @returns {Promise}
   */

  async removePortMapping(remote, port) {
    const action = 'DeletePortMapping';

    const xml = await this.soapRequest(action, [
      ['NewRemoteHost', remote],
      ['NewExternalPort', port],
      ['NewProtocol', 'TCP']
    ]);

    const child = xml.find('DeletePortMappingResponse');

    if (!child)
      throw new Error('Port unmapping failed.');

    return child.text;
  }
}

/**
 * XML Element
 */

class XMLElement {
  /**
   * Create an XML element.
   * @constructor
   */

  constructor(name) {
    this.name = name;
    this.type = name.replace(/^[^:]:/, '');
    this.children = [];
    this.text = '';
  }

  /**
   * Insantiate element from raw XML.
   * @param {String} xml
   * @returns {XMLElement}
   */

  static fromRaw(xml) {
    const sentinel = new XMLElement('');
    const stack = [sentinel];

    let current = sentinel;
    let decl = false;

    while (xml.length > 0) {
      let m;

      m = /^<\?xml[^<>]*\?>/i.exec(xml);
      if (m) {
        xml = xml.substring(m[0].length);
        assert(current === sentinel, 'XML declaration inside element.');
        assert(!decl, 'XML declaration seen twice.');
        decl = true;
        continue;
      }

      m = /^<([\w:]+)[^<>]*?(\/?)>/i.exec(xml);
      if (m) {
        xml = xml.substring(m[0].length);

        const name = m[1];
        const trailing = m[2] === '/';
        const element = new XMLElement(name);

        if (trailing) {
          current.add(element);
          continue;
        }

        stack.push(element);
        current.add(element);
        current = element;

        continue;
      }

      m = /^<\/([\w:]+)[^<>]*>/i.exec(xml);
      if (m) {
        xml = xml.substring(m[0].length);

        const name = m[1];

        assert(stack.length !== 1, 'No start tag.');

        const element = stack.pop();

        assert(element.name === name, 'Tag mismatch.');
        current = stack[stack.length - 1];

        if (current === sentinel)
          break;

        continue;
      }

      m = /^([^<]+)/i.exec(xml);
      if (m) {
        xml = xml.substring(m[0].length);
        const text = m[1];
        current.text = text.trim();
        continue;
      }

      throw new Error('XML parse error.');
    }

    assert(sentinel.children.length > 0, 'No root element.');

    return sentinel.children[0];
  }

  /**
   * Push element onto children.
   * @param {XMLElement} child
   * @returns {Number}
   */

  add(child) {
    return this.children.push(child);
  }

  /**
   * Collect all descendants with matching name.
   * @param {String} name
   * @returns {XMLElement[]}
   */

  collect(name) {
    return this._collect(name, []);
  }

  /**
   * Collect all descendants with matching name.
   * @private
   * @param {String} name
   * @param {XMLElement[]} result
   * @returns {XMLElement[]}
   */

  _collect(name, result) {
    for (const child of this.children) {
      if (child.type === name) {
        result.push(child);
        continue;
      }

      child._collect(name, result);
    }

    return result;
  }

  /**
   * Find child element with matching name.
   * @param {String} name
   * @returns {XMLElement|null}
   */

  find(name) {
    for (const child of this.children) {
      if (child.type === name)
        return child;

      const desc = child.find(name);

      if (desc)
        return desc;
    }

    return null;
  }
}

/*
 * XML Helpers
 */

function parseServices(el) {
  const children = el.collect('service');
  const services = [];

  for (const child of children)
    services.push(parseService(child));

  return services;
}

function parseService(el) {
  const service = Object.create(null);

  for (const child of el.children) {
    if (child.children.length > 0)
      continue;

    service[child.type] = child.text;
  }

  return service;
}

function findService(services, name) {
  for (const service of services) {
    if (service.serviceType === name)
      return service;
  }

  return null;
}

function extractServices(services, targets) {
  for (const name of targets) {
    const service = findService(services, name);
    if (service)
      return service;
  }

  return null;
}

function findIP(el) {
  const child = el.find('NewExternalIPAddress');

  if (!child)
    return null;

  return IP.normalize(child.text);
}

function findError(el) {
  const child = el.find('UPnPError');

  if (!child)
    return null;

  let code = -1;
  const ccode = child.find('errorCode');

  if (ccode && /^\d+$/.test(ccode.text))
    code = parseInt(ccode.text, 10);

  let desc = 'Unknown';
  const cdesc = child.find('errorDescription');

  if (cdesc)
    desc = cdesc.text;

  return new Error(`UPnPError: ${desc} (${code}).`);
}

/*
 * Helpers
 */

function parseHost(uri) {
  const {protocol, host} = url.parse(uri);

  assert(protocol === 'http:' || protocol === 'https:',
    'Bad URL for location.');

  return `${protocol}//${host}`;
}

function prependHost(host, uri) {
  if (uri.indexOf('://') === -1) {
    if (uri[0] !== '/')
      uri = '/' + uri;
    uri = host + uri;
  }
  return uri;
}

/*
 * Expose
 */

module.exports = UPNP;
