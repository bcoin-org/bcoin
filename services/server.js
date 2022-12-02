'use strict';

const Api = require('./api/index');


class Server {
  constructor() {
  }

  async start() {
    try {
      await this.openApi();
    } catch (error) {
      console.error(error);
    }
  }  

  async openApi() {
    this.api = new Api({      
    });

    this.api.setting();
    this.api.start();
    this.api.on('data', result => {
        console.log(result);
    });
  }
}

module.exports = Server;
