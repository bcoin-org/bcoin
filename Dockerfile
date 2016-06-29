FROM alpine:edge
MAINTAINER Steven Bower <steven@purse.io>

RUN apk update && \
    apk upgrade
RUN apk add nodejs bash unrar git python build-base make

RUN mkdir /code /data
ADD . /code
WORKDIR /code

RUN npm install --production
RUN npm uninstall node-gyp

RUN apk del unrar git python build-base make && \
    rm /var/cache/apk/*

CMD ["node", "/code/bin/node"]
