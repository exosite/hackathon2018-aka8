FROM python:2-alpine

RUN apk update && apk add --no-cache build-base curl lua5.1 lua5.1-dev luarocks5.1
RUN pip install requests xmlrunner
RUN ln -s /usr/bin/luarocks-5.1 /usr/bin/luarocks
RUN luarocks install busted
RUN luarocks install luacheck
RUN luarocks install luacov-console
RUN luarocks install luacov

WORKDIR /aka8

ADD . /aka8
