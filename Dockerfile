FROM python:2.7.14

ENV LUA_VERSION 5.1
ENV LUA_PACKAGE lua${LUA_VERSION}

RUN apk add --no-cache ${LUA_PACKAGE} ${LUA_PACKAGE}-dev luarocks${LUA_VERSION}

RUN ln -s /usr/bin/luarocks-${LUA_VERSION} /usr/bin/luarocks && \
  luarocks install busted && \
  luarocks install luacheck && \
  luarocks install luacov && \
  luarocks install luacov-console

RUN pip install -U \
  requests \
  xmlrunner

USER root

WORKDIR /aka8

ADD . /aka8
