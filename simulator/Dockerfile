FROM node:8
RUN apt-get update

ENV DOCKER true
ENV SOLUTION i1747z43gjbc00000.m2.preview.exosite-staging.io
ENV CERT_PATH ./csr/trusted.csr
ENV CREDENTIAL_PATH ./data/credential.csv
ENV PASSWORD ThisIsCorrectPassword
ENV ENV START_INDEX 0
ENV END_INDEX 5000
ENV DEVICE_DELAY 100
ENV DEVICE_PERIOD 1000

WORKDIR /app

COPY package.json /app/package.json

RUN npm install

COPY . /app

RUN chmod -R 777 /app

CMD ["npm", "start"]