FROM python:2.7.14

User root


#=========================================
# Install robotframework and library
#=========================================
RUN pip install -U \
    xmlrunner \
    requests

WORKDIR /aka8
ADD . /aka8

