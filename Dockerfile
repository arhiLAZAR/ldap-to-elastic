FROM python:3

ENV LC_ALL C.UTF-8
ENV DEBIAN_FRONTEND noninteractive

COPY ldap_to_elastic.py /app/ldap_to_elastic.py
COPY ca.crt /app/ca.crt

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      python3-dev \
      python2.7-dev \
      libldap2-dev \
      libsasl2-dev \
      ldap-utils \
      tox \
      lcov \
      valgrind \
      slapd && \
    python -m pip install --no-cache-dir \
      python-ldap \
      requests

WORKDIR /app

ENTRYPOINT [ "/app/ldap_to_elastic.py" ]
