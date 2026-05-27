# Copyright (c) 2026, Oracle OCI Certbot contributors
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl/
# SPDX-License-Identifier: UPL-1.0

FROM fnproject/python:3.11-dev AS build-stage

WORKDIR /function
ADD requirements.txt /function/
RUN pip3 install --target /python --no-cache-dir -r requirements.txt

ADD . /function/
RUN chmod +x /function/hooks/*.py

FROM fnproject/python:3.11

WORKDIR /function
COPY --from=build-stage /function /function
COPY --from=build-stage /python /python

ENV PATH=/python/bin:$PATH
ENV PYTHONPATH=/function:/python

ENTRYPOINT ["/python/bin/fdk", "/function/func.py", "handler"]
