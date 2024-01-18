# FROM python:3.11-alpine
FROM alpine:latest

#Set The ENV commands if you need to specify a proxy
#ENV HTTP-PROXY=--
#ENV HTTPS-PROXY=--

# Install Python and Python modules
RUN apk --update add python3 py3-pip py3-virtualenv py3-yaml
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev
COPY src/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Copy the connector
COPY src /opt/connector
WORKDIR /opt/connector

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
