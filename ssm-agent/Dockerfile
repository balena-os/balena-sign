# https://gist.github.com/ipmb/a8213fb459c27178f88dda7149c35be2
# https://github.com/aws/amazon-ssm-agent/issues/140
FROM golang:1.26-alpine3.23@sha256:6750308561953d451210ed1a8086d36c8c8bdcbf672d38d9d0d424b8a7a0216c as builder

ARG VERSION=3.2.419.0

RUN set -ex && apk add --no-cache \
    bash \
    curl \
    gcc \
    git \
    libc-dev \
    make && \
    curl -sLO https://github.com/aws/amazon-ssm-agent/archive/${VERSION}.tar.gz && \
    mkdir -p /go/src/github.com && \
    tar xzf ${VERSION}.tar.gz && \
    mv amazon-ssm-agent-${VERSION} /go/src/github.com/amazon-ssm-agent && \
    cd /go/src/github.com/amazon-ssm-agent && \
    echo ${VERSION} > VERSION && \
    go install golang.org/x/tools/cmd/goimports@latest && \
    gofmt -w -s . && make checkstyle && \
    make build-linux


# -- runtime
FROM alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN set -ex && apk add --no-cache sudo ca-certificates && \
    adduser -D ssm-user && echo "ssm-user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ssm-agent-users && \
    mkdir -p /etc/amazon/ssm

COPY --from=builder /go/src/github.com/amazon-ssm-agent/bin/linux_amd64/ /usr/bin
COPY --from=builder /go/src/github.com/amazon-ssm-agent/bin/amazon-ssm-agent.json.template /etc/amazon/ssm/amazon-ssm-agent.json
COPY --from=builder /go/src/github.com/amazon-ssm-agent/bin/seelog_unix.xml /etc/amazon/ssm/seelog.xml

RUN apk add --no-cache \
    curl \
    dbus \
    docker-cli \
    jq \
    wget

CMD ["/usr/bin/amazon-ssm-agent"]
