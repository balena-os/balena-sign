# https://gist.github.com/ipmb/a8213fb459c27178f88dda7149c35be2
# https://github.com/aws/amazon-ssm-agent/issues/140
FROM golang:1.26-alpine3.23@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d as builder

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
FROM alpine@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

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
