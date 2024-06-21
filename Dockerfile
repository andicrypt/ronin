# Build Geth in a stock Go builder container
FROM golang:1.20.10-alpine3.18@sha256:0d6e012ec44ed21993ee2ccf05839844f13347165ce7599a8e8442b02f836b45 as builder

RUN apk add --no-cache make gcc musl-dev linux-headers git libstdc++-dev

COPY . /opt
RUN cd /opt && make ronin

# Pull Geth into a second stage deploy alpine container
FROM alpine:3.18@sha256:48d9183eb12a05c99bcc0bf44a003607b8e941e1d4f41f9ad12bdcc4b5672f86

RUN apk add --no-cache ca-certificates
WORKDIR "/opt"

ENV PASSWORD ''
ENV PRIVATE_KEY ''
ENV BOOTNODES ''
ENV VERBOSITY 3
ENV SYNC_MODE 'snap'
ENV NETWORK_ID '2021'
ENV ETHSTATS_ENDPOINT ''
ENV NODEKEY ''
ENV FORCE_INIT 'true'
ENV RONIN_PARAMS ''
ENV INIT_FORCE_OVERRIDE_CHAIN_CONFIG 'false'
ENV ENABLE_FAST_FINALITY 'true'
ENV ENABLE_FAST_FINALITY_SIGN 'false'
ENV BLS_PRIVATE_KEY ''
ENV BLS_PASSWORD ''
ENV BLS_AUTO_GENERATE 'false'
ENV BLS_SHOW_PRIVATE_KEY 'false'
ENV GENERATE_BLS_PROOF 'false'
ENV SHADOW_FORK_CONFIG_PATH ''

COPY --from=builder /opt/build/bin/ronin /usr/local/bin/ronin
COPY --from=builder /opt/genesis/ ./
COPY --from=builder /opt/docker/chainnode/entrypoint.sh ./
COPY --from=builder /opt/core/state/shadow_switch/config/ ./

EXPOSE 7000 6060 8545 8546 30303 30303/udp

ENTRYPOINT ["./entrypoint.sh"]
