# Dependabot-managed canonical Envoy pin; Makefile consumers derive it from here.
FROM envoyproxy/envoy:v1.40.0@sha256:459f2a6404c340fe6afccd69d85527012d47f3c036765493e6f8f3113fa384de

ARG DYNAMIC_MODULE_SOURCE=target/release/libenvoy_coraza_dynamic.so

ENV ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/opt/envoy/modules

RUN install -d -o root -g root -m 0555 /opt/envoy/modules
COPY --chown=0:0 --chmod=0444 ${DYNAMIC_MODULE_SOURCE} /opt/envoy/modules/libenvoy_coraza_dynamic.so
