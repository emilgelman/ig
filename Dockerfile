ARG BASE_IMAGE=alpine:3.17
FROM ${BASE_IMAGE} AS final-stage

WORKDIR /
COPY ig .
COPY entrypoint.sh .
# used for liveness probe (can't override in helm)
COPY gadgettracermanager /bin/gadgettracermanager
# can't override in helm
RUN chmod u+x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]