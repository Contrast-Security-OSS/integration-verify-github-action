FROM alpine:3.14

RUN apk add --no-cache bash curl jq
WORKDIR /opt/contrastverify
ADD verify.sh verify.sh

ENTRYPOINT ["/bin/bash", "verify.sh"]