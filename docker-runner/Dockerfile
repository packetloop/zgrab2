FROM zgrab2_runner_base:latest

RUN go get github.com/buger/jsonparser

WORKDIR /go/src/github.com/packetloop

# Grab the currently-active version of the source
ADD . zgrab2

# This would instead grab it from the source repo
# RUN go-wrapper download github.com/packetloop/zgrab2

WORKDIR /go/src/github.com/packetloop/zgrab2

RUN go get -f -u -v .
RUN go get -f -u -v -t .
RUN go get -f -u -v $(find ./modules -type d)
RUN go get -f -u -v -t $(find ./modules -type d)

# This should already be executable, but just in case...
RUN chmod a+x ./docker-runner/entrypoint.sh

# Build on the container
RUN make container-clean

CMD []
ENTRYPOINT ["/go/src/github.com/packetloop/zgrab2/docker-runner/entrypoint.sh"]
