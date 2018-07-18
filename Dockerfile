FROM golang AS builder
WORKDIR /usr/local/go/src/github.com/j12934/secureCodeBox/
COPY . .

RUN go get

# Otherwise binaries would link to libaries which dont exist on alpine.
# See: https://stackoverflow.com/questions/36279253/go-compiled-binary-wont-run-in-an-alpine-docker-container-on-ubuntu-host
ENV CGO_ENABLED 0

RUN go build main.go

FROM alpine
COPY --from=builder /usr/local/go/src/github.com/j12934/secureCodeBox/main /securecodebox/
RUN chmod +x /securecodebox/main

CMD /securecodebox/main