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
RUN addgroup -S amass_group && adduser -S -g amass_group amass_user

USER amass_user

ARG COMMIT_ID=unkown
ARG REPOSITORY_URL=unkown
ARG BRANCH=unkown

ENV SCB_COMMIT_ID ${COMMIT_ID}
ENV SCB_REPOSITORY_URL ${REPOSITORY_URL}
ENV SCB_BRANCH ${BRANCH}

EXPOSE 8080

CMD /securecodebox/main