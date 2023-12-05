FROM golang:latest as builder

WORKDIR /go/src/cobracmdr
COPY go.mod go.sum /go/src/cobracmdr/
COPY main.go /go/src/cobracmdr/
# https://www.callicoder.com/docker-golang-image-container-example/

RUN go get
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# We start a new container
FROM scratch
# Minimal go containers starting from scratch
# https://rollout.io/blog/building-minimal-docker-containers-for-go-applications/

COPY --from=builder /go/src/cobracmdr/main .

EXPOSE 2222
CMD ["/main", "-console"]
