FROM golang:latest as builder

WORKDIR /go/src/cobracmdr
COPY main.go /go/src/cobracmdr/
# https://www.callicoder.com/docker-golang-image-container-example/

RUN go get
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# We start a new container
FROM alpine:3.10 

#RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /go/src/cobracmdr/main .

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN chown -R appuser:appgroup /app

USER appuser
EXPOSE 2222
CMD ["./main", "-console"]
