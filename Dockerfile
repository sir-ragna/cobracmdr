FROM alpine:3.10 
#           ^ Update this tag

WORKDIR /app
COPY goneypot /app/

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN chown -R appuser:appgroup /app

USER appuser
EXPOSE 2222
CMD ["./goneypot", "-console"]
