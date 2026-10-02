FROM alpine:3.21

RUN apk add --no-cache curl

CMD ["sh", "-c", "echo 'Docker security scan test image'"]
