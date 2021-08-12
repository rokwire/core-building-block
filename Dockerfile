FROM golang:1.16-buster as builder

ENV CGO_ENABLED=0

RUN mkdir /core-app
WORKDIR /core-app
# Copy the source from the current directory to the Working Directory inside the container
COPY . .
RUN make

FROM alpine:3.11.6

#we need timezone database
RUN apk --no-cache add tzdata

COPY --from=builder /core-app/bin/core-building-block /
COPY --from=builder /core-app/driver/web/docs/gen/def.yaml /driver/web/docs/gen/def.yaml

COPY --from=builder /core-app/driver/web/authorization_model.conf /driver/web/authorization_model.conf
COPY --from=builder /core-app/driver/web/authorization_policy.csv /driver/web/authorization_policy.csv

COPY --from=builder /etc/passwd /etc/passwd

#we need timezone database
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo 

ENV ENV_TYPE=aws_secrets_manager

EXPOSE 80
ENTRYPOINT ["/core-building-block"]