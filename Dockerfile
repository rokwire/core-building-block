FROM golang:1.22-alpine as builder

ENV CGO_ENABLED=0

RUN apk add --no-cache --update make git

RUN mkdir /app
WORKDIR /app
# Copy the source from the current directory to the Working Directory inside the container
COPY . .
RUN make

FROM alpine:3.17.3

#we need timezone database
RUN apk add --no-cache --update tzdata

COPY --from=builder /app/bin/core-building-block /

COPY --from=builder /app/driver/web/ui/reset-credential.html /driver/web/ui/reset-credential.html
COPY --from=builder /app/driver/web/ui/error.html /driver/web/ui/error.html
COPY --from=builder /app/driver/web/ui/success.html /driver/web/ui/success.html
COPY --from=builder /app/driver/web/docs/gen/def.yaml /driver/web/docs/gen/def.yaml

COPY --from=builder /app/driver/web/authorization_model.conf /driver/web/authorization_model.conf

COPY --from=builder /app/driver/web/authorization_services_policy.csv /driver/web/authorization_services_policy.csv
COPY --from=builder /app/driver/web/authorization_admin_policy.csv /driver/web/authorization_admin_policy.csv
COPY --from=builder /app/driver/web/authorization_enc_policy.csv /driver/web/authorization_enc_policy.csv
COPY --from=builder /app/driver/web/authorization_bbs_policy.csv /driver/web/authorization_bbs_policy.csv
COPY --from=builder /app/driver/web/authorization_tps_policy.csv /driver/web/authorization_tps_policy.csv
COPY --from=builder /app/driver/web/authorization_system_policy.csv /driver/web/authorization_system_policy.csv

COPY --from=builder /app/driver/web/scope_authorization_services_policy.csv /driver/web/scope_authorization_services_policy.csv

COPY --from=builder /app/vendor/github.com/rokwire/core-auth-library-go/v3/authorization/authorization_model_scope.conf /app/vendor/github.com/rokwire/core-auth-library-go/v3/authorization/authorization_model_scope.conf
COPY --from=builder /app/vendor/github.com/rokwire/core-auth-library-go/v3/authorization/authorization_model_string.conf /app/vendor/github.com/rokwire/core-auth-library-go/v3/authorization/authorization_model_string.conf

COPY --from=builder /etc/passwd /etc/passwd

ENTRYPOINT ["/core-building-block"]
