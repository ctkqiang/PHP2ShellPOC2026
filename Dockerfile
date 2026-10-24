# syntax=docker/dockerfile:1
FROM ruby:3.4-alpine

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY . /app

RUN gem build php2shell_poc2026.gemspec \
    && gem install --local php2shell_poc2026-*.gem \
    && rm -f php2shell_poc2026-*.gem

# Run as an unprivileged user. The tool only needs outbound HTTP(S).
RUN addgroup -S scanner && adduser -S -G scanner scanner
USER scanner

ENTRYPOINT ["php2shell-poc2026"]
CMD ["--help"]
