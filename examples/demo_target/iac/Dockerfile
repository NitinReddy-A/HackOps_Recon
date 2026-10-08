# Intentionally-insecure Dockerfile fixture for Rampart's IaC scanner tests.
# DO NOT build/deploy. Every instruction here is a deliberate misconfiguration.
FROM ubuntu:latest

RUN apt-get update && apt-get install -y curl

# remote script piped straight into a shell (no integrity check)
RUN curl -fsSL https://example.com/install.sh | sh

# remote fetch over ADD
ADD https://example.com/app.tar.gz /opt/app/

# no USER instruction -> container runs as root
CMD ["/opt/app/run"]
