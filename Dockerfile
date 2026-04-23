FROM python:3.12-slim

LABEL maintainer="Humotica <info@humotica.com>"
LABEL description="SNAFT — Semantic Network-Aware Firewall for Trust. Zero-dependency behavioral firewall for AI agents."
LABEL org.opencontainers.image.source="https://github.com/Humotica/snaft"

RUN pip install --no-cache-dir snaft==1.2.0

ENTRYPOINT ["snaft"]
CMD ["status"]
