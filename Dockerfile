FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates python3 python3-venv python3-tk tshark \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv

WORKDIR /opt/sparc
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN python -m pip install --no-cache-dir '.[analysis,traffic]'

ARG SPARC_UID=1000
ARG SPARC_GID=1000
RUN groupadd --gid "${SPARC_GID}" sparc \
    && useradd --uid "${SPARC_UID}" --gid sparc --create-home sparc \
    && install -d -m 0700 -o sparc -g sparc /data

USER sparc
CMD ["python", "-m", "sparc", "--data-dir", "/data/peer"]

