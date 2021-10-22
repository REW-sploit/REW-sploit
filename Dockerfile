#
# To Build:
#       sudo docker build -t rew-sploit/rew-sploit .
#
# To Run:
#       sudo docker run --rm -it --name rew-sploit -v /tmp:/tmp rew-sploit/rew-sploit
#
FROM python:3.9-slim AS builder
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app
COPY requirements.txt .
RUN apt-get update -y && \
    apt-get install -y cpp gcc swig libssl-dev libpcap0.8-dev && \
    python -m venv .venv && \
    .venv/bin/pip install --no-cache-dir -r requirements.txt && \
    find .venv \( -type d -a -name test -o -name tests -o -name __pycache__ \) -o \( -type f -a -name '*.pyc' -o -name '*.pyo' \) -exec rm {} \;

FROM python:3.9-slim
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app
COPY --from=builder /app .
COPY . /app
RUN apt-get update -y && \
    apt-get install -y yara tcpdump && \
    ./.venv/bin/python apply_patch.py -f && \
    ln -s /usr/local/lib/python3.9/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so && \
    apt-get autoremove -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
CMD [ "/app/.venv/bin/python", "rew-sploit.py"]