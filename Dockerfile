FROM ghcr.io/astral-sh/uv:python3.13-alpine@sha256:63b8fa4be2338728034164eb6c067a363fdbb3234fa79b64c83545317b7feec1

ENV VIRT_ENV=/opt/venv
RUN uv venv $VIRT_ENV --python 3.13
ENV PATH="$VIRT_ENV/bin:$PATH"

ADD requirements.txt requirements.txt
RUN uv pip install -r requirements.txt

ADD contrastverify contrastverify
ADD version.py version.py
ADD verify.py verify.py

ENTRYPOINT ["/usr/bin/env", "python3", "/verify.py"]
