FROM alpine:3.20.3

RUN apk add --no-cache python3 py3-pip py3-cryptography
ADD requirements.txt requirements.txt
RUN pip install -r requirements.txt

ADD contrastverify contrastverify
ADD version.py version.py
ADD verify.py verify.py

ENTRYPOINT ["/usr/bin/env", "python3", "/verify.py"]
