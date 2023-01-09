FROM alpine:3.17.1

RUN apk add --no-cache python3 py3-pip
ADD requirements.txt requirements.txt
RUN pip install -r requirements.txt

ADD contrastverify contrastverify
ADD version.py version.py
ADD verify.py verify.py

ENTRYPOINT ["/usr/bin/env", "python3", "/verify.py"]
