FROM alpine:3.14

RUN apk add --no-cache python3 py3-pip
ADD requirements.txt requirements.txt
RUN pip install -r requirements.txt
ADD verify.py verify.py

ENTRYPOINT ["/usr/bin/env", "python3", "/verify.py"]
