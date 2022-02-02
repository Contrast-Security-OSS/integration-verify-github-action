FROM alpine:3.15.0

RUN apk add --no-cache python3 py3-pip
ADD requirements.txt requirements.txt
RUN pip install -r requirements.txt

ADD output_helper.py output_helper.py
ADD verify.py verify.py

ENTRYPOINT ["/usr/bin/env", "python3", "/verify.py"]
