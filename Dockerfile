FROM python:3.6.9

RUN apt update -y
RUN apt install vim less jq -y

COPY requirements.txt /requirements.txt
COPY src /src
COPY conf /conf

RUN python3 -m pip install virtualenv
RUN virtualenv scapyenv
RUN . scapyenv/bin/activate && python3 -m pip install -r requirements.txt && deactivate
