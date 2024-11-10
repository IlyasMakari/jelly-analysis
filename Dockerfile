FROM node:22.4.1-alpine

RUN apk update && apk add bind-tools bash python3 git

ADD . /code 
VOLUME /code/code


ENTRYPOINT /code/config/wrap.sh
