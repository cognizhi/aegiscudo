FROM node:22-alpine
RUN adduser -D -u 10001 sandbox
USER sandbox
WORKDIR /sandbox
ENTRYPOINT ["node", "--version"]