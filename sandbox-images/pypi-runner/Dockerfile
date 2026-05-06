FROM python:3.12-slim
RUN useradd --create-home --uid 10001 sandbox
USER sandbox
WORKDIR /sandbox
ENTRYPOINT ["python", "--version"]