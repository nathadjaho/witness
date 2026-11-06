# Deliberately hostile pages used by the attack lab. Served only on the
# egress network; sandboxes reach it through the proxy like any other site.
FROM python:3.12-alpine
RUN adduser -D -u 10002 web
COPY . /srv
USER web
WORKDIR /srv
EXPOSE 8080
CMD ["python", "-m", "http.server", "8080", "--bind", "0.0.0.0"]
