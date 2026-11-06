FROM python:3.12-alpine
RUN adduser -D -u 10001 proxy
COPY proxy.py /app/proxy.py
USER proxy
EXPOSE 3128 9090
CMD ["python", "-u", "/app/proxy.py"]
