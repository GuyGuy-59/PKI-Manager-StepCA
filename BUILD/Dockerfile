FROM python:slim-trixie
WORKDIR /app
RUN python3 -m pip install --no-cache-dir Flask psycopg2-binary cryptography requests python-jose uvicorn asgiref
EXPOSE 5000
CMD ["uvicorn", "asgi:app", "--workers", "4", "--host", "0.0.0.0", "--port", "5000", "--proxy-headers", "--forwarded-allow-ips=*"]