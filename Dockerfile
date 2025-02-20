FROM alpine:3.18

ARG VERSION
ARG COMMIT=""
RUN echo -e "VERSION=$VERSION\nCOMMIT=$COMMIT" > /version.env

COPY requirements.txt /tmp/requirements.txt

RUN apk update \
 && apk add --no-cache python3 py3-pip \
 && apk add --no-cache --virtual build-deps gcc g++ python3-dev musl-dev pkgconfig \
 && apk add --no-cache curl postgresql postgresql-dev mariadb-dev sqlite-dev \
 && pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir --upgrade uvicorn \
 && pip install --no-cache-dir psycopg2==2.9.10 mysqlclient==2.2.7 pysqlite3==0.5.4 \
 && pip install --no-cache-dir -r /tmp/requirements.txt \
 && apk del build-deps

COPY app /app
COPY README.md /README.md

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "443", "--app-dir", "/app", "--proxy-headers", "--ssl-keyfile", "/app/cert/key.pem", "--ssl-certfile", "/app/cert/cert.pem"]
