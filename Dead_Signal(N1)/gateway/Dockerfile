FROM nginx:1.27-alpine

RUN apk add --no-cache openssl \
    && openssl req -x509 -nodes -days 365 \
      -newkey rsa:2048 \
      -keyout /etc/nginx/server.key \
      -out /etc/nginx/server.crt \
      -subj "/C=IN/ST=Karnataka/L=Dharwad/O=Meridian Systems/CN=portal.meridian.local"

COPY nginx.conf /etc/nginx/nginx.conf
COPY web/ /usr/share/nginx/html/
COPY artifacts/ /usr/share/nginx/html/backup/

EXPOSE 80 443
