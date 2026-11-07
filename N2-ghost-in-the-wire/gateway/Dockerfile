# N2 gateway reverse proxy (nginx)
# Optional: only needed if the shared VVV gateway is not already fronting N2.
FROM nginx:1.27-alpine

COPY gateway/nginx.conf /etc/nginx/conf.d/default.conf

# Drop the default site config shipped with the image so ours is authoritative.
RUN rm -f /etc/nginx/conf.d/default.conf.bak
