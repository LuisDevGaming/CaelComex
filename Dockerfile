# Imagen de producción de Cael Comex
FROM node:24-alpine

ENV NODE_ENV=production \
    PORT=3000 \
    DATA_DIR=/data

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY server.js ./
COPY src ./src
COPY public ./public
COPY admin ./admin
COPY scripts ./scripts

# /data debe montarse como volumen persistente (base de datos, imágenes y respaldos)
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]
USER node

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD wget -qO- http://127.0.0.1:${PORT}/healthz || exit 1
CMD ["node", "server.js"]
