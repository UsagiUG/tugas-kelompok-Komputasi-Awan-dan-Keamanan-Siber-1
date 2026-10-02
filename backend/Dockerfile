# Image for the telemetry API. The build context is this backend folder:
#   cd backend
#   docker build -t telemetry-api .
#   docker run --rm -p 8080:8080 -v "${PWD}/certs:/app/certs:ro" telemetry-api
# Private keys are never baked into the image: mount them (as above) or pass
# RSA_PRIVATE_KEY_PEM / ECC_PRIVATE_KEY_PEM as environment variables.

# ---- stage 1: install production dependencies ----
FROM node:24-slim AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

# ---- stage 2: runtime image ----
FROM node:24-slim
ENV NODE_ENV=production PORT=8080
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --chown=node:node package.json server.js ./
COPY --chown=node:node src ./src
# data/ must be writable: model.js creates main.db (nonce table) here
COPY --chown=node:node data ./data

# run as the unprivileged "node" user that ships with the base image
USER node
EXPOSE 8080

# healthy = server answers /public-key (fails if the private keys did not load)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 8080) + '/public-key').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

# node:sqlite needs no flag on Node 22.13+ / 24
CMD ["node", "server.js"]
