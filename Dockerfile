FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
COPY src ./src
RUN npm ci --ignore-scripts --no-audit --no-fund && npm run build

FROM node:22-alpine
RUN apk add --no-cache git
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && chown -R node:node /app
COPY --from=builder --chown=node:node /app/dist ./dist
USER node
ENTRYPOINT ["node", "dist/cli.js", "--mcp"]
