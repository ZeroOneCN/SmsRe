# 运行镜像：Node 22 自带 node:sqlite，无需任何原生编译依赖
FROM node:22-alpine

WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY public ./public

RUN mkdir -p /app/data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:8080/healthz > /dev/null || exit 1

CMD ["node", "--no-warnings", "src/server.js"]
