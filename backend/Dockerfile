FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
RUN addgroup -S app && adduser -S app -G app && chown -R app:app /app
USER app
EXPOSE 5000
HEALTHCHECK --interval=20s --timeout=5s CMD wget -qO- http://localhost:5000/health || exit 1
CMD ["node", "server.js"]
