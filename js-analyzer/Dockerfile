FROM node:20-alpine

WORKDIR /app

COPY js-analyzer/package.json .
RUN npm install

COPY js-analyzer . .

EXPOSE 5001

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:5001/health', (r) => {if (r.statusCode !== 200) throw new Error(r.statusCode)})"

CMD ["npm", "start"]
