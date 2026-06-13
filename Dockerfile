FROM node:20-alpine

WORKDIR /app

COPY package.json .
RUN npm install --production

COPY proxy-server.js .
COPY public/ public/

EXPOSE 8080 8088 9090

VOLUME [ "/app/data" ]

CMD ["node", "proxy-server.js"]
