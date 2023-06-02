FROM node:16

WORKDIR /user/src/app

COPY package*.json ./

RUN npm install

COPY app.js ./
COPY rsa_private.pem ./

EXPOSE 3000
CMD [ "node", "app.js" ]