FROM node:latest

ENV NPM_TOKEN=npm_iH8xK2mQ4pL9vR3tY7wZ1nB5cD0eF6gA8jS2

RUN curl -sL https://example.com/install.sh | sh

COPY . /app
WORKDIR /app
CMD ["node", "server.js"]
