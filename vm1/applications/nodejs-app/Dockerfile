FROM node:18-alpine
WORKDIR /app
COPY . .
RUN npm install --omit=dev
EXPOSE 3000
CMD ["node", "app.js"]
