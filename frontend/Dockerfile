# Stage 1: Build Vite React App
FROM node:20-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci || npm install

COPY . .
RUN npm run build

# Stage 2: Serve via Nginx
FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

ENV PORT=80 \
    API_GATEWAY_URL=http://express-api:5000

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
