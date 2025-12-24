FROM node:22-alpine
WORKDIR /app

# Point to root package files
COPY ../package*.json ./
RUN npm install

COPY . .

EXPOSE 5000

# AUTOMATION: Seed data first, then start server
CMD ["sh", "-c", "npm run data:import && npm start"]