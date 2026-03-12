# Step 1: Build stage
FROM node:18-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

# Step 2: Runtime stage
FROM node:18-slim
WORKDIR /app
COPY --from=builder /app .

EXPOSE 3001

# Change this to your actual start command (e.g., node index.js)
CMD ["npm", "start"]