# Step 1: Build stage
FROM node:18-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

# Step 2: Runtime stage
FROM node:18-slim
WORKDIR /app
# Copies EVERYTHING (including node_modules) from the builder
COPY --from=builder /app .

# CHANGE: Match this to your app's actual port (8080)
EXPOSE 8080

CMD ["npm", "start"]