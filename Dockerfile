# Step 1: Build stage
FROM node:18-slim AS builder
WORKDIR /app
COPY package*.json ./
# This installs your dependencies (including express)
RUN npm install
COPY . .

# Step 2: Runtime stage
FROM node:18-slim
WORKDIR /app
# CRITICAL: This copies EVERYTHING (including node_modules) from the builder
COPY --from=builder /app .

EXPOSE 8080
CMD ["npm", "start"]