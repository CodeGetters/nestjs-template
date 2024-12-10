# NestJS Template

[中文版](README.md) | [English Version](README-EN.md)

A full-featured NestJS backend project template with common functionalities and best practices.

## Features

- 🚀 High-performance HTTP server based on Fastify
- 📝 Integrated Swagger documentation (OpenAPI)
- 🔒 Global exception handling and unified response format
- 📊 Winston logging system (with daily rotation)
- 💾 Prisma ORM integration
- ⚡️ Request timeout handling
- ✨ Unified response transformation

## Project Structure

```
src/
├── api/           # API modules directory
│ ├── demo/        # Example module
│ └── index.ts     # API route registration
├── common/        # Common modules
│ ├── logger/      # Logging module
│ └── prisma/      # Prisma database module
├── core/          # Core functionality
│ ├── decorator/   # Custom decorators
│ ├── filter/      # Exception filters
│ ├── guard/       # Guards
│ └── interceptor/ # Interceptors
└── main.ts        # Application entry point
```

## Quick Start

### Requirements

- Node.js >= 16
- pnpm >= 8

### Install Dependencies

```bash
pnpm install
```

### Configure Environment Variables

```bash
cp .env.example .env
```

### Database Connection

Uncomment the code at `src/common/prisma/prisma.service.ts:51` and set up the database connection

### Start the Project

```bash
# dev
pnpm run start:dev

# prod
pnpm run start:prod

# build
pnpm run build
```

### Access Documentation

```bash
http://localhost:8080/docs
```

## Main Features

### Unified Response Format

Success response format

```json
{
  "code": "SUCCESS",
  "data": {},
  "message": "Request successful",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

Error response format

```json
{
  "code": "ERROR_CODE",
  "message": "Error message",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "path": "/api/xxx"
}
```

### Logging System

- Automatic daily log file rotation
- Separate error and combined logs
- Console output in development environment
- Log files stored in logs directory

### Exception Handling

- Global exception filter for all uncaught exceptions
- HTTP exception filter for standard HTTP exceptions
- Unified handling of Prisma database exceptions

### Request Timeout Handling

Default 60-second timeout limit, configurable via TimeoutInterceptor

## Development Guide

### Adding New Modules

1. Create a new module directory in `src/api`, e.g., `user`
2. Define service in `src/api/user/user.service.ts`
3. Define controller in `src/api/user/user.controller.ts`
4. Define module in `src/api/user/user.module.ts`
5. Register new module in `src/api/index.ts`

### Using Custom Response Format

Use `@SkipTransform()` decorator to skip unified response transformation:

```typescript
@Get()
@SkipTransform()
getData() {
  return { raw: 'data' };
}
```

## Contributing

Issues and Pull Requests are welcome

## License

MIT
