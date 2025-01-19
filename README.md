# NestJS Template

[中文版](README.md) | [English Version](README-EN.md)

一个功能完整的 NestJS 后端项目模板，集成了常用功能和最佳实践。

## 特性

- 🚀 基于 Fastify 的高性能 HTTP 服务器
- 📝 集成 Swagger 文档（OpenAPI）
- 🔒 全局异常处理和统一响应格式
- 📊 Winston 日志系统（按日期轮转）
- 💾 Prisma ORM 集成
- ⚡️ 请求超时处理
- ✨ 统一的响应数据转换

## 项目结构

```
src/
├── api/                # API 模块目录
│   ├── demo/          # 示例模块
│   └── index.ts       # API 路由注册
├── common/            # 公共模块
│   ├── logger/        # 日志模块
│   └── prisma/        # Prisma 数据库模块
├── core/              # 核心功能模块
│   ├── decorator/     # 自定义装饰器
│   ├── filter/        # 异常过滤器
│   ├── guard/         # 守卫
│   └── interceptor/   # 拦截器
└── main.ts            # 应用入口文件
```

## 快速开始

### 环境要求

- Node.js >= 16
- pnpm >= 8

### 安装依赖

```bash
pnpm install
```

### 配置环境变量

```bash
cp .env.example .env
```

### 数据库连接

将位于 `src/common/prisma/prisma.service.ts:51` 行代码取消注释，并设置数据库连接

### 启动项目

```bash
# dev
pnpm run start:dev

# prod
pnpm run start:prod

# build
pnpm run build
```

### 访问文档

```bash
http://localhost:8080/docs
```

## 主要功能说明

### 统一响应格式

成功响应格式

```json
{
  "code": "SUCCESS",
  "data": {},
  "message": "请求成功",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

错误响应格式

```json
{
  "code": "ERROR_CODE",
  "message": "错误信息",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "path": "/api/xxx"
}
```

### 日志系统

- 自动按日期分割日志文件
- 区分 error 和 combined 日志
- 开发环境下同时输出到控制台
- 日志文件保存在 logs 目录

### 异常处理

- 全局异常过滤器处理所有未捕获的异常
- HTTP 异常过滤器处理标准的 HTTP 异常
- Prisma 数据库异常统一处理

### 请求超时处理

默认 60 秒超时限制，可通过 TimeoutInterceptor 配置

## 开发指南

### 添加新模块

1. 在 `src/api` 目录下创建新模块目录，例如 `user`
2. 在 `src/api/user/user.service.ts` 中定义服务
3. 在 `src/api/user/user.controller.ts` 中定义控制器
4. 在 `src/api/user/user.module.ts` 中定义模块
5. 在 `src/api/index.ts` 中注册新模块

### 使用自定义响应格式

使用 `@SkipTransform()` 装饰器可以跳过统一响应格式转换：

```typescript
@Get()
@SkipTransform()
getData() {
  return { raw: 'data' };
}
```

## 贡献指南

欢迎提交 Issue 和 Pull Request

## 许可证

MIT

```json
  "builds": [
    {
      "src": "dist/main.js",
      "use": "@vercel/node"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "dist/main.js",
      "methods": ["GET", "POST", "PUT", "DELETE"]
    }
  ],
```
