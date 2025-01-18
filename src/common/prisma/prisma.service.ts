import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { LoggerService } from '@/common/logger/logger.service';

/**
 * Prisma 服务类
 * 用于管理数据库连接和日志记录
 * 继承自 PrismaClient 并实现了 OnModuleInit 和 OnModuleDestroy 接口
 */
@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor(private logger: LoggerService) {
    super({
      log: [
        { emit: 'event', level: 'query' },
        { emit: 'event', level: 'info' },
        { emit: 'event', level: 'warn' },
        { emit: 'event', level: 'error' },
      ],
    });

    // 使用 any 类型断言来处理事件监听
    (this as any).$on('query', (e: any) => {
      this.logger.debug(`Query: ${e.query}`, 'PrismaService');
    });

    (this as any).$on('info', (e: any) => {
      this.logger.log(`${e.message}`, 'PrismaService');
    });

    (this as any).$on('warn', (e: any) => {
      this.logger.warn(`${e.message}`, 'PrismaService');
    });

    (this as any).$on('error', (e: any) => {
      this.logger.error(`${e.message}`, null, 'PrismaService');
    });
  }

  /**
   * 模块初始化时连接数据库
   */
  async onModuleInit() {
    console.group('this must be cancelled');
    // await this.$connect();
    // console.log('database url must be set in .env file');
    this.logger.log('Database connected successfully', 'PrismaService');
  }

  /**
   * 模块销毁时断开数据库连接
   */
  async onModuleDestroy() {
    // await this.$disconnect();
    await (this as any).$disconnect();
    this.logger.log('Database disconnected successfully', 'PrismaService');
  }
}
