import { Module } from '@nestjs/common';
// import { LoggerModule } from './common/logger/logger.module';
import { PrismaModule } from './common/prisma/prisma.module';
import { AllExceptionFilter } from '@/core/filter/all-exception.filter';
import { HttpExceptionFilter } from '@/core/filter/http-exception.filter';
import { V1Module } from './api/index';
import { APP_FILTER } from '@nestjs/core';

export const NODE_ENV =
  process.env.NODE_ENV === 'production' ? 'production' : 'development';
export const isVercel = process.env.VERCEL === '1';

console.log('=========NODE_ENV==========', NODE_ENV);

@Module({
  // imports: [PrismaModule, LoggerModule, V1Module],
  imports: [PrismaModule, V1Module],
  providers: [
    // 执行顺序：从后往前！
    {
      provide: APP_FILTER,
      useClass: AllExceptionFilter,
    },
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
  ],
})
export class AppModule {}
