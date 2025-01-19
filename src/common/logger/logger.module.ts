import { Global, Module, DynamicModule } from '@nestjs/common';
import { LoggerService, NoopLoggerService } from './logger.service';
import { isVercel } from '@/app.module';

@Global()
@Module({})
export class LoggerModule {
  static forRoot(): DynamicModule {
    return {
      module: LoggerModule,
      providers: [
        {
          provide: LoggerService,
          useClass: isVercel ? NoopLoggerService : LoggerService,
        },
      ],
      exports: [LoggerService],
    };
  }
}
