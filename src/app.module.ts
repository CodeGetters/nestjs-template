import { Module } from '@nestjs/common';
import { DemoModule } from './common/demo/demo.module';

const NODE_ENV =
  process.env.NODE_ENV === 'production' ? 'production' : 'development';

// console.log('=========NODE_ENV==========', NODE_ENV);

@Module({
  imports: [DemoModule],
})
export class AppModule {}
