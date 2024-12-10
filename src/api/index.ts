import { Module } from '@nestjs/common';
import { RouterModule } from '@nestjs/core';
import { DemoModule } from './demo/demo.module';

@Module({
  imports: [
    DemoModule,
    RouterModule.register([
      {
        path: 'v1',
        children: [{ path: 'demo', module: DemoModule }],
      },
    ]),
  ],
})
export class V1Module {}
