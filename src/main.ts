import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Reflector } from '@nestjs/core';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { TransformInterceptor } from '@/core/interceptor/transform.interceptor';
import { TimeoutInterceptor } from '@/core/interceptor/timeout.interceptor';

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
  );

  app.setGlobalPrefix('api');

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
    }),
  );

  const config = new DocumentBuilder()
    .setTitle('接口文档')
    .setVersion('1.0')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document, {
    jsonDocumentUrl: 'docs/json',
  });

  // 序列化返回内容
  app.useGlobalInterceptors(new TransformInterceptor(new Reflector()));

  // 响应时间超过3s为超时错误
  app.useGlobalInterceptors(new TimeoutInterceptor(60 * 1000));

  await app.listen(8080, '0.0.0.0');
  console.log(`Server is running on: ${await app.getUrl()}`);
  console.log(`Docs is running on: ${await app.getUrl()}/docs`);
  console.log(`Demo API is running on: ${await app.getUrl()}/api/v1/demo`);
}

bootstrap();
