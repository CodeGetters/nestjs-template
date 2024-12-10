import { Controller, Get } from '@nestjs/common';

@Controller('demo')
export class DemoController {
  @Get()
  getHello(): string {
    return 'Hello World';
  }
}
