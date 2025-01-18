import { Controller, Get, Post, Query, Body } from '@nestjs/common';
import { DemoService } from './demo.service';
import { SkipTransform } from '@/core/decorator/skip-transform.decorator';

@Controller()
export class DemoController {
  constructor(private demoService: DemoService) {}

  @Get()
  getHello() {
    return this.demoService.getHello();
  }

  @Post()
  postHello() {
    return this.demoService.postHello();
  }

  @Get('error')
  getError() {
    return this.demoService.getError();
  }

  @Post('error')
  @SkipTransform()
  postError() {
    return this.demoService.postError();
  }

  @Get('params')
  getParams(@Query() query: any) {
    return this.demoService.getParams(query);
  }

  @Post('params')
  postParams(@Body() body: any) {
    return this.demoService.postParams(body);
  }
}
