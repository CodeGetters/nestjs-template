import { Injectable } from '@nestjs/common';
// import { LoggerService } from '@/common/logger/logger.service';
// import { CustomResponse } from '@/core/interceptor/transform.interceptor';

@Injectable()
export class DemoService {
  // constructor(private logger: LoggerService) {}
  constructor() {}

  getHello() {
    // this.logger.log('Getting hello message', 'DemoService');
    // return new CustomResponse('Hello World', '请求成功', '2000');
    return 'Hello World';
  }

  postHello() {
    // this.logger.log('post hello message', 'DemoService');
    return 'post hello';
  }

  getError() {
    // this.logger.error('get error message', 'DemoService');
    return '错误原因.....';
  }

  postError() {
    // this.logger.error('post error message', 'DemoService');
    return '错误原因(跳过序列化).....';
  }

  getParams(query: any) {
    console.log('======query====', query);
    // this.logger.log('get params message', 'DemoService');
    return query;
  }

  postParams(body: any) {
    console.log('======获取form-urlencoded====', body);
    // this.logger.log('post params message', 'DemoService');
    return body;
  }
}
