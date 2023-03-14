import { Body, Controller, Logger, Post, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthGuard } from '@nestjs/passport';
import { CurrencyConversion } from './models/currency-conversion.model';

@Controller('/api')
export class AppController {
  private logger: Logger;

  constructor(private readonly appService: AppService) {
    this.logger = new Logger();
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('/convert-currencies')
  convertCurrency(@Body() conversion: CurrencyConversion): any {
    return { result: this.appService.convertCurrencies(conversion) };
  }
}
