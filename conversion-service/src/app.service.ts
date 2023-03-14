import { Injectable } from '@nestjs/common';
import { CurrencyConversion } from './models/currency-conversion.model';

@Injectable()
export class AppService {
  convertCurrencies(currencyConversion: CurrencyConversion): number {
    const { fromCurrency, toCurrency } = currencyConversion;
    return 0.25 * fromCurrency + toCurrency;
  }
}
