import { HttpException, Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { lastValueFrom, map } from 'rxjs';
import { JsonWebKey } from 'src/models/json-web-key.model';
import { JwksResponse } from '../../models/wks-response.model';

@Injectable()
export class JwksClient {
  private readonly logger: Logger = new Logger(JwksClient.name);
  private readonly JWKS_URL: string = 'http://localhost:8081/v1/oauth2/jwks';
  private readonly TIMEOUT: number = 1000;

  constructor(private httpService: HttpService) {}

  async getJsonWebKeySet(): Promise<Array<JsonWebKey>> {
    this.logger.log(`Attempting to retrieve json web keys from Jwks endpoint`);

    const config = {
      timeout: this.TIMEOUT,
    };

    let response: JwksResponse = null;
    try {
      response = await lastValueFrom(
        this.httpService.get(this.JWKS_URL, config).pipe(
          map((response) => {
            return response.data;
          }),
        ),
      );
    } catch (e) {
      this.logger.error(
        `An error occurred invoking Jwks endpoint to retrieve public keys`,
      );
      this.logger.error(e.stack);
      throw new HttpException(e.message, e.response.status);
    }

    if (!response || !response.keys || response.keys.length == 0) {
      this.logger.error('No json web keys were returned from Jwks endpoint');
      return [];
    }

    return response.keys;
  }
}
