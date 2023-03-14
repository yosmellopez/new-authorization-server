import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { IncomingHttpHeaders } from 'http';
import { JwksClient } from 'src/auth/jwks/jwks.client';
import { JsonWebKey } from 'src/models/json-web-key.model';
import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
@Injectable()
export class JwksService {
  private readonly logger: Logger = new Logger(JwksService.name);
  constructor(private readonly jwksClient: JwksClient) {}

  async verify(request: any): Promise<boolean> {
    const token: string = this.getAuthorizationTokenFromHeader(request.headers);
    if (!this.hasTokenWithValidClaims(token)) {
      this.logger.error('Token with invalid claims was provided');
      return false;
    }

    // Get all web keys from JWKS endpoint
    const jsonWebKeys: Array<JsonWebKey> =
      await this.jwksClient.getJsonWebKeySet();

    console.log(token);

    // Find the public key with matching kid
    const publicKey: string | Buffer = this.findPublicKey(token, jsonWebKeys);

    if (!publicKey) {
      this.logger.error(
        'No public key was found for the bearer token provided',
      );
      return false;
    }

    try {
      jwt.verify(token, publicKey, {
        algorithms: ['RS256'],
      });
    } catch (e) {
      this.logger.error(
        'An error occurred verifying the bearer token with the associated public key',
      );
      this.logger.error(e.stack);
      throw new HttpException(e.message, HttpStatus.FORBIDDEN);
    }

    this.logger.debug(
      'Successfully verified bearer token with the associated public key',
    );

    return true;
  }

  private hasTokenWithValidClaims(token: string) {
    const { header, payload, signature } = jwt.decode(token, {
      complete: true,
    });

    // TODO: Add validation for claims

    return true;
  }

  private findPublicKey(
    token: string,
    jsonWebKeys: Array<JsonWebKey>,
  ): string | Buffer {
    const { header } = jwt.decode(token, { complete: true });

    let key = null;
    for (const jsonWebKey of jsonWebKeys) {
      if (jsonWebKey.kid === header.kid) {
        this.logger.debug(`Found json web key for kid ${header.kid}`);
        key = jsonWebKey;
        break;
      }
    }

    if (!key) {
      return null;
    }

    // Create the public key from the x509 certificate
    return crypto
      .createPublicKey(key.n)
      .export({ type: 'spki', format: 'pem' });
  }

  private getAuthorizationTokenFromHeader(
    headers: IncomingHttpHeaders,
  ): string {
    if (!headers || !headers.authorization) {
      throw new HttpException(
        'Authorization header is missing',
        HttpStatus.BAD_REQUEST,
      );
    }

    let token: string = headers.authorization;

    if (token.startsWith('Bearer ')) {
      token = headers.authorization.split(' ')[1].trim();
    }

    return token;
  }
}
