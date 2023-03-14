import { CanActivate, ExecutionContext, Injectable, Logger } from '@nestjs/common';
import { JwksService } from 'src/auth/jwks/jwks.service';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger: Logger = new Logger(JwtAuthGuard.name);

  constructor(private jwksService: JwksService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    this.logger.log(`Checking if user has authorities`);
    const request = context.switchToHttp().getRequest();
    return await this.jwksService.verify(request);
  }
}
