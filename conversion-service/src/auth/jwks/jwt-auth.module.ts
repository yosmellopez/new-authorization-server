import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { JwksClient } from 'src/auth/jwks/jwks.client';
import { JwksService } from 'src/auth/jwks/jwks.service';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './jwt.strategy';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [
    HttpModule,
    ConfigModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
  ],
  providers: [JwksClient, JwksService, JwtStrategy],
  exports: [JwksService, JwksClient, PassportModule],
})
export class JwtAuthModule {}
