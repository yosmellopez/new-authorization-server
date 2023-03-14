export class JsonWebKey {
  kty: string;
  kid: string;
  n?: string;
  e?: string;
}

export interface JwtPayload {
  sub: string;

  aud: string;

  nbf: number;

  scope: string[];

  iss: string;

  exp: number;

  iat: number;

  authorities: string[];
}


export interface DefaultObject {
  statusCode: number;

  message: string;
}
