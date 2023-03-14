import { JsonWebKey } from 'src/models/json-web-key.model';

export class JwksResponse {
  keys: Array<JsonWebKey>;
}
