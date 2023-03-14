export default () => ({
  port: parseInt(process.env.PORT, 10) || 3000,
  RESOURCE_SERVER_HOST:
    process.env.RESOURCE_SERVER_HOST || 'http://localhost:8081/v1/oauth2/jwks',
  server: {
    host:
      process.env.RESOURCE_SERVER_HOST ||
      'http://localhost:8081/v1/oauth2/jwks',
  },
});
