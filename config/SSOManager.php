<?php

return [
  'JWT_APP_ID' => env('JWT_APP_ID', '1234'),
  'JWT_ISS' => env('JWT_ISS', 'your-256-bit-secret'),
  'JWT_AUTH_ENDPOINT' => env('JWT_AUTH_ENDPOINT', 'https://example.com/api/'),
  'JWS_KEY' => env('JWS_KEY', 'JWT Issuer'),
  'JWT_CLAIMS' => env('JWT_CLAIMS', 'iat,nbf,exp,sub,iss,aud'),
  'SSO_DEBUG' => false,
];