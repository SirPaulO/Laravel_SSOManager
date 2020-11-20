<?php

namespace SirPaul\SSOManager\Traits;

use GuzzleHttp\Client;
use \Illuminate\Auth\AuthenticationException;

trait AuthAPITrait {
  use JWTTokenTrait;

  public function login($credentials) {
    $client = new Client();
    $url = config('SSOManager.JWT_AUTH_ENDPOINT') . 'login';

    try {
      $response = $client->post($url, [
        'headers' => ['alg'=>'HS256'],
        'form_params' => $credentials
      ]);

      $token = $this->getTokenFromRequest($response);

      if(!$token)
        return null;

      $user = $this->getUserFromJWT($token);

      return $user;
    } catch (\Throwable $error) {
      return $this->responseErrorHandler($error);
    }
  }

  public function refresh($token) {
    $client = new Client();
    $url = config('SSOManager.JWT_AUTH_ENDPOINT') . 'refresh';

    try {
      $response = $client->get($url, [
        'headers'       => [
        'alg'           =>'HS256',
        'Authorization' => 'Bearer ' . $token,
        'Accept'        => 'application/json',
        ]
      ]);
    } catch (\Throwable $error) {
      return $this->responseErrorHandler($error);
    }

    $token = $this->getTokenFromRequest($response);

    if(!$token)
      return null;

    $user = $this->getUserFromJWT($token);

    return $user;
  }

  private function getTokenFromRequest($response) {
    try {
      if($response->getStatusCode() != 200)
        return null;
      $responseBody = json_decode($response->getBody()->getContents());
      return $responseBody->token;
    } catch (\Throwable $th) {
      return null;
    }
  }

  private function responseErrorHandler(\Throwable $error) {
    try {
      $errorMessage = json_decode($error->getResponse()->getBody()->getContents());
      throw new AuthenticationException($errorMessage);
    } catch (\Throwable $th) {
      throw new AuthenticationException($error->getMessage());
    }
  }

}