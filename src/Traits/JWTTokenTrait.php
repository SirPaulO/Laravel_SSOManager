<?php

namespace SirPaul\SSOManager\Traits;

use Illuminate\Auth\GenericUser;

use Jose\Component\Core\JWK;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker;


trait JWTTokenTrait {

  /**
   * Get the generic user from a JWT
   *
   * @param  mixed  $user
   * @return \Illuminate\Auth\GenericUser|null
   */
  public function getUserFromJWT($token) {
    if(!$this->checkToken($token) || !$this->verifyToken($token))
      return null;

    // The serializer manager. We only use the JWS Compact Serialization Mode.
    $serializer = new CompactSerializer();
    // We try to load the token.
    $jws = $serializer->unserialize($token);
    // Get Claims
    $claims = json_decode($jws->getPayload(), true);

    $user         = new \stdClass();
    $user->token  = $token;

    foreach ($claims['sub'] as $claimKey => $claimValue) {
      $user->$claimKey = $claimValue;
    }

    return new GenericUser((array) $user);
  }


  public function checkToken($token, $claimsToCheck = null) {
    // The serializer manager. We only use the JWS Compact Serialization Mode.
    $serializer = new CompactSerializer();

    $claimCheckerManager = new ClaimCheckerManager(
      [
      new Checker\IssuedAtChecker(),
      new Checker\NotBeforeChecker(),
      new Checker\ExpirationTimeChecker(),
      ]
    );

    if(!$claimsToCheck)
      $claimsToCheck = ['iat', 'nbf', 'exp', 'iss', 'sub', 'aud'];

    // We try to load the token.
    $jws = $serializer->unserialize($token);

    $claims = json_decode($jws->getPayload(), true);

    $claimCheckerManager->check($claims, $claimsToCheck);

    if($claims['iss'] != config('SSOManager.JWT_ISS'))
      return false;

    $appID = (int) config('SSOManager.JWT_APP_ID');
    $isValidApp = is_array($claims['aud']) ? (int) $claims['aud']['id'] == $appID : (int) $claims['aud'] == $appID;

    if(!$isValidApp)
      return false;

    return true;
  }


  public function verifyToken($token) {
    // The algorithm manager with the HS256 algorithm.
    $algorithmManager = new AlgorithmManager([new HS256()]);

    // We instantiate our JWS Verifier.
    $jwsVerifier = new JWSVerifier($algorithmManager);

    // The serializer manager. We only use the JWS Compact Serialization Mode.
    $serializer = new CompactSerializer();

    // Our key.
    $jwk = new JWK([
      'kty' => 'oct',
      'k' => config('SSOManager.JWS_KEY'),
    ]);

    // We try to load the token.
    $jws = $serializer->unserialize($token);

    // We verify the signature. This method does NOT check the header.
    // The arguments are:
    // - The JWS object,
    // - The key,
    // - The index of the signature to check.
    $isVerified = $jwsVerifier->verifyWithKey($jws, $jwk, 0);

    return $isVerified;
  }

}
