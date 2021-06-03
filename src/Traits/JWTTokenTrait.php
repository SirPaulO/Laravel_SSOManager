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
   * @param $token
   *
   * @return GenericUser|null
   * @throws Checker\InvalidClaimException
   * @throws Checker\MissingMandatoryClaimException
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

    $user->aud = stdClass();
    foreach ($claims['aud'] as $claimKey => $claimValue) {
      $user->aud->$claimKey = $claimValue;
    }

    return new GenericUser((array) $user);
  }

  /**
   * Check token and claims
   *
   * @param $token
   * @param $claimsToCheck
   *
   * @return bool
   * @throws Checker\InvalidClaimException
   * @throws Checker\MissingMandatoryClaimException
   */
  public function checkToken($token) {
    // The serializer manager. We only use the JWS Compact Serialization Mode.
    $serializer = new CompactSerializer();

    $claimCheckerManager = new ClaimCheckerManager(
      [
      new Checker\IssuedAtChecker(),
      new Checker\NotBeforeChecker(),
      new Checker\ExpirationTimeChecker(),
      ]
    );

    $claimsToCheck = explode(',', str_replace(' ', '', config('SSOManager.JWT_CLAIMS')));

    // We try to load the token.
    $jws = $serializer->unserialize($token);

    $claims = json_decode($jws->getPayload(), true);

    $claimCheckerManager->check($claims, $claimsToCheck);

    if(in_array('iss', $claimsToCheck) && $claims['iss'] != config('SSOManager.JWT_ISS'))
      return false;

    if(in_array('aud', $claimsToCheck)) {
      $appID = (int) config('SSOManager.JWT_APP_ID');
      $isValidApp = is_array($claims['aud']) ? (int) $claims['aud']['id'] == $appID : (int) $claims['aud'] == $appID;
    }

    if(!$isValidApp)
      return false;

    return true;
  }

  /**
   * Verify token signature
   *
   * @param $token
   *
   * @return bool
   */
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
