<?php

namespace SirPaul\SSOManager\Providers;

use Illuminate\Http\Request;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;

class SSOUserProvider implements UserProvider {

  use \SirPaul\SSOManager\Traits\AuthAPITrait {
    \SirPaul\SSOManager\Traits\AuthAPITrait::login as ApiLogin;
    \SirPaul\SSOManager\Traits\AuthAPITrait::refresh as ApiRefresh;
  }

  /**
   * The session used by the guard.
   *
   * @var \Illuminate\Contracts\Session\Session
   */
  protected $session;

  /**
   * The request instance.
   *
   * @var \Symfony\Component\HttpFoundation\Request
   */
  protected $request;

  /**
   * Create a new authentication guard.
   *
   * @param  string  $name
   * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
   * @param  \Illuminate\Contracts\Session\Session  $session
   * @param  \Symfony\Component\HttpFoundation\Request|null  $request
   * @return void
   */
  public function __construct(Session $session, Request $request = null) {
    $this->session = $session;
    $this->request = $request;
  }

  public function retrieveById($identifier) {
    return null;
  }

  public function retrieveByToken($identifier, $token) {
    return null;
  }

  public function updateRememberToken(Authenticatable $user, $token) {
    return null;
  }

  /**
   * Retrieve a user by the given credentials.
   *
   * @param  array  $credentials
   * @return \Illuminate\Contracts\Auth\Authenticatable|null
   */
  public function retrieveByCredentials(array $credentials) {
    try {
      $user = $this->ApiLogin($credentials);
    } catch (\Throwable $e) {
      if(config('SSOManager.SSO_DEBUG'))
        dd($e);
      else
        return null;
    }

    if(!$user)
      return null;

    $user->password = \Hash::make($credentials['password']);

    return $user;
  }

  /**
   * @param Authenticatable $user
   * @param array $credentials
   *
   * @return bool
   */
  public function validateCredentials(Authenticatable $user, array $credentials) {
    return \Hash::check($credentials['password'], $user->getAuthPassword());
  }

  public function autoUpdateToken(Authenticatable $user) {
    // If there is no need to update the token (more than 30min to expire) return null
    if($this->checkToken($user->token) && $this->checkToken($user->token, null)) {
      return null;
    }

    $pwd = $user->password;

    $user = $this->ApiRefresh($user->token);

    if(!$user)
      return null;

    $user->password = $pwd;

    return $user;
  }

}
