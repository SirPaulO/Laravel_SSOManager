<?php

namespace SirPaul\SSOManager\Guards;

use Illuminate\Http\Request;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Auth\GenericUser;

use SirPaul\SSOManager\Providers\SSOUserProvider;

class SSOGuard implements Guard {

  use \SirPaul\SSOManager\Traits\JWTTokenTrait;

  /**
   * The name of the Guard. Typically "session".
   *
   * Corresponds to guard name in authentication configuration.
   *
   * @var string
   */
  protected $name;

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
   * Indicates if the logout method has been called.
   *
   * @var bool
   */
  protected $loggedOut = false;

  /**
   * User Object
   *
   * @var \Illuminate\Contracts\Auth\Authenticatable
   */
  protected $user = null;

  /**
   * Create a new authentication guard.
   *
   * @param  string  $name
   * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
   * @param  \Illuminate\Contracts\Session\Session  $session
   * @param  \Symfony\Component\HttpFoundation\Request|null  $request
   * @return void
   */
  public function __construct($name, SSOUserProvider $provider, Session $session, Request $request = null) {
    $this->name = $name;
    $this->session = $session;
    $this->request = $request;
    $this->provider = $provider;
  }

  /**
   * Get the currently authenticated user.
   *
   * @return \Illuminate\Contracts\Auth\Authenticatable|null
   */
  public function user() {
    if ($this->loggedOut) {
      return null;
    }

    // If we've already retrieved the user for the current request we can just
    // return it back immediately. We do not want to fetch the user data on
    // every call to this method because that would be tremendously slow.
    if (!is_null($this->user)) {
      return $this->user;
    }

    try {
      $this->user = unserialize($this->session->get($this->getName()));
      if (!$this->user || !$this->checkToken($this->user->token) || !$this->verifyToken($this->user->token)) {
        $this->logout();
        return null;
      }
    } catch (\Throwable $th) {
      $this->logout();
      return null;
    }

    return $this->user;
  }

  /**
   * Determine if the current user is authenticated.
   *
   * @return bool
   */
  public function check() {
    return $this->user() != null;
  }

  /**
   * Determine if the current user is a guest.
   *
   * @return bool
   */
  public function guest() {
    if ($this->loggedOut) {
      return true;
    }
    return $this->user() == null;
  }

  /**
   * Get the ID for the currently authenticated user.
   *
   * @return int|null
   */
  public function id() {
    if ($this->loggedOut) {
      return;
    }

    return $this->user()
      ? $this->user()->getAuthIdentifier()
      : null; //$this->session->get($this->getName());
  }

  /**
   * Validate a user's credentials.
   *
   * @param  array  $credentials
   * @return bool
   */
  public function validate(array $credentials = []) {
    $user = $this->provider->retrieveByCredentials($credentials);

    return $this->hasValidCredentials($user, $credentials);
  }

  /**
   * Set the current user.
   *
   * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
   * @return $this
   */
  public function setUser(Authenticatable $user) {
    $this->user = $user;

    $this->loggedOut = false;

    return $this;
  }

  /**
   * Attempt to authenticate a user using the given credentials.
   *
   * @param  array  $credentials
   * @return bool
   */
  public function attempt(array $credentials = []) {
    // Ask for the user to the provider
    $user = $this->provider->retrieveByCredentials($credentials);

    // If an implementation of UserInterface was returned, we'll ask the provider
    // to validate the user against the given credentials, and if they are in
    // fact valid we'll log the users into the application and return true.
    if ($this->hasValidCredentials($user, $credentials)) {
      $this->login($user);
      return true;
    }

    return false;
  }

  /**
   * Determine if the user matches the credentials.
   *
   * @param  mixed  $user
   * @param  array  $credentials
   * @return bool
   */
  protected function hasValidCredentials($user, $credentials) {
    return !is_null($user) && $this->provider->validateCredentials($user, $credentials);
  }

  /**
   * Get a unique identifier for the auth session value.
   *
   * @return string
   */
  public function getName() {
    return 'login_'.$this->name.'_'.sha1(static::class);
  }

  /**
   * Get the generic user.
   *
   * @param  mixed  $user
   * @return \Illuminate\Auth\GenericUser|null
   */
  protected function getGenericUser($user) {
    if (!is_null($user)) {
      return new GenericUser((array) $user);
    }
  }

  /**
   * Log a user into the application.
   *
   * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
   * @return void
   */
  public function login(Authenticatable $user) {
    $this->updateSession(serialize($user));
    $this->setUser($user);
  }

  /**
   * Update the session with the given SERIALIZED encoded User.
   *
   * @param  string  $serializedUser
   * @return void
   */
  protected function updateSession($serializedUser) {
    $this->session->put($this->getName(), $serializedUser);
    $this->session->migrate(true);
  }

  /**
   * Log the user out of the application.
   *
   * @return void
   */
  public function logout() {
    $user = $this->user();

    $this->session->remove($this->getName());

    $this->user = null;

    $this->loggedOut = true;

    //$this->redisFlushUser();
  }

}
