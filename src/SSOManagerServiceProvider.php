<?php

namespace SirPaul\SSOManager;

use Illuminate\Support\ServiceProvider;
use SirPaul\SSOManager\Guards\SSOGuard;
use SirPaul\SSOManager\Providers\SSOUserProvider;

class SSOManagerServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
      $this->mergeConfigFrom(
        __DIR__.'/../config/SSOManager.php', 'SSOManager'
      );
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
      $this->publishes([
        __DIR__.'/../config/SSOManager.php' => config_path('SSOManager.php')
      ], 'config');

      \Auth::extend('ssoGuard', function ($app, $name, array $config) {
        // Return an instance of Illuminate\Contracts\Auth\Guard...
        return new SSOGuard($name, \Auth::createUserProvider($config['provider']), Request()->session(), Request());
      });

      \Auth::provider('ssoProvider', function ($app, array $config) {
        // Return an instance of Illuminate\Contracts\Auth\UserProvider...
        return new SSOUserProvider(Request()->session(), Request());
      });
    }
}
