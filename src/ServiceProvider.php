<?php
namespace Mjy191\LaravelWxPayV3;

use Illuminate\Support\ServiceProvider as LaravelServiceProvider;

class ServiceProvider extends LaravelServiceProvider
{
    protected function boot()
    {
        $source = realpath(__DIR__ . '/../config/wx.php');

        if ($this->app->runningInConsole()) {
            $this->publishes([$source => \config_path('wx.php')], 'mjy191-wxPay');
        }
    }
}
