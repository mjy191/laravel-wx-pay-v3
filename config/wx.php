<?php
return [
    // *** 域名 ***
    'host' => '',

    // *** 微信公众号配置 ***
    // 微信公众号appid
    'gzhAPPID'=>'',
    'gzhAPPSECRET'=>'',
    // 微信公众号消息的token
    'gzhTokenMsg'=>'',
    // 公众号access_token的redis前缀
    'gzhTokenName'=>'gzh:token',

    // *** 微信小程序配置 ***
    // 小程序的appid
    'appAPPID'=>'',
    'appSECRET'=>'',
    // 小程序消息的token
    'appTokenMsg'=>'',
    //小程序的access_token的redis前缀
    'appTokenName'=>'wxapp:token',

    // *** 微信支付相关配置 ***
    // 商户号
    'payMCHID'=>'',
    // v2的key
    'sk'=>'',
    // v3的key
    'skv3'=>'',
    // 证书序列号
    'xlid'=>'',
    // 支付证书存放在app/Common/wxCert目录下
    'certPath'=>'/app/Common/wxCert/',
    // 支付回调地址
    'payNotifyUrl'=>'/api/wx/paynotify/',
    // 退款回调地址
    'refundsNotifyUrl'=>'/api/wx/refundsnotify/',
];
