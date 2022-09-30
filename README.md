## 1.基本介绍
### 1.1 项目介绍
> 基于laravel框架 微信小程序支付v3版本，支付请求、支付回调、退款请求、退款回调
### 1.2 配置
在laravel的配置config/app.php中的provide添加```Mjy191\LaravelWxPayV3\ServiceProvider::class``

运行命令```php artisan vendor:publish --provider="Mjy191\LaravelWxPayV3\ServiceProvider"```发布配置config/wx.php

配置微信小程序的支付
```
return [
    // 小程序的appid
    'appAPPID'=>'xxxxxx',
    // 商户号
    'payMCHID'=>'xxxxxx',
    // v2的key
    'sk'=>'xxxxxx',
    // v3的key
    'skv3'=>'xxxxxx',
    // 证书序列号
    'xlid'=>'xxxxxx',
    // 支付证书存放在app/Common/wxCert目录下
    'certPath'=>'/app/Common/wxCert/',
    // 支付回调地址
    'payNotifyUrl'=>'/api/wx/paynotify/',
    // 退款回调地址
    'refundsNotifyUrl'=>'/api/wx/refundsnotify/',
];

```

在routes/api.php新增支付回调地址、退款回调地址

```
Route::post('wx/paynotify/{payNum}',[\App\Http\Controllers\Api\WxController::class,'paynotify']);
Route::post('wx/refundsnotify/{payNum}',[\App\Http\Controllers\Api\WxController::class,'refundsnotify']);
```
在控制器
```
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Mjy191\LaravelWxPayV3\WxPayV3;

class WxController extends Controller
{

    /**
     * 微信支付回调
     */
    public function paynotify(WxPayV3 $wxPayV3)
    {
        return $wxPayV3->notify(function($res){
            // 解密后的消息$res，可以参考下面
            //处理订单业务逻辑
        });
    }

   /**
     * 微信退款回调
     */
    public function refundsnotify(WxPayV3 $wxPayV3){
        return $wxPayV3->refundsNotify(function($res){
            //解密消息$res，可以参考下面
            //处理订单业务逻辑
        });
    }
}
```

```$xslt
支付结果通知回调
https://pay.weixin.qq.com/wiki/doc/apiv3/apis/chapter3_5_5.shtml
            {
                 "transaction_id":"1217752501201407033233368018",
                 "amount":{
                     "payer_total":100,
                     "total":100,
                     "currency":"CNY",
                     "payer_currency":"CNY"
                 },
                 "mchid":"1230000109",
                 "trade_state":"SUCCESS",
                 "bank_type":"CMC",
                 "promotion_detail":[
                     {
                         "amount":100,
                         "wechatpay_contribute":0,
                         "coupon_id":"109519",
                         "scope":"GLOBAL",
                         "merchant_contribute":0,
                         "name":"单品惠-6",
                         "other_contribute":0,
                         "currency":"CNY",
                         "stock_id":"931386",
                         "goods_detail":[
                             {
                                 "goods_remark":"商品备注信息",
                                 "quantity":1,
                                 "discount_amount":1,
                                 "goods_id":"M1006",
                                 "unit_price":100
                             },
                             {
                                 "goods_remark":"商品备注信息",
                                 "quantity":1,
                                 "discount_amount":1,
                                 "goods_id":"M1006",
                                 "unit_price":100
                             }
                         ]
                     },
                     {
                         "amount":100,
                         "wechatpay_contribute":0,
                         "coupon_id":"109519",
                         "scope":"GLOBAL",
                         "merchant_contribute":0,
                         "name":"单品惠-6",
                         "other_contribute":0,
                         "currency":"CNY",
                         "stock_id":"931386",
                         "goods_detail":[
                             {
                                 "goods_remark":"商品备注信息",
                                 "quantity":1,
                                 "discount_amount":1,
                                 "goods_id":"M1006",
                                 "unit_price":100
                             },
                             {
                                 "goods_remark":"商品备注信息",
                                 "quantity":1,
                                 "discount_amount":1,
                                 "goods_id":"M1006",
                                 "unit_price":100
                             }
                         ]
                     }
                 ],
                 "success_time":"2018-06-08T10:34:56+08:00",
                 "payer":{
                     "openid":"oUpF8uMuAJO_M2pxb1Q9zNjWeS6o"
                 },
                 "out_trade_no":"1217752501201407033233368018",
                 "appid":"wxd678efh567hg6787",
                 "trade_state_desc":"支付成功",
                 "trade_type":"MICROPAY",
                 "attach":"自定义数据",
                 "scene_info":{
                     "device_id":"013467007045764"
                 }
             }
```
```$xslt
退款结果回调
https://pay.weixin.qq.com/wiki/doc/apiv3/apis/chapter3_5_11.shtml
             *{
                  "mchid": "1900000100",
                  "transaction_id": "1008450740201411110005820873",
                  "out_trade_no": "20150806125346",
                  "refund_id": "50200207182018070300011301001",
                  "out_refund_no": "7752501201407033233368018",
                  "refund_status": "SUCCESS",
                  "success_time": "2018-06-08T10:34:56+08:00",
                  "user_received_account": "招商银行信用卡0403",
                  "amount" : {
                      "total": 999,
                      "refund": 999,
                      "payer_total": 999,
                      "payer_refund": 999
                  }
              }
             */
```


新建app/Exceptions/ApiException.php
捕获ApiException抛出的异常进行处理
```
namespace App\Exceptions;

use Mjy191\Tools\Tools;
use Exception;

class ApiException extends Exception
{
    /**
     * 转换异常为 HTTP 响应
     *
     * @param \Illuminate\Http\Request
     * @return \Illuminate\Http\Response
     */
    public function render($request)
    {
        return response()->json(Tools::returnData(null,$this->getCode(),$this->getMessage()))->setEncodingOptions(JSON_UNESCAPED_UNICODE);
    }
}
```

### 1.3 安装
```
composer require mjy191/laravel-wx-pay-v3                 
```

## 2. 使用说明
请求参数参考https://pay.weixin.qq.com/wiki/doc/apiv3/open/pay/chapter2_8_3.shtml
```
方法说明
jsApi 下单，返回小程序支付信息
orderDetal 统一下单的详情查询
payNotify 支付回调
refunds 退款申请
refundsResult 退款结果查询
refundsNotify 退款回调
withDraw 提现
```

下单demo

```
use Mjy191\Tools\Tools;
use App\Http\Controllers\Controller;
use Mjy191\LaravelWxPayV3\WxPayV3;


class TestController extends Controller
{

    /**
     * 用户列表
     */
    public function index(){
        $param['openid'] = 'xxxxx'; // 用小程序openid
        $param['out_trade_no'] = 'xxxxx'; // 我方交易订单号
        $param['description'] = 'xxxxx'; //描述
        $param['amount'] = 100;  //交易金额分
        $res = (new WxPayV3())->jsApi($param);
        // 数据返回给小程序前端
        return Tools::returnData($res);
    }
}
```

## 3. 请求日志查询
日志均保存在logs目录下
通过logid aaaaaa 查询
```$xslt
grep aaaaaa *
2082207.log:2022-08-22 07:24:50 uri[/api/order/payInfo?sign=xxx] logid[aaaaaa] curl[url[https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi] method[post] params[{"appid":"xxx","mchid":"xxx","description":"xxxx","out_trade_no":"testxxx","notify_url":"https:\/\/xxx.xxx.com\/api\/wx\/paynotify\/111111","amount":{"total":9000},"payer":{"openid":"xxxxx"}}] header[["Content-Type:application\/json; charset=UTF-8","Accept:application\/json","User-Agent:*\/*","Authorization: WECHATPAY2-SHA256-RSA2048 mchid=\"xxxx\",serial_no=\"xxxxx\",nonce_str=\"xxxx\",timestamp=\"xxxx\",signature=\"xxxxx\""]]]
2022082207.log:2022-08-22 07:24:50 uri[/api/order/payInfo?sign=xxx] logid[aaaaaa] curl response[{"prepay_id":"xxxxxxxxx"}]
2022082207.log:2022-08-22 07:24:50 uri[/api/order/payInfo?sign=xxx] logid[aaaaaa] response[{"code":1,"msg":"success","data":{"appId":"xxxx","timeStamp":"xxxx","nonceStr":"xxxxxx","package":"prepay_id=xxxxx","signType":"RSA","paySign":"xxxx"},"timestamp":xxxx}]

```
