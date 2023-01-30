<?php

namespace Mjy191\LaravelWxPayV3;

use Illuminate\Support\Facades\Request;
use Mjy191\Enum\Enum;
use Mjy191\MyCurl\MyCurl;
use Mjy191\MyLogs\MyLogs;
use Mjy191\Tools\Tools;
use App\Exceptions\ApiException;

class WxPayV3
{
    private $appid;
    private $mchid;
    private $sk;
    private $skv3;
    private $xlid;
    private $time;
    private $noncestr;
    const AUTH_TAG_LENGTH_BYTE = 16;
    private $error;
    // 证书存放路径
    private $certPath;
    // 正式环境、测试环境
    private $env;
    private $payNotifyUrl;
    const HOST = 'https://api.mch.weixin.qq.com';
    const GET = 'GET';
    const POST = 'POST';

    public function __construct()
    {
        $this->appid = config('wx.appAPPID');
        $this->mchid = config('wx.payMCHID');
        $this->sk = config('wx.sk');
        $this->skv3 = config('wx.skv3');
        $this->xlid = config('wx.xlid');
        $this->certPath = base_path() . config('wx.certPath');
        $this->env = env('APP_ENV') == 'production';
        $this->payNotifyUrl = config('wx.payNotifyUrl');
        $this->refundsNotifyUrl = config('wx.refundsNotifyUrl');
    }

    /**
     * 获取返回错误信息
     * @return mixed
     */
    public function getError()
    {
        return $this->error;
    }

    /**
     * v3的jsApi接口
     * @param $param
     * @return array|bool
     */
    public function jsApi($param)
    {
        $data['appid'] = $this->appid;
        $data['mchid'] = $this->mchid;
        $data['description'] = mb_strlen($param['description']) > 127 ? mb_substr($param['description'], 0, 127) : $param['description'];
        // 测试环境订单号前缀test
        $data['out_trade_no'] = $this->env ? $param['out_trade_no'] : "test{$param['out_trade_no']}";
        $data['notify_url'] = Tools::getHost() . $this->payNotifyUrl . $param['out_trade_no'];
        $data['amount']['total'] = $param['amount'];
        $data['payer']['openid'] = $param['openid'];

        //{"prepay_id":"wx1111111111111"}
        $res = $this->request('/v3/pay/transactions/jsapi', self::POST, $data);
        $res = json_decode($res, true);
        if (isset($res['prepay_id'])) {
            $appData = [
                'appId' => $this->appid,
                'timeStamp' => (string)$this->time,
                'nonceStr' => $this->noncestr,
                'package' => "prepay_id={$res['prepay_id']}",
                'signType' => "RSA",
            ];
            $appData['paySign'] = $this->getJsApiSign($appData);
            return $appData;
        } else {
            $this->error = $res;
            throw new ApiException('支付下单系统错误', Enum::erCodeSystem);
        }
    }

    /**
     * 查询订单
     * @param $out_trade_no
     * @return bool|mixed
     */
    public function orderDetal($out_trade_no)
    {
        $uri = "/v3/pay/transactions/out-trade-no/{$out_trade_no}?mchid={$this->mchid}";
        $res = $this->request($uri);
        $res = json_decode($res, true);
        if (isset($res['trade_state']) && $res['trade_state'] == 'SUCCESS') {
            return $res;
        } else {
            $this->error = $res;
            throw new ApiException('查询支付订单系统错误', Enum::erCodeSystem);
        }
    }

    /**
     * v3支付成功异步回调
     * @param $callBack
     * @return bool|mixed
     * @throws ApiException
     */
    public function payNotify($callBack)
    {
        $response = Request::instance()->getContent();
        $response = json_decode($response, true);
        if (!isset($response['resource']['ciphertext'])) {
            throw new ApiException('支付回调返回参数错误', 2);
        }
        $de = $this->decryptToString($response['resource']['associated_data'], $response['resource']['nonce'], $response['resource']['ciphertext']);
        // 记录解密信息
        MyLogs::write('notifyv3', $de);
        $de = json_decode($de, true);
        if (isset($de['trade_state']) && $de['trade_state'] == 'SUCCESS') {
            // 闭包执行业务逻辑
            if(call_user_func_array($callBack, [$de])===true){
                return ['code' => 'SUCCESS', 'message' => '成功'];
            }else{
                return ['code' => 'FAIL', 'message' => '支付结果回调处理错误'];
            }
        } else {
            return ['code' => 'FAIL', 'message' => '支付结果回调处理错误'];
        }
    }

    /**
     * v3退款申请
     * @param $param
     * @return bool|mixed
     */
    public function refunds($param)
    {
        //原订单号
        $data['out_trade_no'] = $this->env ? $param['out_trade_no'] : "test{$param['out_trade_no']}";
        //退款订单号
        $data['out_refund_no'] = $this->env ? $param['out_refund_no'] : "test{$param['out_refund_no']}";
        $data['notify_url'] = Tools::getHost() . $this->refundsNotifyUrl . $param['out_trade_no'];
        //退款金额
        $data['amount']['refund'] = $param['refund'];
        //成交金额
        $data['amount']['total'] = $param['total'];
        $data['amount']['currency'] = 'CNY';
        $res = $this->request("/v3/refund/domestic/refunds", self::POST, $data);
        //$res ='{"amount":{"currency":"CNY","discount_refund":0,"from":[],"payer_refund":1,"payer_total":1,"refund":1,"settlement_refund":1,"settlement_total":1,"total":1},"channel":"ORIGINAL","create_time":"2021-07-19T22:35:45+08:00","funds_account":"AVAILABLE","out_refund_no":"dev_75","out_trade_no":"dev_75","promotion_detail":[],"refund_id":"50301208752021071910775603275","status":"PROCESSING","transaction_id":"4200001210202107188024304115","user_received_account":"工商银行借记卡"}';
        $res = json_decode($res, true);
        if (isset($res['status']) && in_array($res['status'], ['PROCESSING', 'SUCCESS'])) {
            return $res;
        } else {
            $this->error = $res;
            throw new ApiException('退款处理失败', Enum::erCodeSystem);
        }
    }


    /**
     * 退款接口查询
     * @param $param
     * @throws Exception
     */
    public function refundsResult($param)
    {
        $url = "/v3/refund/domestic/refunds/{$param['out_refund_no']}";
        $res = $this->request($url);
        $res = json_decode($res, true);
        if (isset($res['status']) && $res['status'] == 'SUCCESS') {
            return $res;
        } else {
            $this->error = $res;
            throw new ApiException('退款接口查询错误', Enum::erCodeSystem);
        }
    }

    /**
     * v3 退款结果异步通知
     */
    public function refundsNotify($callBack)
    {
        $response = Request::instance()->getContent();
        $response = json_decode($response, true);
        if (!isset($response['resource']['ciphertext'])) {
            throw new ApiException('返回参数错误', 2);
        }
        $de = $this->decryptToString($response['resource']['associated_data'], $response['resource']['nonce'], $response['resource']['ciphertext']);
        MyLogs::write('notifyv3', $de);
        $de = json_decode($de, true);
        if (isset($de['refund_status']) && $de['refund_status'] == 'SUCCESS') {
            if(call_user_func_array($callBack, [$de])===true){
                return ['code' => 'SUCCESS', 'message' => '成功'];
            }else{
                return ['code' => 'FAIL', 'message' => '退款结果回调处理错误'];
            }
        } else {
            return ['code' => 'FAIL', 'message' => '退款结果回调处理错误'];
        }
    }

    /**
     * 提现到零钱
     */
    public function withDraw($param)
    {
        $data['appid'] = $this->appid;
        $data['out_batch_no'] = env('APP_ENV')=='production'?$param['out_batch_no']:"test{$param['out_batch_no']}";
        $data['batch_name'] = mb_substr($param['batch_name'],0,32);
        $data['batch_remark'] = mb_substr($param['batch_remark'],0,32);
        $data['total_amount'] = (int)round(100*$param['amount']);
        $data['total_num'] = 1;
        $data['transfer_detail_list'][0] = [
            'out_detail_no'=>$data['out_batch_no'],
            'transfer_amount'=>(int)round(100*$param['amount']),
            'transfer_remark'=>mb_substr($param['transfer_remark'],0,32),
            'openid'=>$param['openid'],
        ];

        $res = $this->request("/v3/transfer/batches", self::POST, $data);
        $res = json_decode($res, true);
        if (isset($res['out_batch_no'])) {
            return $res;
        } else {
            $this->error = $res;
            throw new ApiException('提现到零钱失败', Enum::erCodeSystem);
        }
    }

    /**
     * 发起http请求
     * @param $uri
     * @param string $method
     * @param string $data
     * @return bool|string
     * @throws ApiException
     */
    private function request($uri, $method = self::GET, $data = '')
    {
        $this->time = time();
        $this->noncestr = $this->getNoncestr();
        if ($data) {
            $data = json_encode($data);
        }
        $sign = $this->sign($uri, $data, $method, $this->noncestr, $this->time);//签名
        $token = sprintf('mchid="%s",serial_no="%s",nonce_str="%s",timestamp="%d",signature="%s"', $this->mchid, $this->xlid, $this->noncestr, $this->time, $sign);//头部信息
        $header = array(
            'Content-Type:' . 'application/json; charset=UTF-8',
            'Accept:application/json',
            'User-Agent:*/*',
            'Authorization: WECHATPAY2-SHA256-RSA2048 ' . $token
        );
        $res = MyCurl::send(self::HOST . $uri, $method, $data, $header);
        return $res;
    }

    /**
     * 微信支付签名
     * @param $url
     * @param $data
     * @param $method
     * @param $randstr
     * @param $time
     * @return string
     * @throws ApiException
     */
    private function sign($url, $data, $method, $randstr, $time)
    {
        if ($method == self::POST) {
            $str = self::POST . "\n" . $url . "\n" . $time . "\n" . $randstr . "\n" . $data . "\n";
        } else if($method == self::GET){
            $str = self::GET . "\n" . $url . "\n" . $time . "\n" . $randstr . "\n" . "\n";
        } else {
            throw new ApiException("无此请求方式",Enum::erCodeServer);
        }
        $key = $this->getPem();//在商户平台下载的秘钥
        $str = $this->getSha256WithRSA($str, $key);
        return $str;
    }

    /**
     * 读取微信支付证书（证书从微信平台下载）
     * @return false|string
     * @throws ApiException
     */
    private function getPem()
    {
        $key = file_get_contents($this->certPath . 'apiclient_key.pem');//在商户平台下载的秘钥
        if (!$key) {
            throw new ApiException('get pem error', Enum::erCodeSystem);
        }
        return $key;
    }

    /**
     * 调起支付的签名
     * @param $data
     * @return string
     * @throws ApiException
     */
    private function getJsApiSign($data)
    {
        $str = $data['appId'] . "\n" . $data['timeStamp'] . "\n" . $data['nonceStr'] . "\n" . $data['package'] . "\n";
        $key = $this->getPem();
        $str = $this->getSha256WithRSA($str, $key);
        return $str;
    }

    private function getSha256WithRSA($content, $privateKey)
    {
        $raw_sign = "";
        openssl_sign($content, $raw_sign, $privateKey, "sha256WithRSAEncryption");
        $sign = base64_encode($raw_sign);
        return $sign;
    }

    /**
     * 生成随机数
     */
    private function getNoncestr($length = 32)
    {
        $chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        $str = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }

    /**
     * Decrypt AEAD_AES_256_GCM ciphertext
     *
     * @param string $associatedData AES GCM additional authentication data
     * @param string $nonceStr AES GCM nonce
     * @param string $ciphertext AES GCM cipher text
     *
     * @return string|bool      Decrypted string on success or FALSE on failure
     */
    private function decryptToString($associatedData, $nonceStr, $ciphertext)
    {
        $ciphertext = \base64_decode($ciphertext);
        if (strlen($ciphertext) <= self::AUTH_TAG_LENGTH_BYTE) {
            return false;
        }

        // ext-sodium (default installed on >= PHP 7.2)
        if (function_exists('\sodium_crypto_aead_aes256gcm_is_available') &&
            \sodium_crypto_aead_aes256gcm_is_available()) {
            return \sodium_crypto_aead_aes256gcm_decrypt($ciphertext, $associatedData, $nonceStr, $this->skv3);
        }

        // ext-libsodium (need install libsodium-php 1.x via pecl)
        if (function_exists('\Sodium\crypto_aead_aes256gcm_is_available') &&
            \Sodium\crypto_aead_aes256gcm_is_available()) {
            return \Sodium\crypto_aead_aes256gcm_decrypt($ciphertext, $associatedData, $nonceStr, $this->skv3);
        }

        // openssl (PHP >= 7.1 support AEAD)
        if (PHP_VERSION_ID >= 70100 && in_array('aes-256-gcm', \openssl_get_cipher_methods())) {
            $ctext = substr($ciphertext, 0, -self::AUTH_TAG_LENGTH_BYTE);
            $authTag = substr($ciphertext, -self::AUTH_TAG_LENGTH_BYTE);

            return \openssl_decrypt($ctext, 'aes-256-gcm', $this->skv3, \OPENSSL_RAW_DATA, $nonceStr,
                $authTag, $associatedData);
        }

        throw new \RuntimeException('AEAD_AES_256_GCM需要PHP 7.1以上或者安装libsodium-php');
    }
}
