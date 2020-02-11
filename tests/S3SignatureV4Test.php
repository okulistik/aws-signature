<?php

namespace AwsSignature;


use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Request;

/**
 * Class S3SignatureV4Test
 * @package AwsSignature
 */
class S3SignatureV4Test extends \PHPUnit_Framework_TestCase
{
    const ISO8601 = 'Y-m-d\TH:i:sO';

    public function testPresign()
    {
        $envSettings = parse_ini_file("env.ini", true);

        $path = $envSettings['awsTestPath'];
        $expiresTime = 36000; //1 hour

        $credentials = [
            'access' => $envSettings['awsCredentials']['accessKey'],
            'secret' => $envSettings['awsCredentials']['secretKey'],
            'host' => $envSettings['awsCredentials']['host'],
            'region' => $envSettings['awsCredentials']['region'],
            'service' => $envSettings['awsCredentials']['service'],
            'contentType' => 'application/octet-stream'
        ];

        $expires = strtotime(date(self::ISO8601)) + $expiresTime;
        $expires = date(self::ISO8601, $expires);

        $sing = new S3SignatureV4();

        $uri = new Psr7\Uri('http://' . $credentials['host'] . $path);

        $request = new Request('GET', $uri);

        $request = $sing->presign($request, $credentials, $expires);

        $requestUri = $request->getUri();

        $expected = "https://{$credentials['host']}{$path}?";
        $this->assertContains($expected, 'https://' . $requestUri->getHost() . $requestUri->getPath() . '?' . $requestUri->getQuery());

    }
}
