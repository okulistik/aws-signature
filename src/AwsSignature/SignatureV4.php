<?php


namespace AwsSignature;

use Psr\Http\Message\RequestInterface;
use GuzzleHttp\Psr7;

class SignatureV4 implements SignatureInterface
{
    use SignatureTrait;

    const ISO8601_BASIC = 'Ymd\THis\Z';
    const AMZ_CONTENT_SHA256_HEADER = 'X-Amz-Content-Sha256';
    const AWS_CRYPTO_TYPE = 'AWS4-HMAC-SHA256 ';
    const UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD';

    /** @var bool */
    private $unsigned;

    private function getHeaderBlacklist()
    {
        return [
            'cache-control' => true,
            'content-length' => true,
            'expect' => true,
            'max-forwards' => true,
            'pragma' => true,
            'range' => true,
            'te' => true,
            'if-match' => true,
            'if-none-match' => true,
            'if-modified-since' => true,
            'if-unmodified-since' => true,
            'if-range' => true,
            'accept' => true,
            'authorization' => true,
            'proxy-authorization' => true,
            'from' => true,
            'referer' => true,
            'user-agent' => true,
            'x-amzn-trace-id' => true,
            'aws-sdk-invocation-id' => true,
            'aws-sdk-retry' => true,
        ];
    }

    public function SignatureForAWS(RequestInterface $request, $credentials)
    {

        $parseRequest = $this->parseRequest($request);
        $payload = $this->getPayload($request);

        $largeDateTime = date(self::ISO8601_BASIC);
        $shortDateTime = substr($largeDateTime, 0, 8);

        $scope = $this->createScope($shortDateTime, $credentials['region'], $credentials['service']);


        $signing = $this->getSigningKey($shortDateTime, $credentials['region'], $credentials['service'], $credentials['secret']);

        $parseRequest['headers'] = [
            'Content-Type' => [$credentials['contentType']],
            'Host' => [$credentials['host']],
            'X-Amz-Content-Sha256' => [$payload],
            'X-Amz-Date' => [$largeDateTime],
        ];

        $context = $this->createContext($parseRequest, $payload);

        $createStringToSign = $this->createStringToSign($largeDateTime, $scope, $context['creq']);
        $signingKey = hash_hmac('sha256', $createStringToSign, $signing);

        $auth = self::AWS_CRYPTO_TYPE
            . "Credential={$credentials['access']}/{$scope}, "
            . "SignedHeaders={$context['headers']}, Signature={$signingKey}";


        $parseRequest['headers']['Authorization'] = [$auth];

        return $this->buildRequest($parseRequest);
    }

    public function presign(RequestInterface $request, $credentials, $expires, array $options = [])
    {
        $startTimestamp = isset($options['start_time'])
            ? $this->convertToTimestamp($options['start_time'], null)
            : time();

        $expiresTimestamp = $this->convertToTimestamp($expires, $startTimestamp);

        $parsed = $this->createPresignedRequest($request);
        $payload = $this->getPresignedPayload($request);


        $httpDate = gmdate(self::ISO8601_BASIC, $startTimestamp);
        $shortDate = substr($httpDate, 0, 8);

        $scope = $this->createScope($shortDate, $credentials['region'], $credentials['service']);
        $credential = $credentials['access'] . '/' . $scope;

        $parsed['headers']['Host'] = [$credentials['host']];
        $parsed['query']['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256';
        $parsed['query']['X-Amz-Credential'] = $credential;
        $parsed['query']['X-Amz-Date'] = gmdate('Ymd\THis\Z', $startTimestamp);
        $parsed['query']['X-Amz-SignedHeaders'] = implode(';', $this->getPresignHeaders($parsed['headers']));
        $parsed['query']['X-Amz-Expires'] = $this->convertExpires($expiresTimestamp, $startTimestamp);

        $context = $this->createContext($parsed, $payload);
        $stringToSign = $this->createStringToSign($httpDate, $scope, $context['creq']);
        $key = $this->getSigningKey(
            $shortDate,
            $credentials['region'],
            $credentials['service'],
            $credentials['secret']
        );
        $parsed['query']['X-Amz-Signature'] = hash_hmac('sha256', $stringToSign, $key);


        return $this->buildRequest($parsed);
    }

    private function createStringToSign($longDate, $credentialScope, $creq)
    {
        $hash = hash('sha256', $creq);

        return "AWS4-HMAC-SHA256\n{$longDate}\n{$credentialScope}\n{$hash}";
    }

    private function createContext(array $parsedRequest, $payload)
    {
        $blacklist = $this->getHeaderBlacklist();

        // Normalize the path as required by SigV4
        $canon = $parsedRequest['method'] . "\n"
            . $this->createCanonicalizedPath($parsedRequest['path']) . "\n"
            . $this->getCanonicalizedQuery($parsedRequest['query']) . "\n";

        // Case-insensitively aggregate all of the headers.
        $aggregate = [];
        foreach ($parsedRequest['headers'] as $key => $values) {
            $key = strtolower($key);
            if (!isset($blacklist[$key])) {
                foreach ($values as $v) {
                    $aggregate[$key][] = $v;
                }
            }
        }

        ksort($aggregate);
        $canonHeaders = [];
        foreach ($aggregate as $k => $v) {
            if (count($v) > 0) {
                sort($v);
            }
            $canonHeaders[] = $k . ':' . preg_replace('/\s+/', ' ', implode(',', $v));
        }

        $signedHeadersString = implode(';', array_keys($aggregate));
        $canon .= implode("\n", $canonHeaders) . "\n\n"
            . $signedHeadersString . "\n"
            . $payload;

        return ['creq' => $canon, 'headers' => $signedHeadersString];
    }

    protected function getPayload(RequestInterface $request)
    {
        if ($this->unsigned && $request->getUri()->getScheme() == 'https') {
            return self::UNSIGNED_PAYLOAD;
        }
        // Calculate the request signature payload
        if ($request->hasHeader(self::AMZ_CONTENT_SHA256_HEADER)) {
            // Handle streaming operations (e.g. Glacier.UploadArchive)
            return $request->getHeaderLine(self::AMZ_CONTENT_SHA256_HEADER);
        }

        if (!$request->getBody()->isSeekable()) {

            throw new \Exception('sha256');
        }

        try {
            return Psr7\hash($request->getBody(), 'sha256');
        } catch (\Exception $e) {
            throw new \Exception('sha256', $e);
        }
    }

    protected function createCanonicalizedPath($path)
    {
        // Only remove one slash in case of keys that have a preceding slash
        if (substr($path, 0, 1) === '/') {
            $path = substr($path, 1);
        }
        return '/' . $path;
    }

    private function parseRequest(RequestInterface $request)
    {
        // Clean up any previously set headers.
        /** @var RequestInterface $request */
        $request = $request
            ->withoutHeader('X-Amz-Date')
            ->withoutHeader('Host')
            ->withoutHeader('Date')
            ->withoutHeader('Authorization');
        $uri = $request->getUri();


        return [
            'method' => $request->getMethod(),
            'path' => $uri->getPath(),
            'query' => Psr7\parse_query($uri->getQuery()),
            'uri' => $uri,
            'headers' => $request->getHeaders(),
            'body' => $request->getBody(),
            'version' => $request->getProtocolVersion()
        ];
    }

    private function getCanonicalizedQuery(array $query)
    {
        unset($query['X-Amz-Signature']);

        if (!$query) {
            return '';
        }

        $qs = '';
        ksort($query);
        foreach ($query as $k => $v) {
            if (!is_array($v)) {
                $qs .= rawurlencode($k) . '=' . rawurlencode($v) . '&';
            } else {
                sort($v);
                foreach ($v as $value) {
                    $qs .= rawurlencode($k) . '=' . rawurlencode($value) . '&';
                }
            }
        }

        return substr($qs, 0, -1);
    }

    private function convertToTimestamp($dateValue, $relativeTimeBase = null)
    {
        if ($dateValue instanceof \DateTimeInterface) {
            $timestamp = $dateValue->getTimestamp();
        } elseif (!is_numeric($dateValue)) {
            $timestamp = strtotime($dateValue,
                $relativeTimeBase === null ? time() : $relativeTimeBase
            );
        } else {
            $timestamp = $dateValue;
        }

        return $timestamp;
    }

    private function createPresignedRequest(RequestInterface $request)
    {
        $parsedRequest = $this->parseRequest($request);

        return $this->moveHeadersToQuery($parsedRequest);
    }

    private function moveHeadersToQuery(array $parsedRequest)
    {
        foreach ($parsedRequest['headers'] as $name => $header) {
            $lname = strtolower($name);
            if (substr($lname, 0, 5) == 'x-amz') {
                $parsedRequest['query'][$name] = $header;
            }
            $blacklist = $this->getHeaderBlacklist();
            if (isset($blacklist[$lname])
                || $lname === strtolower(self::AMZ_CONTENT_SHA256_HEADER)
            ) {
                unset($parsedRequest['headers'][$name]);
            }
        }

        return $parsedRequest;
    }

    private function getPresignHeaders(array $headers)
    {
        $presignHeaders = [];
        $blacklist = $this->getHeaderBlacklist();
        foreach ($headers as $name => $value) {
            $lName = strtolower($name);
            if (!isset($blacklist[$lName])
                && $name !== self::AMZ_CONTENT_SHA256_HEADER
            ) {
                $presignHeaders[] = $lName;
            }
        }
        return $presignHeaders;
    }

    private function convertExpires($expiresTimestamp, $startTimestamp)
    {
        $duration = $expiresTimestamp - $startTimestamp;

        // Ensure that the duration of the signature is not longer than a week
        if ($duration > 604800) {
            throw new \InvalidArgumentException('The expiration date of a '
                . 'signature version 4 presigned URL must be less than one '
                . 'week');
        }

        return $duration;
    }

    private function buildRequest(array $req)
    {
        if ($req['query']) {
            $req['uri'] = $req['uri']->withQuery(Psr7\build_query($req['query']));
        }

        return new Psr7\Request(
            $req['method'],
            $req['uri'],
            $req['headers'],
            $req['body'],
            $req['version']
        );
    }
}