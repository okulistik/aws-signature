<?php


namespace AwsSignature;


use Psr\Http\Message\RequestInterface;

class S3SignatureV4 extends SignatureV4
{
    /**
     * Always add a x-amz-content-sha-256 for data integrity.
     * @param RequestInterface $request
     * @param $credentials
     * @return RequestInterface|\stdClass
     * @throws \Exception
     */
    public function SignatureForAWS(RequestInterface $request, $credentials)
    {
        if (!$request->hasHeader('x-amz-content-sha256')) {
            $request = $request->withHeader(
                'X-Amz-Content-Sha256',
                $this->getPayload($request)
            );
        }

        return parent::SignatureForAWS($request, $credentials);
    }

    /**
     * Always add a x-amz-content-sha-256 for data integrity.
     * @param RequestInterface $request
     * @param $credentials
     * @param $expires
     * @param array $options
     * @return \GuzzleHttp\Psr7\Request|RequestInterface
     */
    public function presign(RequestInterface $request, $credentials, $expires, array $options = [])
    {
        if (!$request->hasHeader('x-amz-content-sha256')) {
            $request = $request->withHeader(
                'X-Amz-Content-Sha256',
                $this->getPresignedPayload($request)
            );
        }

        return parent::presign($request, $credentials, $expires, $options);
    }

    /**
     * Override used to allow pre-signed URLs to be created for an
     * in-determinate request payload.
     * @param RequestInterface $request
     * @return
     */
    protected function getPresignedPayload(RequestInterface $request)
    {
        return SignatureV4::UNSIGNED_PAYLOAD;
    }

    /**
     * Amazon S3 does not double-encode the path component in the canonical request
     */
    protected function createCanonicalizedPath($path)
    {
        // Only remove one slash in case of keys that have a preceding slash
        if (substr($path, 0, 1) === '/') {
            $path = substr($path, 1);
        }
        return '/' . $path;
    }
}