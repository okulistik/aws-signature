<?php


namespace AwsSignature;


use Psr\Http\Message\RequestInterface;

interface SignatureInterface
{
    /**
     * Signs the specified request with an AWS signing protocol by using the
     * provided AWS account credentials and adding the required headers to the
     * request.
     *
     * @param RequestInterface $request Request to sign
     *
     * @param $credentials
     * @return RequestInterface Returns the modified request.
     */
    public function SignatureForAWS(
        RequestInterface $request,
        $credentials
    );

    /**
     * Create a pre-signed request.
     *
     * @param RequestInterface $request Request to sign
     * @param $credentials
     * @param int|string|\DateTime $expires The time at which the URL should
     *     expire. This can be a Unix timestamp, a PHP DateTime object, or a
     *     string that can be evaluated by strtotime.
     *
     * @param array $options
     * @return RequestInterface
     */
    public function presign(
        RequestInterface $request,
        $credentials,
        $expires,
        array $options = []
    );
}