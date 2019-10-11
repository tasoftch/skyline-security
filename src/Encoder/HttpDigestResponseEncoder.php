<?php
/**
 * Copyright (c) 2018 TASoft Applications, Th. Abplanalp <info@tasoft.ch>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace Skyline\Security\Encoder;


class HttpDigestResponseEncoder extends HttpDigestA1Encoder
{
    private $expectsPlainUserCredentials = false;
    private $httpMethod;


    public function encodePassword(string $A1, array &$options = []): string
    {
        $uri = $options["uri"] ?? $_SERVER["REQUEST_URI"];
        $options["uri"] = $uri;

        $A2 = md5("$this->httpMethod:$uri");
        return @md5("{$A1}:{$options['nonce']}:{$options['nc']}:{$options['cnonce']}:{$options['qop']}:{$A2}");
    }

    /**
     * The Digest encoder is switched because the authorization sent by the browser contains an encoded response hash.
     * The encoden needs to encode the stored users credential to compare the response.
     * That's why the arguments in this method are switched
     * @param string $plain The persistent user's password. If getExpectsPlainUserCredentials() is false, it assumes the credentials as A1
     * @param string $encoded
     * @param array $options
     * @return bool
     */
    public function isPasswordValid(string $plain, string $encoded, array $options = []): bool
    {
        if($this->getExpectsPlainUserCredentials())
            $plain = parent::encodePassword($plain, $options);
        $response = $this->encodePassword($plain, $options);
        return $this->comparePasswords($encoded, $response);
    }

    /**
     * @return bool
     */
    public function getExpectsPlainUserCredentials(): bool
    {
        return $this->expectsPlainUserCredentials;
    }

    /**
     * Sets if the encoder should assume that the passed $encoded into isPasswordValid() is a plain password.
     * If $this->expectsPlainUserCredentials is false, it expects a hashed A1 password string.
     * @param bool $expectsPlainUserCredentials
     */
    public function setExpectsPlainUserCredentials(bool $expectsPlainUserCredentials): void
    {
        $this->expectsPlainUserCredentials = $expectsPlainUserCredentials;
    }

    public function __construct(string $realm, string $user, string $httpMethod = "", bool $isEncodedPasswordA1 = true)
    {
        parent::__construct($realm, $user);
        $this->expectsPlainUserCredentials = !$isEncodedPasswordA1;
        $this->httpMethod = $httpMethod ? $httpMethod : $_SERVER["REQUEST_METHOD"];
    }

    /**
     * @return string
     */
    public function getHttpMethod()
    {
        return $this->httpMethod;
    }

    /**
     * @param string $httpMethod
     */
    public function setHttpMethod($httpMethod): void
    {
        $this->httpMethod = $httpMethod;
    }
}