<?php
/**
 * BSD 3-Clause License
 *
 * Copyright (c) 2019, TASoft Applications
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

namespace Skyline\Security\Identity\Provider\Session;


use Generator;
use InvalidArgumentException;
use Skyline\Security\Exception\BadCredentialException;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Identity\Provider\AbstractIdentityProvider;
use Skyline\Security\Identity\SessionIdentity;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class RememberMeIdentityProvider extends AbstractIdentityProvider
{
    const COOKIE_DELIMITER = ':';
    const COOKIE_NAME = 'skyline_security_remember_me';
    const REMEMBER_ME_NAME = "remember_me";

    const OPTION_COOKIE_NAME = 'name';
    const OPTION_COOKIE_PATH = 'path';
    const OPTION_COOKIE_DOMAIN = 'domain';
    const OPTION_COOKIE_SECURE = 'secure';
    const OPTION_COOKIE_HTTPONLY = "httponly";
    const OPTION_COOKIE_LIFETIME = 'lifetime';
    const OPTION_REMEMBER_ME = 'rememberName';

    /** @var array  */
    protected $options = array(
        self::OPTION_COOKIE_NAME => self::COOKIE_NAME,
        self::OPTION_COOKIE_SECURE => false,
        self::OPTION_COOKIE_HTTPONLY => true,
        self::OPTION_COOKIE_PATH => '/',
        self::OPTION_COOKIE_DOMAIN => NULL,
        self::OPTION_COOKIE_LIFETIME => 8640000
    );

    /** @var string */
    private $providerKey;

    /** @var string */
    private $secret;


    /**
     * RememberMeIdentityProvider constructor.
     * @param string $providerKey
     * @param string $secret
     * @param array $options
     */
    public function __construct(string $providerKey, string $secret, array $options = [])
    {
        if(!function_exists("openssl_encrypt") || !function_exists("openssl_decrypt"))
            trigger_error("Please install the openssl extension to protect your session information!", E_USER_WARNING);

        if (empty($secret)) {
            throw new InvalidArgumentException('$secret must not be empty.');
        }
        if (empty($providerKey)) {
            throw new InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->providerKey = $providerKey;
        $this->secret = $secret;
        $this->options = array_merge($this->options, $options);
    }

    public function isProvidedIdentity(IdentityInterface $identity): bool
    {
        return $identity instanceof SessionIdentity && $identity->isRememberMe();
    }

    public function yieldIdentities(Request $request): Generator
    {
        if(null === $cookie = $request->cookies->get( $this->options[static::OPTION_COOKIE_NAME])) {
            return;
        }

        $parts = $this->decodeCookie( $cookie );
        $user = $parts[0] ?? NULL;
        if(!$user)
            return;
        $pass = $parts[1] ?? NULL;
        if(!$pass)
            return;

        $pass = $this->generateDecodedCredentials( $pass );
        if(!$pass) {
            $e = new BadCredentialException("Remember-Me Cookie is is not provided in correct manner");
            throw $e;
        }

        $reliability = min($parts[2] ?? 0, IdentityInterface::RELIABILITY_REMEMBER_ME);
        $options = unserialize(base64_decode($parts[3] ?? base64_encode("N;")));
        if(!is_array($options))
            $options = [];

        yield $this->createIdentity($user, $pass, $reliability, $options);
    }

    /**
     * @param Request $request
     * @return bool
     */
    public function getClientRememberMeRequest(Request $request): bool {
        $name = $this->options[ static::OPTION_REMEMBER_ME ] ?? static::REMEMBER_ME_NAME;
        $parameter = $request->request->get($name);

        return ('true' === $parameter || 'on' === $parameter || '1' === $parameter || 'yes' === $parameter || true === $parameter);
    }

    public function getLifeTime() {
        return time() + $this->options[ self::OPTION_COOKIE_LIFETIME ] ?? 8640000;
    }

    /**
     * Can be used by subclasses to create different identities
     *
     * @param $username
     * @param $password
     * @param $reliability
     * @param $options
     * @return IdentityInterface
     */
    protected function createIdentity($username, $password, $reliability, $options): IdentityInterface {
        return (new SessionIdentity($username, $password, SessionIdentity::RELIABILITY_REMEMBER_ME, $options))->setRememberMe(true);
    }

    public function acceptCommonInstall(IdentityInterface $identity)
    {
        return true;
    }

    public function installIdentity(IdentityInterface $identity, Request $request, Response $response)
    {
        if($this->getClientRememberMeRequest($request)) {
            $parts = [];
            $parts[] = $identity->getToken();
            $parts[] = $this->generateEncodedCredentials($identity);
            $parts[] = $identity->getReliability();
            $parts[] = base64_encode(serialize($this->getOptions()));

            $value = $this->encodeCookie($parts);

            $response->headers->setCookie(
                new Cookie(
                    $this->options[static::OPTION_COOKIE_NAME],
                    $value,
                    $this->getLifeTime(),
                    $this->options[static::OPTION_COOKIE_PATH] ?? "/",
                    $this->options[static::OPTION_COOKIE_DOMAIN] ?? NULL,
                    $this->options[static::OPTION_COOKIE_SECURE] ?? true,
                    $this->options[static::OPTION_COOKIE_HTTPONLY] ?? true)
            );
        }
        return true;
    }

    public function uninstallIdentity(IdentityInterface $identity, Response $response)
    {
        $response->headers->clearCookie($this->options[ static::OPTION_COOKIE_NAME ]);
        return true;
    }


    /**
     * @return string
     */
    public function getProviderKey(): string
    {
        return $this->providerKey;
    }

    /**
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * @return array
     */
    public function getOptions(): array
    {
        return $this->options;
    }


    private function generateDecodedCredentials($data) {
        if(function_exists("openssl_decrypt")) {
            $encrypt_method = "AES-256-CBC";
            $key = hash( 'sha256', $this->getSecret() );
            $iv = substr( hash( 'sha256', $this->getProviderKey() ), 0, 16 );

            return openssl_decrypt( base64_decode($data), $encrypt_method, $key, 0, $iv  );
        }
        return base64_decode($data);
    }

    private function generateEncodedCredentials(IdentityInterface $identity) {
        if(function_exists("openssl_decrypt")) {
            $encrypt_method = "AES-256-CBC";
            $key = hash( 'sha256', $this->getSecret() );
            $iv = substr( hash( 'sha256', $this->getProviderKey() ), 0, 16 );

            return base64_encode( openssl_encrypt( $identity->getCredentials(), $encrypt_method, $key, 0, $iv ) );
        }
        return base64_encode( $identity->getCredentials() );
    }

    /**
     * Decodes the raw cookie value.
     *
     * @param string $rawCookie
     *
     * @return array
     */
    private function decodeCookie($rawCookie)
    {
        return explode(static::COOKIE_DELIMITER, base64_decode($rawCookie));
    }

    /**
     * Encodes the cookie parts.
     *
     * @return string
     *
     * @throws InvalidArgumentException When $cookieParts contain the cookie delimiter. Extending class should either remove or escape it.
     */
    private function encodeCookie(array $cookieParts)
    {
        foreach ($cookieParts as $cookiePart) {
            if (false !== strpos($cookiePart, self::COOKIE_DELIMITER)) {
                throw new InvalidArgumentException(sprintf('$cookieParts should not contain the cookie delimiter "%s"', self::COOKIE_DELIMITER));
            }
        }

        return base64_encode(implode(self::COOKIE_DELIMITER, $cookieParts));
    }
}