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

namespace Skyline\Security\CSRF;


use InvalidArgumentException;
use Skyline\Security\CSRF\TokenGenerator\TokenGeneratorInterface;
use Skyline\Security\CSRF\TokenGenerator\URISafeTokenGenerator;
use Skyline\Security\CSRF\TokenStorage\NativeSessionTokenStorage;
use Skyline\Security\CSRF\TokenStorage\TokenStorageInterface;

class CSRFTokenManager
{
    private $generator;
    private $storage;
    private $namespace;

    /**
     * @param TokenGeneratorInterface|null $generator
     * @param TokenStorageInterface|null $storage
     * @param string|callable|null $namespace
     *                                                     * null: generates a namespace using $_SERVER['HTTPS']
     *                                                     * string: uses the given string
     *                                                     * callable: uses the result of this callable (must return a string)
     */
    public function __construct(TokenGeneratorInterface $generator = null, TokenStorageInterface $storage = null, $namespace = null)
    {
        $this->generator = $generator ?: new UriSafeTokenGenerator();
        $this->storage = $storage ?: new NativeSessionTokenStorage();

        $superGlobalNamespaceGenerator = function () {
            return !empty($_SERVER['HTTPS']) && 'off' !== strtolower($_SERVER['HTTPS']) ? 'https-' : '';
        };

        if (null === $namespace) {
            $this->namespace = $superGlobalNamespaceGenerator;
        } elseif (is_callable($namespace) || is_string($namespace)) {
            $this->namespace = $namespace;
        } else {
            throw new InvalidArgumentException(sprintf('$namespace must be a string, a callable returning a string or null. "%s" given.', gettype($namespace)));
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getToken(string $tokenId)
    {
        $namespacedId = $this->getNamespace().$tokenId;
        if ($this->storage->hasToken($namespacedId)) {
            $value = $this->storage->getToken($namespacedId);
        } else {
            $value = $this->generator->generateToken();

            $this->storage->setToken($namespacedId, $value);
        }

        return new CSRFToken($tokenId, $value);
    }

    /**
     * {@inheritdoc}
     */
    public function refreshToken(string $tokenId)
    {
        $namespacedId = $this->getNamespace().$tokenId;
        $value = $this->generator->generateToken();

        $this->storage->setToken($namespacedId, $value);

        return new CSRFToken($tokenId, $value);
    }

    /**
     * {@inheritdoc}
     */
    public function removeToken(string $tokenId)
    {
        return $this->storage->removeToken($this->getNamespace().$tokenId);
    }

    /**
     * {@inheritdoc}
     */
    public function isTokenValid(CSRFToken $token)
    {
        $namespacedId = $this->getNamespace().$token->getId();
        if (!$this->storage->hasToken($namespacedId)) {
            return false;
        }

        return hash_equals($this->storage->getToken($namespacedId), $token->getValue());
    }

    private function getNamespace(): string
    {
        return is_callable($ns = $this->namespace) ? $ns() : $ns;
    }
}