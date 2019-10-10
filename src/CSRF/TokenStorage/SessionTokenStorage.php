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

namespace Skyline\Security\CSRF\TokenStorage;


use Skyline\Security\CSRF\Exception\TokenNotFoundException;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class SessionTokenStorage implements TokenStorageInterface
{
    /**
     * The namespace used to store values in the session.
     */
    const SESSION_NAMESPACE = '_csrf';

    private $session;
    private $namespace;

    /**
     * Initializes the storage with a Session object and a session namespace.
     *
     * @param string $namespace The namespace under which the token is stored in the session
     */
    public function __construct(SessionInterface $session, string $namespace = self::SESSION_NAMESPACE)
    {
        $this->session = $session;
        $this->namespace = $namespace;
    }

    /**
     * {@inheritdoc}
     */
    public function getToken(string $tokenId)
    {
        if (!$this->session->isStarted()) {
            $this->session->start();
        }

        if (!$this->session->has($this->namespace.'/'.$tokenId)) {
            throw new TokenNotFoundException('The CSRF token with ID '.$tokenId.' does not exist.');
        }

        return (string) $this->session->get($this->namespace.'/'.$tokenId);
    }

    /**
     * {@inheritdoc}
     */
    public function setToken(string $tokenId, string $token)
    {
        if (!$this->session->isStarted()) {
            $this->session->start();
        }

        $this->session->set($this->namespace.'/'.$tokenId, $token);
    }

    /**
     * {@inheritdoc}
     */
    public function hasToken(string $tokenId)
    {
        if (!$this->session->isStarted()) {
            $this->session->start();
        }

        return $this->session->has($this->namespace.'/'.$tokenId);
    }

    /**
     * {@inheritdoc}
     */
    public function removeToken(string $tokenId)
    {
        if (!$this->session->isStarted()) {
            $this->session->start();
        }

        return $this->session->remove($this->namespace.'/'.$tokenId);
    }

    /**
     * {@inheritdoc}
     */
    public function clear()
    {
        foreach (array_keys($this->session->all()) as $key) {
            if (0 === strpos($key, $this->namespace.'/')) {
                $this->session->remove($key);
            }
        }
    }
}