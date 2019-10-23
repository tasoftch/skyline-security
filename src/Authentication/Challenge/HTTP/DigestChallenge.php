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

namespace Skyline\Security\Authentication\Challenge\HTTP;


use Symfony\Component\HttpFoundation\Response;

class DigestChallenge extends BasicChallenge
{
    const DEFAULT_OPAQUE_STRING = 'skyline-default-opaque';

    /** @var string */
    private $nonce;
    /** @var string */
    private $opaque;

    public function __construct(string $realm = "Skyline Protected Area", $nonce = NULL, $opaque = NULL)
    {
        parent::__construct($realm);
        $this->nonce = $nonce ?: md5( date("Y-m-d G") );
        $this->opaque = $opaque ?: md5(static::DEFAULT_OPAQUE_STRING);
    }

    protected function createAuthenticationHeader(Response $response)
    {
        $response->headers->set('WWW-Authenticate', sprintf('Digest realm="%s",qop="auth",nonce="%s",opaque="%s"', $this->getRealm(), $this->getNonce(), $this->getOpaque()));
    }

    /**
     * @return string
     */
    public function getNonce(): string
    {
        return $this->nonce;
    }

    /**
     * @return string
     */
    public function getOpaque(): string
    {
        return $this->opaque;
    }
}