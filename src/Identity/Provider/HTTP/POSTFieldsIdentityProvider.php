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

namespace Skyline\Security\Identity\Provider\HTTP;


use Generator;
use Skyline\Security\Identity\HttpIdentity;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Identity\Provider\AbstractIdentityProvider;
use Symfony\Component\HttpFoundation\Request;

class POSTFieldsIdentityProvider extends AbstractIdentityProvider
{
    /** @var string */
    private $tokenFieldName;
    /** @var string */
    private $credentialsFieldName;

    /**
     * POSTFieldsIdentityProvider constructor.
     * @param string $tokenFieldName
     * @param string $credentialsFieldName
     */
    public function __construct(string $tokenFieldName = 'username', string $credentialsFieldName = 'password')
    {
        $this->tokenFieldName = $tokenFieldName;
        $this->credentialsFieldName = $credentialsFieldName;
    }


    /**
     * @return string
     */
    public function getTokenFieldName(): string
    {
        return $this->tokenFieldName;
    }

    /**
     * @return string
     */
    public function getCredentialsFieldName(): string
    {
        return $this->credentialsFieldName;
    }

    public function isProvidedIdentity(IdentityInterface $identity): bool
    {
        return $identity instanceof HttpIdentity && $identity->getType() == HttpIdentity::TYPE_POST_FIELDS;
    }

    public function yieldIdentities(Request $request): Generator
    {
        $token = $this->getTokenValue($request);
        $credentials = $this->getCredentialValue($request);

        if($token) {
            yield (new HttpIdentity($token, $credentials, HttpIdentity::RELIABILITY_HTML_FORM))->setType( HttpIdentity::TYPE_POST_FIELDS );
        }
    }

    /**
     * Method to override for obtaining the identity token
     *
     * @param Request $request
     * @return string
     */
    protected function getTokenValue(Request $request) {
        $name = $this->getTokenFieldName();
        return $request->request->get($name);
    }

    /**
     * Method to override for obtaining the identity credentials
     *
     * @param Request $request
     * @return string
     */
    protected function getCredentialValue(Request $request) {
        $name = $this->getCredentialsFieldName();
        return $request->request->get($name);
    }
}