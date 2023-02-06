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
use Skyline\Security\Authentication\Challenge\HTTP\BasicChallenge;
use Skyline\Security\Exception\SecurityException;
use Skyline\Security\Identity\HttpIdentity;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Identity\Provider\AbstractIdentityProvider;
use Symfony\Component\HttpFoundation\Request;

class BasicIdentityProvider extends AbstractIdentityProvider
{
    /** @var string */
    private $realm;


    /**
     * Construct HTTPBasicIdentityProvider for realm
     * @param string|BasicChallenge $realmOrChallenge
     */
    public function __construct($realmOrChallenge = 'Skyline Protected Area')
    {
        if($realmOrChallenge instanceof BasicChallenge)
            $realmOrChallenge = $realmOrChallenge->getRealm();
        $this->realm = $realmOrChallenge;
    }

    public function isProvidedIdentity(IdentityInterface $identity): bool
    {
        if($identity instanceof HttpIdentity && $identity->getType() == HttpIdentity::TYPE_BASIC)
            return  true;
        return false;
    }

    public function yieldIdentities(Request $request): Generator
    {
        $auth = $request->headers->get("Authorization");
        if(stripos($auth ?: "", 'basic') === 0) {
            $auth = substr($auth, 6);
            $auth = explode(":", base64_decode($auth), 2);
            if(count($auth) != 2)
                throw new SecurityException("HTTP Basic: Authorization header could not be parsed");
            $user = $auth[0];
            $logged = $request->cookies->get(IdentityInterface::LOGGED_COOKIE_NAME);
            if($logged == '-')
                return;

            $pass = $auth[1];

            yield (new HttpIdentity($user, $pass, HttpIdentity::RELIABILITY_HTTP))->setType(HttpIdentity::TYPE_BASIC);
        }
    }

    /**
     * @return string
     */
    public function getRealm(): string
    {
        return $this->realm;
    }
}