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
use Skyline\Security\Authentication\Challenge\HTTP\DigestChallenge;
use Skyline\Security\Encoder\HttpDigestResponseEncoder;
use Skyline\Security\Identity\HttpIdentity;
use Skyline\Security\Identity\Identity;
use Skyline\Security\Identity\IdentityInterface;
use Symfony\Component\HttpFoundation\Request;
use Skyline\Security\Encoder\PasswordEncoderInterface;

class DigestIdentityProvider extends BasicIdentityProvider
{
    /** @var string|null */
    private $nonce;
    /** @var string|null */
    private $opaque;

    /**
     * DigestIdentityProvider constructor.
     * @param string|DigestChallenge $realmOrChallenge
     */
    public function __construct($realmOrChallenge = 'Skyline Protected Area')
    {
        if($realmOrChallenge instanceof DigestChallenge) {
            $this->nonce = $realmOrChallenge->getNonce();
            $this->opaque = $realmOrChallenge->getOpaque();
        }
        parent::__construct($realmOrChallenge);
    }

    public function yieldIdentities(Request $request): Generator
    {
        $auth = $request->headers->get("Authorization");

        if(stripos($auth, 'digest') === 0) {
            $data = $this->digestParse($auth);

            if($data) {
                $logged = $request->cookies->get(IdentityInterface::LOGGED_COOKIE_NAME);
                if($logged == '-')
                    return;

                $user = $data['username'];
                $pass = $data["response"];
                unset($data["username"]);
                unset($data["response"]);

                if($this->nonce && $this->nonce != $data["nonce"] || $this->opaque && $this->opaque != $data["opaque"])
                    return;

                yield (new HttpIdentity($user, $pass, Identity::RELIABILITY_HTTP, $data))->setType(HttpIdentity::TYPE_DIGEST);
            }
        }
    }

    /**
     * Parse the digest authorization header
     *
     * @param $digest
     * @return array|bool
     */
    private function digestParse($digest) {
        // protect against missing data
        $needed_parts = array('nonce'=>1, 'nc'=>1, 'cnonce'=>1, 'qop'=>1, 'username'=>1, 'uri'=>1, 'response'=>1, 'opaque' => 1);
        $data = array();

        preg_match_all('@(\w+)=(?:(?:")([^"]+)"|([^\s,$]+))@', $digest, $matches, PREG_SET_ORDER);

        foreach ($matches as $m) {
            $data[$m[1]] = $m[2] ? $m[2] : $m[3];
            unset($needed_parts[$m[1]]);
        }

        return $needed_parts ? false : $data;
    }

    /**
     * Return the digest password encoder to decode the password (needing realm and token)
     *
     * @inheritDoc
     */
    public function getSpecificIdentityPasswordEncoder(IdentityInterface $identity): ?PasswordEncoderInterface
    {
        return new HttpDigestResponseEncoder($this->getRealm(), $identity->getToken());
    }

    /**
     * @inheritDoc
     */
    public function isProvidedIdentity(IdentityInterface $identity): bool
    {
        return $identity instanceof HttpIdentity && $identity->getType() == HttpIdentity::TYPE_DIGEST;
    }
}