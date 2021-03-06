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

namespace Skyline\Security\Identity\Provider;


use Generator;
use Skyline\Security\Identity\AnonymousIdentity;
use Skyline\Security\Identity\IdentityInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class AnonymousIdentityProvider extends AbstractIdentityProvider
{
    const ANONYMIOUS_COOKIE_NAME = 'skyline-anonymous-identity';


    public function isProvidedIdentity(IdentityInterface $identity): bool
    {
        return $identity instanceof AnonymousIdentity ? true : false;
    }

    public function yieldIdentities(Request $request): Generator
    {
        $cookie = $request->cookies->get( static::ANONYMIOUS_COOKIE_NAME );
        if($cookie) {
            yield new AnonymousIdentity($cookie, "", IdentityInterface::RELIABILITY_ANONYMOUS);
        } else {
            yield new AnonymousIdentity(uniqid("sky_anonymous_identity"), "", IdentityInterface::RELIABILITY_ANONYMOUS);
        }
    }

    public function installIdentity(IdentityInterface $identity, Request $request, Response $response)
    {
        $response->headers->setCookie( new Cookie(static::ANONYMIOUS_COOKIE_NAME, $identity->getToken()) );
        return true;
    }

    public function uninstallIdentity(IdentityInterface $identity, Response $response)
    {
        $response->headers->clearCookie(static::ANONYMIOUS_COOKIE_NAME);
        return true;
    }
}