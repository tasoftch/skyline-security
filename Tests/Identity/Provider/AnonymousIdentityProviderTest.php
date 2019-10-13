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

/**
 * AnonymousIdentityProviderTest.php
 * skyline-security
 *
 * Created on 2019-10-12 13:53 by thomas
 */

namespace Identity\Provider;

use Skyline\Security\Identity\AnonymousIdentity;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Identity\Provider\AnonymousIdentityProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class AnonymousIdentityProviderTest extends TestCase
{
    public function testProvider() {
        $ip = new AnonymousIdentityProvider();

        $request = Request::create("/test");
        $count = 0;
        /** @var IdentityInterface $identity */
        foreach($ip->yieldIdentities($request) as $identity) {
            $count++;
        }

        $this->assertEquals(1, $count);
        $this->assertInstanceOf(AnonymousIdentity::class, $identity);


        $this->assertNull($ip->getSpecificIdentityPasswordEncoder($identity));
        $response = new Response();

        $this->assertTrue($ip->installIdentity($identity, $request, $response));

        $cookie = $response->headers->getCookies()[0];
        $this->assertEquals($identity->getToken(), $cookie->getValue());
        $this->assertEquals(0, $cookie->getExpiresTime());

        $this->assertTrue($ip->uninstallIdentity($identity, $response));
        $cookie = $response->headers->getCookies()[0];
        $this->assertEmpty($cookie->getValue());
        $this->assertEquals(AnonymousIdentityProvider::ANONYMIOUS_COOKIE_NAME, $cookie->getName());
        $this->assertNotEquals(0, $cookie->getExpiresTime());
    }

    public function testAnonymousIndentityRequest() {
        $request = Request::create("/test", 'POST', [], [AnonymousIdentityProvider::ANONYMIOUS_COOKIE_NAME=>'my-anonymous-token']);
        $ip = new AnonymousIdentityProvider();

        $count = 0;
        /** @var IdentityInterface $identity */
        foreach($ip->yieldIdentities($request) as $identity) {
            $count++;
        }

        $this->assertEquals(1, $count);
        $this->assertInstanceOf(AnonymousIdentity::class, $identity);

        $this->assertEquals("my-anonymous-token", $identity->getToken());

        $this->assertTrue($ip->isProvidedIdentity($identity));
    }
}
