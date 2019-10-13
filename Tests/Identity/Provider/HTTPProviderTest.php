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
 * HTTPProviderTest.php
 * skyline-security
 *
 * Created on 2019-10-13 11:24 by thomas
 */

namespace Identity\Provider;

use PHPUnit\Framework\TestCase;
use Skyline\Security\Authentication\Challenge\HTTP\DigestChallenge;
use Skyline\Security\Identity\HttpIdentity;
use Skyline\Security\Identity\Provider\HTTP\BasicIdentityProvider;
use Skyline\Security\Identity\Provider\HTTP\DigestIdentityProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class HTTPProviderTest extends TestCase
{
    public function testBasicProvider() {
        $p = new BasicIdentityProvider();

        $req = Request::create("/test");

        $identity = NULL;
        foreach($p->yieldIdentities($req) as $identity)
            break;

        $this->assertNull($identity);

        $req = Request::create("/test", "GET", [], [], [], ["HTTP_AUTHORIZATION" => "Basic ".base64_encode("admin:admin12")]);
        $identity = NULL;
        foreach($p->yieldIdentities($req) as $identity)
            break;

        $this->assertInstanceOf(HttpIdentity::class, $identity);
        $this->assertEquals(HttpIdentity::TYPE_BASIC, $identity->getType());
    }

    public function testDigestProvider() {
        $p = new DigestIdentityProvider();
        $req = Request::create("/test");

        $identity = NULL;
        foreach($p->yieldIdentities($req) as $identity)
            break;

        $this->assertNull($identity);

        $req = Request::create("/test", "GET", [], [], [], ["HTTP_AUTHORIZATION" => "Digest ".base64_encode("admin:admin12")]);
        $identity = NULL;
        foreach($p->yieldIdentities($req) as $identity)
            break;

        $this->assertNull($identity);

        // see /Tests/server.php for complete digest test
    }
}
