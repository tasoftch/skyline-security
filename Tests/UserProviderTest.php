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
 * UserProviderTest.php
 * skyline-security
 *
 * Created on 2019-10-10 16:50 by thomas
 */

use PHPUnit\Framework\TestCase;
use Skyline\Security\User\InitialUser;
use Skyline\Security\User\Provider\ChainUserProvider;
use Skyline\Security\User\Provider\InitialUserProvider;
use Skyline\Security\User\Provider\InMemoryUserProvider;
use Skyline\Security\User\User;

class UserProviderTest extends TestCase
{
    public function testInitialUserProvider() {
        $ip = new InitialUserProvider("admin", "admin");
        $user = $ip->loadUserWithToken("admin");

        $this->assertInstanceOf(InitialUser::class, $user);
        $this->assertEquals([
            "admin"
        ], $ip->getUsernames());
    }

    /**
     * @expectedException Skyline\Security\Exception\SecurityException
     */
    public function testInitialUserInvalidUsername() {
		$this->expectException(\Skyline\Security\Exception\SecurityException::class);
        $ip = new InitialUserProvider("", "admin");
    }

    /**
     * @expectedException Skyline\Security\Exception\SecurityException
     */
    public function testInitialUserInvalidCredential() {
		$this->expectException(\Skyline\Security\Exception\SecurityException::class);
        $ip = new InitialUserProvider("admin", "");
    }

    public function testUnexistingUser() {
        $ip = new InitialUserProvider("admin", "admin");
        $user = $ip->loadUserWithToken("test");

        $this->assertNull($user);
    }

    public function testInMemoryUserProvider() {
        $ip = new InMemoryUserProvider();

        $ip->addUser($a1 = new User("admin", "test"));
        $ip->addUser($a2 = new User("admin2", "test"));

        $this->assertSame($a1, $ip->loadUserWithToken("admin"));
        $this->assertSame($a2, $ip->loadUserWithToken("admin2"));
    }

    public function testChainUserProvider() {
        $ip = new InMemoryUserProvider();

        $ip->addUser($a1 = new User("admin", "test"));
        $ip->addUser($a2 = new User("admin2", "test"));

        $ch = new ChainUserProvider([$ip]);

        $ip2 = new InMemoryUserProvider();

        $ip2->addUser($a3 = new User("admin3", "test"));
        $ip2->addUser($a4 = new User("admin4", "test"));

        $ch->addProvider($ip2);

        $this->assertSame($a1, $ip->loadUserWithToken("admin"));
        $this->assertSame($a2, $ip->loadUserWithToken("admin2"));

        $this->assertSame($a3, $ip2->loadUserWithToken("admin3"));
        $this->assertSame($a4, $ip2->loadUserWithToken("admin4"));

        $this->assertSame($a1, $ch->loadUserWithToken("admin"));
        $this->assertSame($a2, $ch->loadUserWithToken("admin2"));
        $this->assertSame($a3, $ch->loadUserWithToken("admin3"));
        $this->assertSame($a4, $ch->loadUserWithToken("admin4"));

        $this->assertEquals(["admin3", "admin4"], $ip2->getUsernames());

        $this->assertEquals(["admin", "admin2", "admin3", "admin4"], $ch->getUsernames());
    }
}
