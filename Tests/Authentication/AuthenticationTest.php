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
 * AuthenticationTest.php
 * skyline-security
 *
 * Created on 2019-10-13 13:25 by thomas
 */

use PHPUnit\Framework\TestCase;
use Skyline\Security\Authentication\AuthenticationService;
use Skyline\Security\Encoder\PasswordEncoderChain;
use Skyline\Security\Encoder\PlaintextPasswordEncoder;
use Skyline\Security\Exception\Auth\NoIdentityException;
use Skyline\Security\Exception\UserNotFoundException;
use Skyline\Security\Identity\Identity;
use Skyline\Security\User\AdvancedUser;
use Skyline\Security\User\Provider\ChainUserProvider;
use Skyline\Security\User\Provider\InMemoryUserProvider;
use Skyline\Security\User\User;
use Symfony\Component\HttpFoundation\Request;

class AuthenticationTest extends TestCase
{
    /**
     * @expectedException Skyline\Security\Exception\Auth\NoIdentityException
     * @expectedExceptionCode 401
     */
    public function testNoIdentity() {
		$this->expectException(NoIdentityException::class);
        $auth = new AuthenticationService($ch = new ChainUserProvider(), $pc = new PasswordEncoderChain());

        $request = Request::create("/test");
        $auth->authenticateIdentity(NULL, $request);
    }

    /**
     * @expectedException Skyline\Security\Exception\Auth\NoIdentityException
     * @expectedExceptionCode 403
     */
    public function testDeniedAnonymous() {
        $auth = new AuthenticationService($ch = new ChainUserProvider(), $pc = new PasswordEncoderChain());

        $request = Request::create("/test");

        $identity = new Identity("admin", "12345", Identity::RELIABILITY_ANONYMOUS);
		$this->expectException(NoIdentityException::class);
        $auth->authenticateIdentity($identity, $request);
    }

    /**
     * @expectedException Skyline\Security\Exception\UserNotFoundException
     * @expectedExceptionCode 401
     */
    public function testUserNotFound() {
        $auth = new AuthenticationService($ch = new ChainUserProvider(), $pc = new PasswordEncoderChain());

        $request = Request::create("/test");

        $identity = new Identity("admin", "12345", Identity::RELIABILITY_HTTP);
		$this->expectException(UserNotFoundException::class);
        $auth->authenticateIdentity($identity, $request);
    }

    /**
     * @expectedException Skyline\Security\Exception\Auth\HiddenUserException
     * @expectedExceptionCode 401
     */
    public function testHiddenUser() {
        $auth = new AuthenticationService($ch = new ChainUserProvider(), $pc = new PasswordEncoderChain());
        $ch->addProvider($up = new InMemoryUserProvider());
        $up->addUser( new AdvancedUser("admin", "12345", [], AdvancedUser::OPTION_HIDDEN) );

        $request = Request::create("/test");
        $identity = new Identity("admin", "12345", Identity::RELIABILITY_HTTP);
		$this->expectException(\Skyline\Security\Exception\Auth\HiddenUserException::class);
        $auth->authenticateIdentity($identity, $request);
    }

    /**
     * @expectedException Skyline\Security\Exception\Auth\BlockedUserException
     * @expectedExceptionCode 401
     */
    public function testBlockedUser() {
        $auth = new AuthenticationService($ch = new ChainUserProvider(), $pc = new PasswordEncoderChain());
        $ch->addProvider($up = new InMemoryUserProvider());
        $up->addUser( new AdvancedUser("admin", "12345", [], AdvancedUser::OPTION_BLOCKED) );

        $request = Request::create("/test");
        $identity = new Identity("admin", "12345", Identity::RELIABILITY_HTTP);
		$this->expectException(\Skyline\Security\Exception\Auth\BlockedUserException::class);
        $auth->authenticateIdentity($identity, $request);
    }

    /**
     * @expectedException Skyline\Security\Exception\Auth\DeactivatedUserException
     * @expectedExceptionCode 401
     */
    public function testDeactivated() {
        $auth = new AuthenticationService($ch = new ChainUserProvider(), $pc = new PasswordEncoderChain());
        $ch->addProvider($up = new InMemoryUserProvider());
        $up->addUser( new AdvancedUser("admin", "12345", [], AdvancedUser::OPTION_DEACTIVATED) );

        $request = Request::create("/test");
        $identity = new Identity("admin", "12345", Identity::RELIABILITY_HTTP);
		$this->expectException(\Skyline\Security\Exception\Auth\DeactivatedUserException::class);
        $auth->authenticateIdentity($identity, $request);
    }

    /**
     * @expectedException Skyline\Security\Exception\Auth\WrongPasswordException
     * @expectedExceptionCode 401
     */
    public function testNoEncoderSet() {
        // Will never be able to authenticate without any passwor encoder.

        $auth = new AuthenticationService($ch = new ChainUserProvider(), $pc = new PasswordEncoderChain());
        $ch->addProvider($up = new InMemoryUserProvider());
        $up->addUser( new AdvancedUser("admin", "12345", []) );

        $request = Request::create("/test");
        $identity = new Identity("admin", "12345", Identity::RELIABILITY_HTTP);
		$this->expectException(\Skyline\Security\Exception\Auth\WrongPasswordException::class);
        $auth->authenticateIdentity($identity, $request);
    }

    public function testAuthentication() {
        $auth = new AuthenticationService($ch = new ChainUserProvider(), $pc = new PasswordEncoderChain());
        $ch->addProvider($up = new InMemoryUserProvider());
        $up->addUser($user = new AdvancedUser("admin", "12345", []) );

        $pc->addEncoder(new PlaintextPasswordEncoder());

        $request = Request::create("/test");
        $identity = new Identity("admin", "12345", Identity::RELIABILITY_HTTP);

        $u = $auth->authenticateIdentity($identity, $request);

        $this->assertSame($user, $u);
    }
}
