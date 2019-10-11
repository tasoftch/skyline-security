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
 * AdvancedUserTestTest.php
 * skyline-security
 *
 * Created on 2019-10-10 16:44 by thomas
 */

use PHPUnit\Framework\TestCase;
use Skyline\Security\Role\RoleInterface;
use Skyline\Security\User\AdvancedUser;

class AdvancedUserTestTest extends TestCase
{
    public function testUser() {
        $user = new AdvancedUser("hello", "12345", [RoleInterface::ROLE_STANDARD_USER], 35);
        $this->assertEquals("hello", $user->getUsername());
        $this->assertEquals("12345", $user->getCredentials());
        $this->assertEquals([ RoleInterface::ROLE_STANDARD_USER ], $user->getRoles());

        $this->assertEquals(35, $user->getOptions());

        $this->assertTrue($user->eraseCredentials());
        $this->assertEquals("", $user->getCredentials());

        $this->assertFalse($user->hasRole( RoleInterface::ROLE_ROOT ));
        $this->assertTrue($user->hasRole( RoleInterface::ROLE_STANDARD_USER ));

    }
}
