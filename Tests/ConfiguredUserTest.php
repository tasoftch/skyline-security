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
 * ConfiguredUserTest.php
 * skyline-security
 *
 * Created on 2019-10-13 13:22 by thomas
 */

namespace Skyline\Security\User;

use PHPUnit\Framework\TestCase;

class ConfiguredUserTest extends TestCase
{
    public function testConfiguredUser() {
        $user = new ConfiguredUser([
            ConfiguredUser::USERNAME_KEY => 'admin',
            ConfiguredUser::CREDENTIALS_KEY => 'test'
        ]);

        $this->assertEquals("admin", $user->getUsername());
        $this->assertEquals("test", $user->getCredentials());
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testInvalidConfiguration() {
		$this->expectException(\InvalidArgumentException::class);
        $user = new ConfiguredUser([
            // ConfiguredUser::USERNAME_KEY => 'admin',
            ConfiguredUser::CREDENTIALS_KEY => 'test'
        ]);
    }
}
