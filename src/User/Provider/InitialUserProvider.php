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

namespace Skyline\Security\User\Provider;


use Skyline\Security\Exception\SecurityException;
use Skyline\Security\Role\RoleInterface;
use Skyline\Security\User\InitialUser;
use Skyline\Security\User\UserInterface;

class InitialUserProvider implements UserProviderInterface, UserProviderAwareInterface
{
    /** @var string */
    protected $username;

    /** @var string */
	protected $password;

	protected $roles = [];

    /**
     * InitialUserSource constructor.
     * @param string $username
     * @param string $password
     * @param array $roles
     */
    public function __construct(string $username, string $password, $roles = [RoleInterface::ROLE_ROOT])
    {
        if(!$username) {
            throw new SecurityException("Can not load initial user without valid username", 403);
        }

        if(!$password) {
            throw new SecurityException("Can not load initial user without valid password", 403);
        }

        $this->username = $username;
        $this->password = $password;
        $this->roles = $roles;
    }

    public function loadUserWithToken(string $token): ?UserInterface
    {
        if($token == $this->username) {
            $u = new InitialUser($this->username, $this->password, $this->roles);
            return $u;
        }
        return NULL;
    }

    public function getUsernames(): array
    {
        return [
            $this->username
        ];
    }
}