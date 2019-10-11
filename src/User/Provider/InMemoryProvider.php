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


use Skyline\Security\Exception\UserNotFoundException;
use Skyline\Security\Identity\Token\TokenInterface;
use Skyline\Security\User\UserInterface;

class InMemoryProvider implements UserProviderInterface, UserProviderAwareInterface
{
    /** @var array */
    private $users;

    public function loadUserWithToken(TokenInterface $token): ?UserInterface
    {
        $user = $this->users[ $token->getToken() ] ?? NULL;
        if(!$user) {
            $e = new UserNotFoundException("User %s not found", 401, NULL, $token->getToken());
            $e->setToken($token);
            throw $e;
        }
        return $user;
    }

    /**
     * @return array
     */
    public function getUsers(): array
    {
        return array_values($this->users);
    }

    public function addUser(UserInterface $user) {
        $this->users[ $user->getUsername() ] = $user;
    }

    public function removeUserNamed(string $username) {
        if(isset($this->users[$username]))
            unset($this->users[$username]);
    }

    public function removeUser(UserInterface $user) {
        $this->removeUserNamed($user->getUsername());
    }

    public function removeAllUsers() {
        $this->users = [];
    }

    public function setUsers(iterable $users) {
        $this->removeAllUsers();
        $this->addUsers($users);
    }

    public function addUsers(iterable $users) {
        foreach($users as $u)
            $this->addUser($u);
    }

    public function getAllUsernames(): array
    {
        return array_keys($this->users);
    }
}