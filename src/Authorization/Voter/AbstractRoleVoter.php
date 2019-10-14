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

namespace Skyline\Security\Authorization\Voter;


use Skyline\Security\User\UserInterface;

abstract class AbstractRoleVoter implements VoterInterface
{
    private $requiresAllRoles = true;

    /**
     * AbstractRoleVoter constructor.
     * @param bool $requiresAllRoles
     */
    public function __construct(bool $requiresAllRoles = true)
    {
        $this->requiresAllRoles = $requiresAllRoles;
    }


    public function grantAccess(UserInterface $user, $object, array $attributes): int
    {
        $passed = false;

        if($this->requiresAllRoles()) {
            foreach($attributes as $attribute) {
                $passed = true;

                foreach($user->getRoles() as $role) {
                    if($this->compareRoles($role, $attribute))
                        continue 2;
                }
                return self::ACCESS_DENIED;
            }
            return $passed ? self::ACCESS_GRANT : self::ACCESS_ABSTAIN;
        } else {
            foreach($user->getRoles() as $role) {
                foreach($attributes as $attribute) {
                    $passed = true;
                    if($this->compareRoles($role, $attribute))
                        return self::ACCESS_GRANT;
                }
            }
            return $passed ? self::ACCESS_DENIED : self::ACCESS_ABSTAIN;
        }
    }



    /**
     * Called to compare all required roles against owned by the user.
     * This method should return true, if the owned role satisfies the required one.
     *
     * @param $ownedRole
     * @param $requiredRole
     * @return bool
     */
    abstract protected function compareRoles($ownedRole, $requiredRole): bool;

    /**
     * @return bool
     */
    public function requiresAllRoles(): bool
    {
        return $this->requiresAllRoles;
    }

    /**
     * @param bool $requiresAllRoles
     */
    public function setRequiresAllRoles(bool $requiresAllRoles): void
    {
        $this->requiresAllRoles = $requiresAllRoles;
    }
}