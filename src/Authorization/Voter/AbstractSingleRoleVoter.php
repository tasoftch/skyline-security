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


use Skyline\Security\Role\RoleInterface;
use Skyline\Security\User\UserInterface;

abstract class AbstractSingleRoleVoter extends AbstractRoleVoter
{
    public function requiresAllRoles(): bool
    {
        // Grants access, if the user has the required single role
        return false;
    }

    public function grantAccess(UserInterface $user, $object, array $attributes): int
    {
        $singleRole = $this->getSingleRole();
        foreach($user->getRoles() as $role) {
            if($this->compareRoles($role, $singleRole))
                return self::ACCESS_GRANT;
        }
        return self::ACCESS_DENIED;
    }


    protected function compareRoles($ownedRole, $requiredRole): bool
    {
        if($ownedRole instanceof RoleInterface)
            $ownedRole = $ownedRole->getRole();

        $requiredRole = $this->getSingleRole();

        if($requiredRole instanceof RoleInterface)
            $requiredRole = $requiredRole->getRole();

        if($ownedRole == $requiredRole)
            return true;
        return false;
    }

    /**
     * Gets the requested single tole
     *
     * @return string|RoleInterface
     */
    abstract protected function getSingleRole();
}