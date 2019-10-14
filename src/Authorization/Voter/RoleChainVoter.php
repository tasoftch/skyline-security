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

/**
 * Role chains are kind of nested roles, but only by name.
 * The roles are subdivided by dots.
 *
 * SKYLINE                  is a role
 * SKYLINE.ADMIN            ADMIN is a sub role of SKYLINE
 * SKYLINE.ADMIN.EDIT       EDIT is a sub role of ADMIN.
 *
 * A user with the role SKYLINE.ADMIN.EDIT gets granted, if this or sub roles of this is requested.
 * So if SKYLINE.ADMIN is requested, the voter won't grant access for role SKYLINE.ADMIN.EDIT
 *
 * @package Skyline\Security\Authorization\Voter
 */
class RoleChainVoter extends AbstractRoleVoter
{
    protected function compareRoles($ownedRole, $requiredRole): bool
    {
        if($ownedRole instanceof RoleInterface)
            $ownedRole = $ownedRole->getRole();

        if($requiredRole instanceof RoleInterface)
            $requiredRole = $requiredRole->getRole();

        return stripos($requiredRole, $ownedRole) === 0 ? true : false;
    }
}