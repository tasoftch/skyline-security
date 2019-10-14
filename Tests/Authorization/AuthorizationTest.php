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
 * AuthorizationTest.php
 * skyline-security
 *
 * Created on 2019-10-14 16:46 by thomas
 */

use PHPUnit\Framework\TestCase;
use Skyline\Security\Authorization\AuthorizationService;
use Skyline\Security\Authorization\Voter\CallbackVoter;
use Skyline\Security\Authorization\Voter\RoleAdminVoter;
use Skyline\Security\Authorization\Voter\RoleChainVoter;
use Skyline\Security\Authorization\Voter\RoleRootVoter;
use Skyline\Security\Authorization\Voter\RoleVoter;
use Skyline\Security\Role\RoleInterface;
use Skyline\Security\User\User;

class AuthorizationTest extends TestCase
{
    public function testRoleVoter() {
        $service = new AuthorizationService();

        $service->addVoter($voter = new RoleVoter(true));

        $user = new User("", "", [
            "MY_ROLE",
            "YOUR_ROLE",
            "HIS_ROLE"
        ]);

        $this->assertTrue($service->grantAccess($user, NULL, ["MY_ROLE", "YOUR_ROLE"]));
        $this->assertFalse($service->grantAccess($user, NULL, []));

        $this->assertTrue($service->grantAccess($user, NULL, ["MY_ROLE", "YOUR_ROLE", "HIS_ROLE"]));
        $this->assertFalse($service->grantAccess($user, NULL, ["OUR_ROLE"]));



        $service->removeVoter($voter);

        // Without a voter, access must be denied.
        $this->assertFalse($service->grantAccess($user, NULL, ["ALL_ROLES"]));
        $this->assertFalse($service->grantAccess($user, NULL, [RoleInterface::ROLE_ROOT]));



        $service->addVoter(new RoleVoter(false));

        $this->assertTrue($service->grantAccess($user, NULL, ["MY_ROLE", "YOUR_ROLE"]));
        $this->assertFalse($service->grantAccess($user, NULL, []));

        $this->assertTrue($service->grantAccess($user, NULL, ["MY_ROLE", "YOUR_ROLE", "HIS_ROLE"]));
        $this->assertFalse($service->grantAccess($user, NULL, ["OUR_ROLE"]));

        $this->assertFalse($service->grantAccess($user, NULL, ["OUR_ROLE", "THEIR_ROLE"]));

        $this->assertTrue($service->grantAccess($user, NULL, ["OUR_ROLE", "YOUR_ROLE", "THEIR_ROLE"]));
    }

    public function testCallbackVoter() {
        $service = new AuthorizationService([], AuthorizationService::STRATEGY_CONSENSUS);

        $voter = new CallbackVoter(function($user, $object, $attributes) {
            return $object === $this;
        });

        $service->addVoter($voter);

        $user = new User("", "", [
            "MY_ROLE",
            "YOUR_ROLE",
            "HIS_ROLE"
        ]);

        $this->assertFalse($service->grantAccess($user, NULL, [1,2,3]));
        $this->assertTrue($service->grantAccess($user, $this, [1,2,3]));
    }


    public function testConsensiousService() {
        $service = new AuthorizationService([], AuthorizationService::STRATEGY_CONSENSUS);
        $service->addVoter( new CallbackVoter(function($user, $object, $attributes) {
            return $object === ($attributes[0] ?? NULL) ? CallbackVoter::ACCESS_GRANT : CallbackVoter::ACCESS_DENIED;
        }));
        $service->addVoter( new CallbackVoter(function($user, $object, $attributes) {
            return $object === ($attributes[1] ?? NULL) ? CallbackVoter::ACCESS_GRANT : CallbackVoter::ACCESS_DENIED;
        }));

        $service->addVoter(new RoleAdminVoter());
        $service->addVoter(new RoleRootVoter());

        $user = new User("", "", [
            "MY_ROLE",
            "YOUR_ROLE",
            "HIS_ROLE"
        ]);

        // 0 == 0 => false
        $this->assertFalse($service->grantAccess($user, NULL, [56, 7]));

        // grant > denied => true
        $this->assertTrue($service->grantAccess($user, $this, [$this, $this]));

        $user = new User("", "", [
            RoleInterface::ROLE_ADMINISTRATOR,
            "YOUR_ROLE",
            "HIS_ROLE"
        ]);

        // callbacks are false, onyl admin is true
        $this->assertFalse($service->grantAccess($user, $this));
        $this->assertTrue($service->grantAccess($user, $this, [$this]));

        $user = new User("", "", [
            RoleInterface::ROLE_ADMINISTRATOR,
            RoleInterface::ROLE_ROOT,
            "HIS_ROLE"
        ]);

        $this->assertTrue($service->grantAccess($user, NULL));
        $this->assertTrue($service->grantAccess($user, $this));
    }

    public function testUnianimous() {
        $service = new AuthorizationService([], AuthorizationService::STRATEGY_UNANIMOUS);
        $service->addVoter( new CallbackVoter(function($user, $object, $attributes) {
            return $object === ($attributes[0] ?? 12) ? CallbackVoter::ACCESS_GRANT : CallbackVoter::ACCESS_DENIED;
        }));
        $service->addVoter( new CallbackVoter(function($user, $object, $attributes) {
            return $object === ($attributes[1] ?? 12) ? CallbackVoter::ACCESS_GRANT : CallbackVoter::ACCESS_DENIED;
        }));

        $service->addVoter(new RoleAdminVoter());
        $service->addVoter(new RoleRootVoter());

        $user = new User("", "", [
            "MY_ROLE",
            "YOUR_ROLE",
            "HIS_ROLE"
        ]);

        // 0 == 0 => false
        $this->assertFalse($service->grantAccess($user, NULL, [56, 7]));

        // grant > denied => true
        $this->assertFalse($service->grantAccess($user, $this, [$this, $this]));

        $user = new User("", "", [
            RoleInterface::ROLE_ADMINISTRATOR,
            "YOUR_ROLE",
            "HIS_ROLE"
        ]);

        // callbacks are false, onyl admin is true
        $this->assertFalse($service->grantAccess($user, $this));
        $this->assertFalse($service->grantAccess($user, $this, [$this]));

        $user = new User("", "", [
            RoleInterface::ROLE_ADMINISTRATOR,
            RoleInterface::ROLE_ROOT,
            "HIS_ROLE"
        ]);

        $this->assertFalse($service->grantAccess($user, NULL));
        $this->assertFalse($service->grantAccess($user, $this));

        $this->assertTrue($service->grantAccess($user, $this, [$this, $this]));
    }

    public function testRoleChainVoter() {
        $service = new AuthorizationService();

        $service->addVoter($voter = new RoleChainVoter(true));

        $user = new User("", "", [
            RoleInterface::ROLE_ROOT,
            "MY.SPECIAL.ROLE",
            "MY.OTHER"
        ]);

        $this->assertFalse($service->grantAccess($user, $this, [
            RoleInterface::ROLE_ADMINISTRATOR
        ]));

        $this->assertTrue($service->grantAccess($user, $this, [
            RoleInterface::ROLE_ROOT
        ]));

        $this->assertTrue($service->grantAccess($user, $this, [
            "SKYLINE.ROOT.EDIT"
        ]));

        $this->assertTrue($service->grantAccess($user, $this, [
            "SKYLINE.ROOT",
            "MY.OTHER.ROLE"
        ]));

        $this->assertTrue($service->grantAccess($user, $this, [
            "SKYLINE.ROOT",
            "MY.SPECIAL.ROLE.SUB.CHILD"
        ]));

        $this->assertTrue($service->grantAccess($user, $this, [
            "SKYLINE.ROOT.EDITOR.TRANSLATOR",
            "MY.OTHER"
        ]));

        $this->assertFalse($service->grantAccess($user, $this, [
            "SKYLINE.ROOT.EDITOR.TRANSLATOR",
            "MY"
        ]));
    }
}
