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
 * AutologoutTest.php
 * skyline-security
 *
 * Created on 2019-10-13 18:46 by thomas
 */

use PHPUnit\Framework\TestCase;
use Skyline\Security\Authentication\Validator\AbstractAttemptValidator;
use Skyline\Security\Authentication\Validator\Factory\AutoLogoutValidatorFactory;
use Skyline\Security\Exception\AutoLogoutException;
use Skyline\Security\Identity\Identity;
use Symfony\Component\HttpFoundation\Request;

class AutologoutTest extends TestCase
{
    /**
     * @expectedException Skyline\Security\Exception\AutoLogoutException
     */
    public function testAutologout() {
        $file = __DIR__ . "/security.sqlite";
        if(file_exists($file))
            unlink($file);

        /** @var AbstractAttemptValidator $val1 */
        $val1 = (new AutoLogoutValidatorFactory($file, 3))->getValidators()[0];

        $identity = new Identity("admin", "121212", 200);
        $request = Request::create("/test", "POST", [], [], [], ["REMOTE_ADDR" => '201.66.78.12']);

        $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
        $val1->grantAfterAuthentication($identity, NULL, $request);

        sleep(1);
        $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));

        sleep(1);
        $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));

        sleep(2);
		$this->expectException(AutoLogoutException::class);
        $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
    }
}
