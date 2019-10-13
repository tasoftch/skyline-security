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
 * SameSQLitePDOTest.php
 * skyline-security
 *
 * Created on 2019-10-13 17:50 by thomas
 */

use PHPUnit\Framework\TestCase;
use Skyline\Security\Authentication\Validator\CallbackAttemptValidator;
use Skyline\Security\Authentication\Validator\Factory\BruteForceByClientIPValidatorFactory;
use Skyline\Security\Authentication\Validator\Factory\BruteForceByServerURIValidatorFactory;
use Skyline\Security\Exception\FailedAttemptException;
use Skyline\Security\Identity\Identity;
use Skyline\Security\User\User;
use Symfony\Component\HttpFoundation\Request;

class BruteForceValidatorTest extends TestCase
{
    /**
     * @expectedException Skyline\Security\Exception\FailedAttemptException
     */
    public function testFailures() {
        $file = __DIR__ . "/security.sqlite";
        if(file_exists($file))
            unlink($file);


        $validators = [
            (new BruteForceByClientIPValidatorFactory($file, 3, 100))->getValidators()[0],
            (new BruteForceByServerURIValidatorFactory($file, 3, 1))->getValidators()[0]
        ];

        $identity = new Identity("admin", "121212", 200);

        $request = Request::create("/test", "POST", [], [], [], ["REMOTE_ADDR" => '201.66.78.12']);

        /** @var CallbackAttemptValidator $val1 */
        foreach($validators as $val1) {
            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $val1->grantAfterAuthentication($identity, NULL, $request);

            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $val1->grantAfterAuthentication($identity, NULL, $request);

            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $val1->grantAfterAuthentication($identity, NULL, $request);

            $val1->grantBeforeAuthentication($identity, $request);
        }
    }

    /**
     *
     */
    public function testSuccess() {
        $file = __DIR__ . "/security.sqlite";
        if(file_exists($file))
            unlink($file);


        $validators = [
            (new BruteForceByClientIPValidatorFactory($file, 3, 100))->getValidators()[0],
            (new BruteForceByServerURIValidatorFactory($file, 3, 1))->getValidators()[0]
        ];

        $identity = new Identity("admin", "121212", 200);
        $request = Request::create("/test", "POST", [], [], [], ["REMOTE_ADDR" => '201.66.78.12']);

        /** @var CallbackAttemptValidator $val1 */
        foreach($validators as $val1) {
            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $val1->grantAfterAuthentication($identity, NULL, $request);

            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $val1->grantAfterAuthentication($identity, NULL, $request);

            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $user = new User("admin", "121212");

            // Must reset falied attempts.
            $val1->grantAfterAuthentication($identity, $user, $request);

            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $val1->grantAfterAuthentication($identity, NULL, $request);

            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $val1->grantAfterAuthentication($identity, NULL, $request);
        }
    }

    /**
     *
     */
    public function testAfterBlockedTime() {
        $file = __DIR__ . "/security.sqlite";
        if(file_exists($file))
            unlink($file);


        $validators = [
            (new BruteForceByClientIPValidatorFactory($file, 3, 1))->getValidators()[0],
            (new BruteForceByServerURIValidatorFactory($file, 3, 1))->getValidators()[0]
        ];

        $identity = new Identity("admin", "121212", 200);
        $request = Request::create("/test", "POST", [], [], [], ["REMOTE_ADDR" => '201.66.78.12']);

        /** @var CallbackAttemptValidator $val1 */
        foreach($validators as $val1) {
            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $val1->grantAfterAuthentication($identity, NULL, $request);

            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $val1->grantAfterAuthentication($identity, NULL, $request);

            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $val1->grantAfterAuthentication($identity, NULL, $request);

            try {
                $val1->grantBeforeAuthentication($identity, $request);
            } catch (FailedAttemptException $exception) {
            }

            $this->assertInstanceOf(FailedAttemptException::class, $exception);

            usleep(1200000);

            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $val1->grantAfterAuthentication($identity, NULL, $request);

            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $val1->grantAfterAuthentication($identity, NULL, $request);

            $this->assertTrue($val1->grantBeforeAuthentication($identity, $request));
            $val1->grantAfterAuthentication($identity, NULL, $request);

            try {
                $val1->grantBeforeAuthentication($identity, $request);
            } catch (FailedAttemptException $exception) {
            }

            $this->assertInstanceOf(FailedAttemptException::class, $exception);
        }
    }
}
