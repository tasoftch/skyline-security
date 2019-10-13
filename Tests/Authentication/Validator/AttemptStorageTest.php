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
 * AttemptStorageTest.php
 * skyline-security
 *
 * Created on 2019-10-13 16:30 by thomas
 */

use Skyline\Security\Authentication\Validator\Attempt;
use Skyline\Security\Authentication\Validator\Storage\AttemptStorage;
use PHPUnit\Framework\TestCase;

class AttemptStorageTest extends TestCase
{
    public function testAttemptStorage() {
        $storage = new AttemptStorage(__DIR__ . "/attempt.sqlite", "admin", "12345");
        $this->assertFileNotExists(__DIR__ . "/attempt.sqlite");

        $storage->setAttempt(new Attempt("test",$dd = new DateTime(), 1));
        $this->assertFileExists(__DIR__ . "/attempt.sqlite");

        $a = $storage->getAttempt("test");
        $this->assertInstanceOf(Attempt::class, $a);

        $dd = new DateTime($dd->format("Y-m-d G:i:s"));

        $this->assertEquals($dd, $a->getDate());
        $this->assertEquals(1, $a->getTrials());

        $this->assertNull($storage->getAttempt("hehe"));

        $storage->clearAttempts(3);

        $a = $storage->getAttempt("test");
        $this->assertInstanceOf(Attempt::class, $a);

        sleep(3);
        $storage->clearAttempts(2);
        $this->assertNull($storage->getAttempt("test"));



        unlink(__DIR__ . "/attempt.sqlite");
    }
}
