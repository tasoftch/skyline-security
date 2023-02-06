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

namespace Skyline\Security\Authentication\Validator;

/**
 * An attempt is a successful or falied authentication request.
 * @package Skyline\Security\Authentication\Validator
 */
class Attempt implements \Serializable
{
    /** @var string */
    private $hash;
    /** @var \DateTime */
    private $date;
    /** @var int */
    private $trials;

    /**
     * Attempt constructor.
     * @param string $hash
     * @param \DateTime $date
     * @param int $trials
     */
    public function __construct(string $hash, \DateTime $date, int $trials)
    {
        $this->hash = $hash;
        $this->date = $date;
        $this->trials = $trials;
    }

    /**
     * @return string
     */
    public function getHash(): string
    {
        return $this->hash;
    }

    /**
     * @return \DateTime
     */
    public function getDate(): \DateTime
    {
        return $this->date;
    }

    /**
     * @return int
     */
    public function getTrials(): int
    {
        return $this->trials;
    }

    public function serialize()
    {
        return serialize($this->__serialize());
    }

    public function unserialize($serialized)
    {
        $this->__unserialize( unserialize($serialized) );
    }

	public function __serialize(): array
	{
		return [
			$this->hash,
			$this->trials,
			$this->date->format("Y-m-d G:i:s")
		];
	}

	public function __unserialize(array $data): void
	{
		list($this->hash, $this->trials, $date) = $data;
		$this->date = new \DateTime($date);
	}
}