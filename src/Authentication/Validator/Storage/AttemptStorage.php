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

namespace Skyline\Security\Authentication\Validator\Storage;


use DateTime;
use InvalidArgumentException;
use Skyline\Security\Authentication\Validator\Attempt;

class AttemptStorage extends SQLiteStorage
{
    /** @var string */
    private $tableName;

    public function __construct(string $filename, string $tableName = 'ATTEMPT', $userName = NULL, $password = NULL)
    {
        parent::__construct($filename, $userName, $password);
        $this->tableName = $tableName;
    }

    /**
     * @return string
     */
    public function getTableName(): string
    {
        return $this->tableName;
    }

    protected function initializeStorage()
    {
        $tn = $this->getTableName();
        $this->createAttemptTable($tn);
    }

    protected function createAttemptTable($tableName) {
        $this->getPDO()->exec("CREATE TABLE IF NOT EXISTS $tableName (
    hash TEXT NOT NULL UNIQUE ,
    date date NOT NULL,
    data TEXT DEFAULT NULL
);");
    }

    protected function checkStorage()
    {
        parent::checkStorage();
        try {
            $tn = $this->getTableName();
            $result = @$this->getPDO()->query("SELECT 1 FROM $tn LIMIT 1");
            if($result !== false)
                $this->createAttemptTable($tn);
        } catch (\PDOException $exception) {
            $this->createAttemptTable($tn);
        }

        return;
    }


    public function set($hash, $name, $value)
    {
        throw new InvalidArgumentException("Do not use [AttemptStorage set] directly. Use setAttempt instead");
    }

    public function get($hash, $name)
    {
        throw new InvalidArgumentException("Do not use [AttemptStorage get] directly. Use getAttempt instead");
    }

    public function clear($hash, $name)
    {
        throw new InvalidArgumentException("Do not use [AttemptStorage clear] directly. Use clearAttempts instead");
    }

    /**
     * Stores an attempt
     *
     * @param Attempt $attempt
     */
    public function setAttempt(Attempt $attempt) {
        $this->checkStorage();
        $tn = $this->getTableName();

        $hash = $this->getPDO()->quote($attempt->getHash());
        $date = $this->getPDO()->quote($attempt->getDate()->format("Y-m-d G:i:s"));
        $attempt = $this->getPDO()->quote( serialize($attempt) );

        $this->getPDO()->exec("DELETE FROM $tn WHERE hash = $hash");
        $this->getPDO()->exec("INSERT INTO $tn (hash, date, data) VALUES ( $hash, $date, $attempt )");
    }

    /**
     * Fetches an attempt
     *
     * @param $hash
     * @return Attempt
     */
    public function getAttempt($hash):?Attempt {
        $this->checkStorage();
        $tn = $this->getTableName();

        $hash = $this->getPDO()->quote($hash);
        $attempt = $this->getPDO()->query("SELECT data FROM $tn WHERE hash = $hash")->fetch(\PDO::FETCH_ASSOC)["data"] ?? NULL;
        if($attempt)
            return unserialize( $attempt );
        return NULL;
    }

    /**
     * Clears all attempts older than $olderThan seconds
     * @param int $olderThan
     */
    public function clearAttempts(int $olderThan) {
        $this->checkStorage();
        $tn = $this->getTableName();

        $date = new DateTime("now-{$olderThan}seconds");
        $date = $this->getPDO()->quote( $date->format("Y-m-d G:i:s") );
        $this->getPDO()->exec("DELETE FROM $tn WHERE date <= $date");
    }

    public function clearAttempt(Attempt $attempt) {
        $this->checkStorage();
        $tn = $this->getTableName();

        $hash = $this->getPDO()->quote($attempt->getHash());
        $this->getPDO()->exec("DELETE FROM $tn WHERE hash = $hash");
    }
}