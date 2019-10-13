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


class SQLiteStorage extends AbstractFileStorage
{
    private $userName;
    private $password;
    /** @var \PDO */
    private $PDO;

    public function __construct(string $filename, $userName = NULL, $password = NULL)
    {
        parent::__construct($filename);
        $this->userName = $userName;
        $this->password = $password;
    }

    protected function getPDO(): \PDO {
        if(!$this->PDO) {
            $this->PDO = new \PDO("sqlite:".$this->getFilename(), $this->userName, $this->password);
            $this->PDO->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        }

        return $this->PDO;
    }


    protected function initializeStorage()
    {
        $this->getPDO()->exec("CREATE TABLE VAL_STORAGE (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT DEFAULT NULL
);");
    }

    public function set($hash, $name, $value)
    {
        $this->checkStorage();
        $hash = $this->PDO->quote($hash);
        $name = $this->PDO->quote($name);
        $value = $this->PDO->quote($value);

        if($this->PDO->query("SELECT count(name) as CNT FROM VAL_STORAGE WHERE hash = $hash AND name = $name")->fetch(\PDO::FETCH_ASSOC)["CNT"] ?? 0) {
            $this->PDO->exec("UPDATE VAL_STORAGE SET value = $value WHERE hash = $hash AND name = $name");
        } else {
            $this->PDO->exec("INSERT INTO VAL_STORAGE (hash, name, value) VALUES ($hash, $name, $value)");
        }
    }

    public function get($hash, $name)
    {
        $this->checkStorage();

        $hash = $this->PDO->quote($hash);
        $name = $this->PDO->quote($name);

        return $this->PDO->query("SELECT value FROM VAL_STORAGE WHERE hash = $hash AND name = $name LIMIT 1")->fetch(\PDO::FETCH_ASSOC)["value"] ?? NULL;
    }

    public function clear($hash, $name)
    {
        $this->checkStorage();
        $hash = $this->PDO->quote($hash);
        if($name) {
            $name = $this->PDO->quote($name);
            $this->PDO->exec("DELETE FROM VAL_STORAGE WHERE hash = $hash AND name = $name");
        } else {
            $this->PDO->exec("DELETE FROM VAL_STORAGE WHERE hash = $hash");
        }
    }
}