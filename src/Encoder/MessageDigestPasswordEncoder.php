<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Skyline\Security\Encoder;


use LogicException;

/**
 * MessageDigestPasswordEncoder uses a message digest algorithm.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class MessageDigestPasswordEncoder extends AbstractPasswordEncoder
{
    const OPTION_ALGORITHM_KEY = 'algorithm';
    const OPTION_BASE64_KEY = 'encodeHashAsBase64';
    const OPTION_ITERATION_COUNT_KEY = 'iterations';

    private $algorithm;
    private $encodeHashAsBase64;
    private $iterations;

    /**
     * @param string $algorithm          The digest algorithm to use
     * @param bool   $encodeHashAsBase64 Whether to base64 encode the password hash
     * @param int    $iterations         The number of iterations to use to stretch the password hash
     */
    public function __construct(string $algorithm = 'sha512', bool $encodeHashAsBase64 = true, int $iterations = 5000)
    {
        $this->algorithm = $algorithm;
        $this->encodeHashAsBase64 = $encodeHashAsBase64;
        $this->iterations = $iterations;
    }

    /**
     * {@inheritdoc}
     */
    public function encodePassword(string $plain, array &$options = []): string
    {
        $this->checkPasswordTooLong($plain);

        if (!in_array($this->algorithm, hash_algos(), true)) {
            throw new LogicException(sprintf('The algorithm "%s" is not supported.', $this->algorithm));
        }

        $algorithm = $options[static::OPTION_ALGORITHM_KEY] ?? $this->algorithm;
        $iterations = $options[static::OPTION_ITERATION_COUNT_KEY] ?? $this->iterations;
        $base64 = $options[static::OPTION_BASE64_KEY] ?? $this->encodeHashAsBase64;

        $salt = $this->getSalt($options);

        $salted = $this->mergePasswordAndSalt($plain, $salt);
        $digest = hash($algorithm, $salted, true);

        // "stretch" hash
        for ($i = 1; $i < $iterations; ++$i) {
            $digest = hash($algorithm, $digest.$salted, true);
        }

        return $base64 ? base64_encode($digest) : bin2hex($digest);
    }
}
