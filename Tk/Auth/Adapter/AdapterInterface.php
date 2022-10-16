<?php
namespace Tk\Auth\Adapter;

use Tk\Auth\Result;
use Tk\Traits\SystemTrait;

/**
 * @author Tropotek <http://www.tropotek.com/>
 */
abstract class AdapterInterface
{
    use SystemTrait;

    /**
     * If set then the password to be compared can be hashed
     * using a user configurable hashing function
     * Eg: ->setOnHash(function (string $password, $data = null) {  });
     *
     * @var callable
     */
    protected $onHash = null;


    /**
     * Perform an authentication attempt
     */
    public abstract function authenticate(): Result;

    /**
     * If a hash function is set then that is used to hash a password.
     */
    public function setOnHash(callable $callable): AdapterInterface
    {
        $this->onHash = $callable;
        return $this;
    }

    protected function getOnHash(): callable
    {
        return $this->onHash;
    }

}