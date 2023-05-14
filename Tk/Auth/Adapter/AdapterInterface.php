<?php
namespace Tk\Auth\Adapter;

use Tk\Auth\Result;
use Tk\Traits\SystemTrait;

abstract class AdapterInterface
{
    use SystemTrait;

    /**
     * Perform an authentication attempt
     */
    public abstract function authenticate(): Result;

}