<?php
/*
 * @author Michael Mifsud <info@tropotek.com>
 * @link http://www.tropotek.com/
 * @license Copyright 2007 Michael Mifsud
 */
namespace Tk\Auth\Adapter;

/**
 * Adapter Interface
 * 
 *
 */
abstract class Iface extends \Tk\Collection
{

    /**
     * Performs an authentication attempt
     *
     * @return \Tk\Auth\Result
     * @throws \Tk\Auth\Exception If authentication cannot be performed
     */
    public abstract function authenticate();


}