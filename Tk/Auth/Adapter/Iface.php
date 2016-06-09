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
 * @package Tk\Auth\Adapter
 */
abstract class Iface extends \Tk\Collection
{

    /**
     * The hash function to use for this adapter
     * @var callable
     */
    //private $hashFunction = '';

    /**
     * Performs an authentication attempt
     *
     * @return \Tk\Auth\Result
     * @throws \Tk\Auth\Exception If authentication cannot be performed
     */
    abstract public function authenticate();

    
    
    // TODO: All hash methods are to be removed from adapters and that responsability is to reside externally in the User object or elsewhere
    
    
    /**
     * Name of selected hashing algorithm (e.g. "md5", "sha256", "haval160,4", etc..)
     *
     * Or alternatively a callable object to execute
     * 
     * To find out what algorithms are available:
     *
     * <code>
     * $data = "hello";
     * foreach (hash_algos() as $v) {
     *     $r = hash($v, $data, false);
     *     printf("%-12s %3d %s\n", $v, strlen($r), $r);
     * }
     * </code>
     *
     * @param string|callable $hashFunction
     * @return Iface
     */
//    public function setHashFunction($hashFunction)
//    {
//        $this->hashFunction = $hashFunction;
//        return $this;
//    }
//    
//    public function getHashFunction()
//    {
//        return $this->hashFunction;
//    }

    /**
     * Execute the supplied hash function
     *
     * @param $str
     * @return mixed
     */
//    protected function hash($str)
//    {
//        if (is_callable($this->getHashFunction())) {
//            $str = call_user_func_array($this->getHashFunction(), array($str));
//        }
//        return $str;
//    }
}