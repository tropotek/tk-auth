<?php
namespace Tk\Event;



/**
 * @author Michael Mifsud <info@tropotek.com>
 * @see http://www.tropotek.com/
 * @license Copyright 2016 Michael Mifsud
 */
class AuthAdapterEvent extends Event
{

    /**
     * @var \Tk\Auth\Result|null
     */
    private $result = null;

    /**
     * @var \Tk\Auth\Adapter\Iface
     */
    private $adapter = null;


    /**
     * __construct
     *
     * @param \Tk\Auth\Adapter\Iface $adapter
     * @param array $data Login data from a login interface (ie: form, openId, etc)
     */
    public function __construct($adapter, $data = [])
    {
        $this->adapter = $adapter;
        $this->replace($data);
    }

    /**
     * @return \Tk\Auth
     * @deprecated
     */
    public function getAuth()
    {
        return \Tk\Config::getInstance()->get('auth');
    }

    /**
     * Set the result object
     *
     * @param \Tk\Auth\Result $result
     * @return $this
     */
    public function setResult($result) 
    {
        $this->result = $result;
        return $this;
    }

    /**
     * @return \Tk\Auth\Result|null
     */
    public function getResult()
    {
        return $this->result;
    }

    /**
     * @return \Tk\Auth\Adapter\Iface
     */
    public function getAdapter()
    {
        return $this->adapter;
    }
    
}