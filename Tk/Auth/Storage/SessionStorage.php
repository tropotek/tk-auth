<?php
/*
 * @author Michael Mifsud <info@tropotek.com>
 * @see http://www.tropotek.com/
 * @license Copyright 2007 Michael Mifsud
 */
namespace Tk\Auth\Storage;


/**
 *
 *
 *
 */
class SessionStorage implements Iface
{
    /**
     * Default session namespace
     */
    const SID_DEFAULT = '_auth.session';

    /**
     * Session namespace
     *
     * @var mixed
     */
    protected $sid = '';

    /**
     * @var array|\ArrayAccess
     */
    protected $session = null;



    /**
     * Sets session storage options and initializes session namespace object
     *
     * @param array|\ArrayAccess $session
     * @param string  $sid
     */
    public function __construct($session, $sid = self::SID_DEFAULT)
    {
        $this->session = $session;
        $this->sid = $sid;
    }

    /**
     * Returns the session namespace for this storage object
     *
     * @return string
     */
    public function getSid()
    {
        return $this->sid;
    }

    /**
     * Get the session object
     *
     * @return array|\ArrayAccess
     */
    public function getSession()
    {
        return $this->session;
    }


    /**
     * Defined by \Tk\Auth\Storage\Iface
     *
     * @return bool
     */
    public function isEmpty()
    {
        return !isset($this->session[$this->getSid()]);
    }

    /**
     * Defined by \Tk\Auth\Storage\Iface
     *
     * @return mixed
     */
    public function read()
    {
        return $this->session[$this->getSid()];
    }

    /**
     * Defined by \Tk\Auth\Storage\Iface
     *
     * @param  mixed $contents
     * @return void
     */
    public function write($contents)
    {
        $this->session[$this->getSid()] = $contents;
    }

    /**
     * Defined by \Tk\Auth\Storage\Iface
     *
     * @return void
     */
    public function clear()
    {
        unset($this->session[$this->getSid()]);
    }

}
