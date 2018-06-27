<?php
namespace Tk\Event;


/**
 * @author Michael Mifsud <info@tropotek.com>
 * @see http://www.tropotek.com/
 * @license Copyright 2016 Michael Mifsud
 */
class AuthEvent extends Event
{

    /**
     * @var \Tk\Auth\Adapter\Iface
     */
    private $adapter = null;

    /**
     * @var \Tk\Auth\Result
     */
    private $result = null;

    /**
     * The redirect url for login/logout events
     * @var \Tk\Uri
     */
    private $redirect = null;



    /**
     * __construct
     *
     * @param array $data  Login data from a login interface (ie: form, openId, etc)
     */
    public function __construct($data = [])
    {
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
     * @return \Tk\Auth\Result
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

    /**
     * @param \Tk\Auth\Adapter\Iface $adapter
     * @return $this
     */
    public function setAdapter($adapter)
    {
        $this->adapter = $adapter;
        return $this;
    }

    /**
     * return the url to redirect to after logout.
     *
     * @param \Tk\Uri|null $redirect
     * @return $this
     */
    public function setRedirect(\Tk\Uri $redirect = null)
    {
        $this->redirect = $redirect;
        return $this;
    }

    /**
     * @return \Tk\Uri
     */
    public function getRedirect()
    {
        return $this->redirect;
    }
    
}