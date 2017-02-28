<?php
namespace Tk\Event;

use Tk\EventDispatcher\Event;
use Tk\Auth;


/**
 * Class AuthEvent
 *
 * @author Michael Mifsud <info@tropotek.com>
 * @link http://www.tropotek.com/
 * @license Copyright 2016 Michael Mifsud
 */
class AuthEvent extends Event
{
    /**
     * @var Auth
     */
    private $auth = null;

    /**
     * @var \Tk\Auth\Result
     */
    private $result = null;

    /**
     * The redirect url for login/logout events
     *
     * @var \Tk\Uri
     */
    private $redirect = null;



    /**
     * __construct
     * 
     * @param Auth $auth
     * @param array $data  Login data from a login interface (ie: form, openId, etc)
     */
    public function __construct($auth, $data = [])
    {
        parent::__construct($data);
        $this->auth = $auth;
    }

    /**
     * @return Auth
     */
    public function getAuth()
    {
        return $this->auth;
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