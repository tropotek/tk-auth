<?php
/*
 * @author Michael Mifsud <info@tropotek.com>
 * @link http://www.tropotek.com/
 * @license Copyright 2007 Michael Mifsud
 */
namespace Tk\Auth\Adapter;
use Tk\Auth\Result;

/**
 * A DB table authenticator adaptor
 *
 *
 */
class DbTable extends Iface
{

    /**
     * @var string
     */
    protected $tableName = 'user';

    /**
     * @var string
     */
    protected $usernameColumn = 'username';

    /**
     * @var string
     */
    protected $passwordColumn = 'password';

    /**
     * @var \PDO
     */
    protected $db = null;



    /**
     * Constructor
     *
     * @param \PDO $db
     * @param  string $username The username of the account being authenticated
     * @param  string $password The password of the account being authenticated
     */
    public function __construct($db, $username = null, $password = null)
    {
        parent::__construct($username, $password);
        $this->db = $db;
    }

    /**
     * @return string
     */
    public function getTableName()
    {
        return $this->tableName;
    }

    /**
     * @param string $tableName
     * @return $this
     */
    public function setTableName($tableName)
    {
        $this->tableName = $tableName;
        return $this;
    }

    /**
     * @return string
     */
    public function getUsernameColumn()
    {
        return $this->usernameColumn;
    }

    /**
     * @param string $usernameColumn
     * @return $this
     */
    public function setUsernameColumn($usernameColumn)
    {
        $this->usernameColumn = $usernameColumn;
        return $this;
    }

    /**
     * @return string
     */
    public function getPasswordColumn()
    {
        return $this->passwordColumn;
    }

    /**
     * @param string $passwordColumn
     * @return $this
     */
    public function setPasswordColumn($passwordColumn)
    {
        $this->passwordColumn = $passwordColumn;
        return $this;
    }

    /**
     *
     * @return Result
     * @throws \Tk\Auth\Exception if answering the authentication query is impossible
     */
    public function authenticate()
    {
        if (!$this->getUsername() || !$this->getPassword()) {
            return Result(Result::FAILURE_CREDENTIAL_INVALID, $this->getUsername(), 'Invalid username or password.');
        }
        $sql = sprintf('SELECT * FROM %s WHERE %s = %s LIMIT 1',
            $this->db->quoteParameter($this->tableName),
            $this->db->quoteParameter($this->usernameColumn),
            $this->db->quote($this->getUsername()));
        try {
            $result = $this->db->query($sql);
            $user = $result->fetchObject();
            if ($user) {
                $passHash = \Tk\Auth::hash($this->getPassword(), $this->getHashFunction());
                if ($passHash == $user->{$this->passwordColumn}) {
                    return new Result(Result::SUCCESS, $user);
                }
            }
        } catch (\Exception $e) {
            throw new \Tk\Auth\Exception('The supplied parameters failed to produce a valid sql statement, please check table and column names for validity.', 0, $e);
        }
        return new Result(Result::FAILURE_IDENTITY_NOT_FOUND, $this->getUsername(), 'Invalid username or password.');
    }


}
