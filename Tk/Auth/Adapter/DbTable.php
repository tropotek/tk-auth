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
    protected $tableName = '';

    /**
     * @var string
     */
    protected $usernameColumn = '';

    /**
     * @var string
     */
    protected $passwordColumn = '';

    /**
     * @var \Tk\Db\Pdo
     */
    protected $db = null;


    /**
     * Constructor
     * 
     * @param \tk\Db\Pdo $db
     * @param string $tableName
     * @param string $userColumn
     * @param string $passColumn
     */
    public function __construct($db, $tableName, $userColumn, $passColumn)
    {
        $this->db = $db;
        $this->tableName = $tableName;
        $this->usernameColumn = $userColumn;
        $this->passwordColumn = $passColumn;
        
    }

    /**
     *
     * @param $username
     * @param $password
     * @return Result
     * @throws \Tk\Auth\Exception if answering the authentication query is impossible
     */
    public function authenticate()
    {
        if (!$this->getUsername() || !$this->getPassword()) {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, $this->getUsername(), 'Invalid username or password.');
        }
        $sql = sprintf('SELECT * FROM %s WHERE %s = %s LIMIT 1',
            $this->db->quoteParameter($this->tableName),
            $this->db->quoteParameter($this->usernameColumn),
            $this->db->quote($this->getUsername()));
        try {
            $result = $this->db->query($sql);
            $user = $result->fetchObject();
            if ($user) {
                $passHash = self::hash($this->getPassword(), $this->getHashFunction());
                if ($passHash == $user->{$this->passwordColumn}) {
                    return new Result(Result::SUCCESS, $this->getUsername());
                }
            }
        } catch (\Exception $e) {
            throw new \Tk\Auth\Exception('The supplied parameters failed to produce a valid sql statement, please check table and column names for validity.', 0, $e);
        }
        return new Result(Result::FAILURE_IDENTITY_NOT_FOUND, $this->getUsername(), 'Invalid username or password.');
    }


}
