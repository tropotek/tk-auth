<?php
namespace Tk\ExtAuth\Microsoft;

use Tk\Db\Mapper;
use Tk\Db\Tool;
use Tk\Db\Map\ArrayObject;
use Tk\DataMap\Db;

class TokenMap extends Mapper
{

    public function __construct($db)
    {
        parent::__construct($db);
        $this->setTable('user_microsoft_token');
    }

    public function getDbMap(): \Tk\DataMap\DataMap
    {
        if (!$this->dbMap) {
            $this->dbMap = new \Tk\DataMap\DataMap();
            $this->dbMap->addPropertyMap(new Db\Integer('id'), 'key');
            $this->dbMap->addPropertyMap(new Db\Text('userId', 'user_id'));
            $this->dbMap->addPropertyMap(new Db\Text('sessionKey', 'session_key'));
            $this->dbMap->addPropertyMap(new Db\Date('expires'));
            $this->dbMap->addPropertyMap(new Db\Text('redirect'));
            $this->dbMap->addPropertyMap(new Db\Text('refreshToken', 'refresh_token'));
            $this->dbMap->addPropertyMap(new Db\Text('codeVerifier', 'code_verifier'));
            $this->dbMap->addPropertyMap(new Db\Text('token'));
            $this->dbMap->addPropertyMap(new Db\Text('idToken', 'id_token'));
        }
        return $this->dbMap;
    }

    public function installTable()
    {
        if ($this->getDb()->hasTable($this->getTable())) return;

        $sql = <<<MYSQL
CREATE TABLE IF NOT EXISTS `{$this->getTable()}` (
  `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` INT(11) UNSIGNED NOT NULL,
  `session_key` VARCHAR(255) DEFAULT NULL,
  `expires` DATETIME DEFAULT NULL,
  `redirect` VARCHAR(255) DEFAULT NULL,
  `refresh_token` TEXT DEFAULT NULL,
  `code_verifier` VARCHAR(255) DEFAULT NULL,
  `token` TEXT DEFAULT NULL,
  `id_token` TEXT DEFAULT NULL,
  PRIMARY KEY (`id`)
);
MYSQL;
        $this->getDb()->exec($sql);
    }

    /**
     * @param string $sessionKey
     * @return null|\Tk\Db\Map\Model|Token
     * @throws \Exception
     */
    public function findBySessionKey(string $sessionKey): ?Token
    {
        return $this->findFiltered(['sessionKey' => $sessionKey])->current();
    }

    /**
     * @param string $sessionKey
     * @return null|\Tk\Db\Map\Model|Token
     * @throws \Exception
     */
    public function findByUserId(int $userId): Token
    {
        return $this->findFiltered(['userId' => $userId])->current();
    }

    /**
     * @param array|\Tk\Db\Filter $filter
     * @param Tool|null $tool
     * @return ArrayObject|Token[]
     * @throws \Exception
     */
    public function findFiltered($filter, Tool $tool = null)
    {
        $r = $this->selectFromFilter($this->makeQuery(\Tk\Db\Filter::create($filter)), $tool);
        return $r;
    }

    /**
     * @param \Tk\Db\Filter $filter
     * @return \Tk\Db\Filter
     */
    public function makeQuery(\Tk\Db\Filter $filter)
    {
        $filter->appendFrom('%s a', $this->quoteParameter($this->getTable()));

        if (!empty($filter['id'])) {
            $w = $this->makeMultiQuery($filter['id'], 'a.id');
            if ($w) $filter->appendWhere('(%s) AND ', $w);
        }

        if (!empty($filter['userId'])) {
            $w = $this->makeMultiQuery($filter['userId'], 'a.user_id');
            if ($w) $filter->appendWhere('(%s) AND ', $w);
        }

        if (!empty($filter['expired'])) {
            $filter->appendWhere('a.expires < %s AND ', $this->quote($filter['expired']));
        }

        if (!empty($filter['sessionKey'])) {
            $filter->appendWhere('a.session_key = %s AND ', $this->quote($filter['sessionKey']));
        }

        if (!empty($filter['token'])) {
            $filter->appendWhere('a.token = %s AND ', $this->quote($filter['token']));
        }

        if (!empty($filter['exclude'])) {
            $w = $this->makeMultiQuery($filter['exclude'], 'a.id', 'AND', '!=');
            if ($w) $filter->appendWhere('(%s) AND ', $w);
        }

        return $filter;
    }


    public function cleanExpired()
    {
        $maxRefresh = strtotime('-72 hour');
        return $this->getDb()->exec('DELETE FROM ' . $this->getTable() . ' WHERE expires < ' . $this->quote(date('Y-m-d H:i:s', $maxRefresh)));
    }

}