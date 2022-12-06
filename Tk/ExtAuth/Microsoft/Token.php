<?php
namespace Tk\ExtAuth\Microsoft;

use Tk\Date;
use Tk\Db\Map\Model;
use Tk\Uri;

class Token extends Model
{
    const SESSION_KEY = 'auth.ms.sessionKey';

    /**
     * @var int
     */
    public $id = 0;

    /**
     * @var int
     */
    public $userId = 0;

    public $sessionKey = '';

    /**
     * @var null|\DateTime
     */
    public $expires = null;

    public $redirect = '';

    public $refreshToken = '';

    public $codeVerifier = '';

    public $token = '';

    /**
     * Json object???
     * @var string|array
     */
    public $idToken = '';


    public function __construct()
    {
        $this->expires = Date::create()->add(new \DateInterval('PT5M'));
    }

    public static function create(string $sessionKey, string $redirect, string $codeVerifier): Token
    {
        $obj = new static();
        $obj->sessionKey = $sessionKey;
        $obj->redirect = $redirect;
        $obj->codeVerifier = $codeVerifier;
        return $obj;
    }

    public function delete()
    {
        //$this->sendGetRequest($this->getConfig()->get('auth.microsoft.logout'), '');
        return parent::delete();
    }


    public function isExpiring(): bool
    {
        return ($this->expires < Date::create($this->expires)->add(new \DateInterval('PT10M')));
    }


    public function getProfile()
    {
        $profile = json_decode($this->sendGetRequest('https://graph.microsoft.com/v1.0/me/'));
        return $profile;
    }

    /**
     * Put the contents in an img tag src attribute
     *
     * @return string
     */
    public function getPhoto(): string
    {
        //Photo is a bit different, we need to request the image data which will include content type, size etc, then request the image
        $photoType = json_decode($this->sendGetRequest('https://graph.microsoft.com/v1.0/me/photo/'));
        $photo = $this->sendGetRequest('https://graph.microsoft.com/v1.0/me/photo/%24value');
        if (isset($photoType->{'@odata.mediaContentType'})) {
            return 'data:' . $photoType->{'@odata.mediaContentType'} . ';base64,' . base64_encode($photo);
        }
        return '';
    }

    public function sendGetRequest($url, $contentType = 'application/json')
    {
        $ch = curl_init($url);
        if ($contentType) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('Authorization: Bearer ' . $this->token, 'Content-Type: ' . $contentType));
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);

        curl_close($ch);
        return $response;
    }


    /**
     * Generate A UUID for a session key
     * @return string
     */
    public static function makeSessionKey(): string
    {
        //uuid function is not my code, but unsure who the original author is. KN
        //uuid version 4
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            // 32 bits for "time_low"
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            // 16 bits for "time_mid"
            mt_rand(0, 0xffff),
            // 16 bits for "time_hi_and_version",
            // four most significant bits holds version number 4
            mt_rand(0, 0x0fff) | 0x4000,
            // 16 bits, 8 bits for "clk_seq_hi_res",
            // 8 bits for "clk_seq_low",
            // two most significant bits holds zero and one for variant DCE1.1
            mt_rand(0, 0x3fff) | 0x8000,
            // 48 bits for "node"
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }
}