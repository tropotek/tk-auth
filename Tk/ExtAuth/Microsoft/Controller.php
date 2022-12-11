<?php

namespace Tk\ExtAuth\Microsoft;

use Bs\Db\User;
use Tk\Auth\AuthEvents;
use Tk\Auth\Exception;
use Tk\ConfigTrait;
use Tk\Date;
use Tk\Event\AuthEvent;
use Tk\Log;
use Tk\Request;
use Tk\Uri;


/**
 * Azure: https://portal.azure.com/
 * You must setup the app in Azure te get these values. This will not be covered here.
 *
 * Add the following to the config.php
 * ```
 *   // Microsoft SSO settings
 *   $config['auth.microsoft.enabled'] = true;
 *   // tennant ID or `common` for multi-tenant
 *   $config['auth.microsoft.tenantid'] = 'common';
 *   $config['auth.microsoft.clientid'] = '';
 *   $config['auth.microsoft.logout'] = 'https://login.microsoftonline.com/common/wsfederation?wa=wsignout1.0';
 *   $config['auth.microsoft.scope'] = 'openid offline_access profile user.read';
 *   // method = 'certificate' or 'secret'
 *   $config['auth.microsoft.oauth.method'] = 'secret';
 *   $config['auth.microsoft.oauth.secret'] = '';
 *   // on Windows, the certificate paths should be in the form c:/path/to/cert.crt
 *   //$config['auth.microsoft.oauth.certfile'] = '/data/cert/certificate.crt';
 *   //$config['auth.microsoft.oauth.keyfile'] = '/data/cert/privatekey.pem';
 * ```
 * Add the following routes:
 * ```
 *    $routes->add('login-microsoft', Route::create('/microsoftLogin.html', 'Tk\ExtAuth\Microsoft\Controller::doLogin'));
 *    $routes->add('auth-microsoft', Route::create('/microsoftAuth.html',  'Tk\ExtAuth\Microsoft\Controller::doAuth'));
 * ```
 * Add the following to the login page:
 * ```
 *    <a href="/microsoftLogin.html" class="btn btn-lg btn-default col-12" choice="microsoft">Microsoft</a>
 * ```
 *
 */
class Controller extends \Bs\Controller\Iface
{
    use ConfigTrait;

    private  $oAuthVerifier = '';

    private $oAuthChallenge = '';

    private $oAuthChallengeMethod = '';

    protected $error = '';

    /**
     * Login constructor.
     */
    public function __construct()
    {
        $this->setPageTitle('Login');
    }

    /**
     * @return \Tk\Controller\Page
     */
    public function getPage()
    {
        if (!$this->page) {
            $templatePath = '';
            if ($this->getConfig()->get('template.login')) {
                $templatePath = $this->getConfig()->getSitePath() . $this->getConfig()->get('template.login');
            }
            $this->page = $this->getConfig()->getPage($templatePath);
        }
        return parent::getPage();
    }

    protected function getLoginUrl()
    {
        return Uri::create('/microsoftLogin.html');
    }

    protected function getAuthUrl()
    {
        return Uri::create('/microsoftAuth.html');
    }

    /**
     * Find/Create user once the token is validated.
     * redirect to user homepage or set an error if not found
     *
     * @param Token $token
     * @return void
     * @throws \Exception
     */
    protected function findUser($token)
    {
        $idToken = json_decode($token->idToken);
        $username = $idToken->preferred_username;
        $name = $idToken->name;

        // Try to find an existing user
        $user = $this->getConfig()->getUserMapper()->findByEmail($username);
        if (!$user) {
            $user = $this->getConfig()->getUserMapper()->findByUsername($username);
        }
        if (!$user) {
            $user = new User();
            $user->setType(User::TYPE_MEMBER);
            $user->setName($name);
            $user->setUsername($username);
            $user->setEmail($username);
            $user->save();
        }
        $token->userId = $user->getId();
        $token->save();

        $this->getConfig()->getAuth()->getStorage()->write($this->getConfig()->getUserIdentity($user));
        if ($user && $user->isActive()) {
            $this->getConfig()->setAuthUser($user);
        }
        // Redirect to home page
        \Bs\Uri::createHomeUrl('/index.html', $user)->redirect();
    }

    public function doLogin(Request $request)
    {
        if (!$this->getConfig()->get('auth.microsoft.enabled')) {
            throw new Exception('Microsoft authentication not enabled on this site.');
        }
        $token = null;

        try {
            TokenMap::create()->installTable();

            // If logged in already Logout of current account
            if ($this->getAuthUser()) {
                // logout user
                $event = new AuthEvent();
                $this->getConfig()->getEventDispatcher()->dispatch(AuthEvents::LOGOUT, $event);
                Uri::create()->redirect();
            }

            // get existing token if one exists
            $sessionKey = $this->getSession()->get(Token::SESSION_KEY, '');

            if ($sessionKey) {
                $token = TokenMap::create()->findBySessionKey($sessionKey);
                $this->oAuthVerifier = $token->codeVerifier;
                $this->doAuthChallenge();
                // invalidate session if token not valid
                if (!($token && $token->idToken)) {
                    $this->getConfig()->getSession()->remove(Token::SESSION_KEY);
                    $this->getConfig()->getSession()->destroy();
                    Uri::create()->redirect();
                }

                if ($token->isExpiring()) {
                    if ($token->refreshToken) {
                        $oauthRequest = $this->generateOauthRequest(
                            'grant_type=refresh_token&refresh_token=' . $token->refreshToken .
                            '&client_id=' . $this->getConfig()->get('auth.microsoft.clientid') .
                            '&scope=' . $this->getConfig()->get('auth.microsoft.scope')
                        );
                        $response = $this->postOauthRequest('token', $oauthRequest);
                        $reply = json_decode($response);

                        if ($reply->error) {
                            if (substr($reply->error_description, 0, 12) == 'AADSTS70008:') {
                                $token->redirect = $this->getLoginUrl()->toString();
                                $token->refreshToken = '';
                                $token->expires = Date::create()->add(new \DateInterval('PT5M'));
                                $token->save();

                                $oAuthURL = $this->getMsAuthUrl();
                                $oAuthURL->redirect();
                            }
                            throw new Exception($reply->error_description);
                        }

                        $idToken = base64_decode(explode('.', $reply->id_token)[1]);
                        $token->token = $reply->access_token;
                        $token->refreshToken = $reply->refresh_token;
                        $token->idToken = $idToken;
                        $token->redirect = '';
                        $token->expires = Date::create()->add(new \DateInterval('PT' . $reply->expires_in . 'S'));
                        $token->save();
                    }
                }

                // Populate userData and userName from the JWT stored in the database.
                if ($token->idToken) {
                    $this->findUser($token);
                }

            } else {    // if (sessionKey)
                $this->doAuthChallenge();
                $sessionKey = Token::makeSessionKey();
                $this->getSession()->set(Token::SESSION_KEY, $sessionKey);
                $token = Token::create($sessionKey, $this->getLoginUrl()->toString(), $this->oAuthVerifier);
                $token->save();

                $oAuthURL = $this->getMsAuthUrl();
                $oAuthURL->redirect();
            }
        } catch (\Exception $e) {
            if ($token && $token->getId()) {
                $token->delete();
            }
        }
    }

    public function doAuth(Request $request)
    {
        $token = null;
        try {
            if ($request->get('error')) {
                throw new Exception($request->get('error'));
            }

            $token = TokenMap::create()->findBySessionKey($this->getSession()->get(Token::SESSION_KEY, ''));
            if (!$token) {
                Log::Error('MS oAuth validation failed!');
                Uri::create('/')->redirect();
            }
            $oauthRequest = $this->generateOauthRequest(
                'grant_type=authorization_code&client_id=' . $this->getConfig()->get('auth.microsoft.clientid') .
                '&redirect_uri=' . urlencode($this->getAuthUrl()->toString()) .
                '&code=' . $request->get('code') .
                '&code_verifier=' . $token->codeVerifier
            );
            $response = $this->postOauthRequest('token', $oauthRequest);
            if (!$response) {
                throw new Exception('Unknown error acquiring token');
            }
            $reply = json_decode($response);
            if (isset($reply->error)) {
                throw new Exception($reply->error_description);
            }
            $idToken = base64_decode(explode('.', $reply->id_token)[1]);
            $redirect = Uri::create($token->redirect);

            $token->token = $reply->access_token;
            $token->refreshToken = $reply->refresh_token;
            $token->idToken = $idToken;
            $token->redirect = '';
            $token->expires = Date::create()->add(new \DateInterval('PT' . $reply->expires_in . 'S'));
            $token->save();

            $redirect->redirect();
        } catch (\Exception $e) {
            if ($token && $token->getId()) {
                $token->delete();
            }
        }
    }

    protected function getMsAuthUrl(): Uri
    {
        $url = Uri::create('https://login.microsoftonline.com/' . $this->getConfig()->get('auth.microsoft.tenantid') . '/oauth2/v2.0/authorize');
        $url->set('response_type', 'code');
        $url->set('client_id', $this->getConfig()->get('auth.microsoft.clientid'));
        $url->set('redirect_uri', $this->getAuthUrl()->toString());
        $url->set('scope', $this->getConfig()->get('auth.microsoft.scope'));
        $url->set('code_challenge', $this->oAuthChallenge);
        $url->set('code_challenge_method', $this->oAuthChallengeMethod);
        return $url;
    }

    protected function doAuthChallenge()
    {
        // Function to generate code verifier and code challenge for oAuth login. See RFC7636 for details.
        $verifier = $this->oAuthVerifier;
        if (!$this->oAuthVerifier) {
            $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~';
            $charLen = strlen($chars) - 1;
            $verifier = '';
            for ($i = 0; $i < 128; $i++) {
                $verifier .= $chars[mt_rand(0, $charLen)];
            }
            $this->oAuthVerifier = $verifier;
        }
        // Challenge = Base64 Url Encode ( SHA256 ( Verifier ) )
        // Pack (H) to convert 64 char hash into 32 byte hex
        // As there is no B64UrlEncode we use strtr to swap +/ for -_ and then strip off the =
        $this->oAuthChallenge = str_replace('=', '', strtr(base64_encode(pack('H*', hash('sha256', $verifier))), '+/', '-_'));
        $this->oAuthChallengeMethod = 'S256';
    }

    protected function generateOauthRequest($data)
    {
        if ($this->getConfig()->get('auth.microsoft.oauth.method') == 'certificate') {
            // Use the certificate specified
            // https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials
            $cert = file_get_contents($this->getConfig()->get('auth.microsoft.oauth.certfile'));
            $certKey = openssl_pkey_get_private(file_get_contents($this->getConfig()->get('auth.microsoft.oauth.keyfile')));
            $certHash = openssl_x509_fingerprint($cert);
            $certHash = base64_encode(hex2bin($certHash));
            $caHeader = json_encode(array('alg' => 'RS256', 'typ' => 'JWT', 'x5t' => $certHash));
            $caPayload = json_encode(array(
                'aud' => 'https://login.microsoftonline.com/' . $this->getConfig()->get('auth.microsoft.tenantid') . '/v2.0',
                'exp' => date('U', strtotime('+10 minute')),
                'iss' => $this->getConfig()->get('auth.microsoft.clientid'),
                'jti' => Token::makeSessionKey(),
                'nbf' => date('U'),
                'sub' => $this->getConfig()->get('auth.microsoft.clientid')
            ));
            $caSignature = '';

            $caData = $this->base64UrlEncode($caHeader) . '.' . $this->base64UrlEncode($caPayload);
            openssl_sign($caData, $caSignature, $certKey, OPENSSL_ALGO_SHA256);
            $caSignature = $this->base64UrlEncode($caSignature);
            $clientAssertion = $caData . '.' . $caSignature;
            return $data . '&client_assertion=' . $clientAssertion . '&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        } else {
            // Use the client secret instead
            return $data . '&client_secret=' . urlencode($this->getConfig()->get('auth.microsoft.oauth.secret'));
        }
    }

    protected function postOauthRequest($endpoint, $data)
    {
        $ch = curl_init('https://login.microsoftonline.com/' . $this->getConfig()->get('auth.microsoft.tenantid') . '/oauth2/v2.0/' . $endpoint);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        if ($cError = curl_error($ch)) {
            throw new Exception($cError);
        }
        curl_close($ch);
        return $response;
    }

    protected function base64UrlEncode($toEncode)
    {
        return str_replace('=', '', strtr(base64_encode($toEncode), '+/', '-_'));
    }

    /**
     * @return \Dom\Template
     */
    public function show()
    {
        $template = parent::show();

        if ($this->error) {
            $template->insertHtml('error', 'Error: ' . $this->error);
            $template->setVisible('error');
        } else {
            $template->setVisible('no-error');
        }

        return $template;
    }



    /**
     * @return \Dom\Template
     */
    public function __makeTemplate()
    {
        $xhtml = <<<HTML
<div class="tk-microsoft-auth">
<p choice="no-error">Logging you in.</p>
<p var="error" choice="error"></p>
</div>
HTML;

        return \Dom\Loader::load($xhtml);
    }



}