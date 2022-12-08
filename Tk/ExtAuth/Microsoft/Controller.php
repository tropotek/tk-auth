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

class Controller
{
    use ConfigTrait;

    private  $oAuthVerifier = '';

    private $oAuthChallenge = '';

    private $oAuthChallengeMethod = '';


    public function doLogin(Request $request)
    {
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
                Uri::create()->reset()->redirect();
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
                            $token->redirect = Uri::create('/microsoftLogin.html')->toString();
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
                $idToken = json_decode($token->idToken);
                $username = $idToken->preferred_username;   // Email
                $name = $idToken->name;
                $uid = $idToken->oid;           // unique ID to identify the MS user
                // is unimellb =>  0e5bf3cf-1ff4-46b7-9176-52c538c22a4d

                $userTennantId = $idToken->tid; // Company/institution ID get this from the institution if available

                vd(explode('/', $idToken->iss));

                // Try to find an existing user
                $user = $this->getConfig()->getUserMapper()->findByEmail($username);
                if (!$user) {
                    $user = $this->getConfig()->getUserMapper()->findByUsername($username);
                }
                if (!$user) {
                    $user = new User();
                    $user->setUid($uid);
                    $user->setType(User::TYPE_MEMBER);
                    $user->setName($name);
                    $user->setUsername($username);
                    $user->setEmail($username);
                    $user->save();
                }
                $token->userId = $user->getId();
                $token->save();

                $this->getConfig()->getAuth()->getStorage()->write($user->getUsername());
                if ($user && $user->isActive()) {
                    $this->getConfig()->setAuthUser($user);
                }
            }

        } else {    // if (sessionKey)
            if ($request->has('login')) {
                $this->doAuthChallenge();
                $sessionKey = Token::makeSessionKey();
                $this->getSession()->set(Token::SESSION_KEY, $sessionKey);
                $token = Token::create($sessionKey, Uri::create()->reset()->toString(), $this->oAuthVerifier);
                $token->save();

                $oAuthURL = $this->getMsAuthUrl();
                $oAuthURL->redirect();
            }
        }

        return <<<HTML
<p>Loggin you in.</p>
<p><small>This windows should cose in a few seconds.</small></p>
<script>
    window.opener.postMessage('closing', window.opener);
</script>
HTML;

    }


    public function doAuth(Request $request)
    {
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
            '&redirect_uri=' . urlencode(Uri::create('/microsoftAuth.html')->toString()) .
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
        $token->expires = Date::create()->add(new \DateInterval('PT'.$reply->expires_in.'S'));
        $token->save();

        $redirect->redirect();
    }


    protected function getMsAuthUrl(): Uri
    {
        $url = Uri::create('https://login.microsoftonline.com/' . $this->getConfig()->get('auth.microsoft.tenantid') . '/oauth2/v2.0/' . 'authorize');
        $url->set('response_type', 'code');
        $url->set('client_id', $this->getConfig()->get('auth.microsoft.clientid'));
        $url->set('redirect_uri', Uri::create('/microsoftAuth.html')->toString());
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

}