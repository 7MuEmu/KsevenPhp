<?php
declare(strict_types=1);

namespace KSeven\WebLicense\Crypto;

use RuntimeException;

/**
 * Codec criptográfico do K'Seven Web Licensing SDK (PHP 8.1+):
 * - Estado local cifrado (k7st.v1) com HKDF-SHA256 + AES-256-GCM
 * - Transporte cifrado em trânsito (k7seal.v1) com ECDH P-256 + HKDF-SHA256 + AES-256-GCM
 * - Verificação de manifesto assinado Ed25519
 */
final class Codec
{
    public static function resolveStateSecret(?string $customSecret = null): string
    {
        if ($customSecret !== null && trim($customSecret) !== '') {
            return trim($customSecret);
        }
        $envSecret = getenv('K7_WEB_STATE_SECRET');
        if (is_string($envSecret) && trim($envSecret) !== '') {
            return trim($envSecret);
        }
        $host = gethostname() ?: 'php-host';
        $uid = function_exists('posix_getuid') ? (string) posix_getuid() : '0';
        return $host . '|' . PHP_OS_FAMILY . '|' . php_uname('m') . '|' . $uid . '|k7-web-sdk-local-seal-v1';
    }

    public static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $input): string
    {
        $pad = strlen($input) % 4;
        if ($pad > 0) {
            $input .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode(strtr($input, '-_', '+/'), true);
        if ($decoded === false) {
            throw new RuntimeException('Base64URL inválido no envelope criptográfico.');
        }
        return $decoded;
    }

    public static function encodeEncryptedState(array $state, ?string $customSecret = null): string
    {
        $master = self::resolveStateSecret($customSecret);
        $salt = random_bytes(16);
        $key = hash_hkdf('sha256', $master, 32, 'k7-web-state-v1', $salt);
        $iv = random_bytes(12);
        $tag = '';
        $plain = json_encode($state, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, 'k7st.v1');
        if ($cipher === false || strlen($tag) !== 16) {
            throw new RuntimeException('Falha ao cifrar estado local AES-256-GCM.');
        }

        return implode('.', [
            'k7st',
            'v1',
            self::base64UrlEncode($salt),
            self::base64UrlEncode($iv),
            self::base64UrlEncode($tag),
            self::base64UrlEncode($cipher),
        ]);
    }

    public static function decodeEncryptedState(string $rawContent, ?string $customSecret = null): ?array
    {
        $trimmed = trim($rawContent);
        if ($trimmed === '') {
            return null;
        }
        // Compatibilidade com estado JSON legado durante migração
        if (str_starts_with($trimmed, '{')) {
            $decoded = json_decode($trimmed, true);
            return is_array($decoded) ? $decoded : null;
        }

        $parts = explode('.', $trimmed);
        if (count($parts) !== 6 || $parts[0] !== 'k7st' || $parts[1] !== 'v1') {
            throw new RuntimeException('Formato de arquivo de estado cifrado inválido.');
        }

        $salt = self::base64UrlDecode($parts[2]);
        $iv = self::base64UrlDecode($parts[3]);
        $tag = self::base64UrlDecode($parts[4]);
        $cipher = self::base64UrlDecode($parts[5]);

        $master = self::resolveStateSecret($customSecret);
        $key = hash_hkdf('sha256', $master, 32, 'k7-web-state-v1', $salt);

        $plain = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, 'k7st.v1');
        if (!is_string($plain)) {
            throw new RuntimeException('Não foi possível decifrar o estado da licença. Verifique K7_WEB_STATE_SECRET.');
        }

        $decoded = json_decode($plain, true);
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Gera par ECDH P-256 efêmero para negociação em /api/web/license/v1/session-key.
     *
     * @return array{privateKey: \OpenSSLAsymmetricKey, clientPublicKeySpkiBase64: string}
     */
    public static function createEphemeralEcdhKeyPair(): array
    {
        $priv = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        if ($priv === false) {
            throw new RuntimeException('OpenSSL falhou ao gerar chave efêmera ECDH P-256.');
        }
        $details = openssl_pkey_get_details($priv);
        if (!is_array($details) || empty($details['key'])) {
            throw new RuntimeException('Falha ao extrair chave pública ECDH P-256.');
        }
        $pem = (string) $details['key'];
        $b64 = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/', '', $pem);
        return [
            'privateKey' => $priv,
            'clientPublicKeySpkiBase64' => (string) $b64,
        ];
    }

    public static function deriveWireAesKey(
        \OpenSSLAsymmetricKey $clientPrivateKey,
        string $sessionId,
        string $serverPublicKeySpkiBase64
    ): string {
        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(trim($serverPublicKeySpkiBase64), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
        $serverPub = openssl_pkey_get_public($pem);
        if ($serverPub === false) {
            throw new RuntimeException('Chave pública ECDH do servidor inválida.');
        }
        if (!function_exists('openssl_pkey_derive')) {
            throw new RuntimeException('openssl_pkey_derive indisponível neste build do PHP.');
        }
        $shared = openssl_pkey_derive($serverPub, $clientPrivateKey, 32);
        if (!is_string($shared) || $shared === '') {
            throw new RuntimeException('Falha na derivação ECDH com o servidor.');
        }
        return hash_hkdf('sha256', $shared, 32, 'k7-web-wire-v1', $sessionId);
    }

    public static function sealWirePayload(array $payload, string $aesKeyRaw, string $aad): string
    {
        $iv = random_bytes(12);
        $tag = '';
        $plain = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $cipher = openssl_encrypt($plain, 'aes-256-gcm', $aesKeyRaw, OPENSSL_RAW_DATA, $iv, $tag, $aad);
        if ($cipher === false || strlen($tag) !== 16) {
            throw new RuntimeException('Falha ao cifrar payload de transporte.');
        }
        return implode('.', [
            'k7seal',
            'v1',
            self::base64UrlEncode($iv),
            self::base64UrlEncode($tag),
            self::base64UrlEncode($cipher),
        ]);
    }

    public static function unsealWirePayload(string $sealedEnvelope, string $aesKeyRaw, string $aad): array
    {
        $parts = explode('.', trim($sealedEnvelope));
        if (count($parts) !== 5 || $parts[0] !== 'k7seal' || $parts[1] !== 'v1') {
            throw new RuntimeException('Envelope de resposta cifrado k7seal.v1 inválido.');
        }
        $iv = self::base64UrlDecode($parts[2]);
        $tag = self::base64UrlDecode($parts[3]);
        $cipher = self::base64UrlDecode($parts[4]);

        $plain = openssl_decrypt($cipher, 'aes-256-gcm', $aesKeyRaw, OPENSSL_RAW_DATA, $iv, $tag, $aad);
        if (!is_string($plain)) {
            throw new RuntimeException('Falha ao autenticar/decifrar envelope de resposta do servidor.');
        }
        $decoded = json_decode($plain, true);
        return is_array($decoded) ? $decoded : [];
    }

    public static function verifyEd25519Manifest(string $manifestJson, string $sigBase64, string $publicKeyPem): array
    {
        $sigBytes = base64_decode($sigBase64, true);
        if ($sigBytes === false) {
            throw new RuntimeException('Assinatura base64 inválida.');
        }

        $verified = false;
        if (function_exists('sodium_crypto_sign_verify_detached') && str_contains($publicKeyPem, 'BEGIN PUBLIC KEY')) {
            $b64 = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/', '', $publicKeyPem);
            $der = base64_decode((string) $b64, true);
            if ($der !== false && strlen($der) === 44) {
                $rawPub = substr($der, 12);
                $verified = sodium_crypto_sign_verify_detached($sigBytes, $manifestJson, $rawPub);
            }
        }
        if (!$verified && function_exists('openssl_verify')) {
            $key = openssl_pkey_get_public($publicKeyPem);
            if ($key !== false) {
                $ok = @openssl_verify($manifestJson, $sigBytes, $key, 0);
                $verified = ($ok === 1);
            }
        }

        if (!$verified) {
            throw new RuntimeException('Assinatura Ed25519 do manifesto rejeitada.');
        }

        $manifest = json_decode($manifestJson, true);
        if (!is_array($manifest) || ($manifest['schema'] ?? '') !== 'k7-web-release-v1') {
            throw new RuntimeException('Schema de manifesto inválido.');
        }
        return $manifest;
    }
}
