<?php
declare(strict_types=1);

namespace KSeven\WebLicense\Crypto;

use RuntimeException;
use KSeven\WebLicense\Support\Env;

/**
 * Codec criptográfico do K'Seven Web Licensing SDK (PHP 8.1+):
 * - Estado local cifrado (k7st.v1) com HKDF-SHA256 + AES-256-GCM
 * - Transporte cifrado em trânsito (k7seal.v1) com ECDH P-256 + HKDF-SHA256 + AES-256-GCM e AAD vinculada a sessão/nonce
 * - Verificação Ed25519 de cadeia de chaves (raiz -> ativa/secundária), handshake ECDH, respostas runtime (ALLOW/DENY) e manifestos
 * - Assinatura assimétrica opcional de requisições por instalação (x-k7-web-client-signature)
 */
final class Codec
{
    /**
     * Resolve o segredo mestre usado na derivação (HKDF-SHA256) da chave de cifragem do estado local.
     * Prioriza o parâmetro explícito, depois a variável de ambiente `K7_WEB_STATE_SECRET` e, por fim,
     * gera uma impressão determinística baseada no hostname, sistema operacional, arquitetura e UID.
     *
     * @param string|null $customSecret Segredo personalizado fornecido via configuração do SDK.
     * @return string Segredo mestre não vazio para derivação da chave local.
     */
    public static function resolveStateSecret(?string $customSecret = null): string
    {
        if ($customSecret !== null && trim($customSecret) !== '') {
            return trim($customSecret);
        }

        $envSecret = Env::get('K7_WEB_STATE_SECRET');
        if ($envSecret !== null) {
            return $envSecret;
        }

        $host = gethostname() ?: 'php-host';
        $uid = function_exists('posix_getuid') ? (string) posix_getuid() : '0';
        return $host . '|' . PHP_OS_FAMILY . '|' . php_uname('m') . '|' . $uid . '|k7-web-sdk-local-seal-v1';
    }

    /**
     * Codifica bytes arbitrários para o formato Base64URL (RFC 4648 §5) sem caracteres de padding (`=`).
     *
     * @param string $bytes Sequência de bytes brutos a ser codificada.
     * @return string Representação Base64URL segura para URLs e envelopes delimitados por pontos.
     */
    public static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Decodifica uma string em Base64URL (com ou sem padding `=`) de volta para bytes brutos.
     *
     * @param string $input String codificada em Base64URL.
     * @return string Bytes binários originais decodificados.
     * @throws RuntimeException Se a entrada contiver caracteres inválidos ou falhar na decodificação estrita.
     */
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

    /**
     * Serialização JSON determinística (chaves ordenadas recursivamente) idêntica ao backend Node.js.
     * Aceita stdClass (preservando objetos vazios `{}`), arrays indexados e arrays associativos.
     *
     * @param mixed $value Valor escalar, objeto `stdClass` ou array a ser canonizado.
     * @return string String JSON canônica sem espaços extras e com chaves ordenadas lexicograficamente.
     * @throws \JsonException Se algum valor não puder ser serializado em JSON válido.
     */
    public static function canonicalizeJson(mixed $value): string
    {
        if ($value === null) {
            return 'null';
        }
        if (is_bool($value) || is_int($value) || is_float($value) || is_string($value)) {
            return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        }
        if ($value instanceof \stdClass) {
            $vars = get_object_vars($value);
            ksort($vars, SORT_STRING);
            $parts = [];
            foreach ($vars as $k => $v) {
                $parts[] = json_encode((string) $k, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)
                    . ':'
                    . self::canonicalizeJson($v);
            }
            return '{' . implode(',', $parts) . '}';
        }
        if (is_array($value)) {
            if (array_is_list($value)) {
                $items = array_map(static fn ($item) => self::canonicalizeJson($item), $value);
                return '[' . implode(',', $items) . ']';
            }
            $copy = $value;
            ksort($copy, SORT_STRING);
            $parts = [];
            foreach ($copy as $k => $v) {
                $parts[] = json_encode((string) $k, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)
                    . ':'
                    . self::canonicalizeJson($v);
            }
            return '{' . implode(',', $parts) . '}';
        }
        return json_encode((string) $value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /**
     * Calcula o resumo criptográfico SHA-256 (em hexadecimal minúsculo) da representação JSON canônica de um valor.
     *
     * @param mixed $value Estrutura de dados a ser canonizada e resumida.
     * @return string Hash SHA-256 hexadecimal de 64 caracteres.
     * @throws \JsonException Se a canonização JSON falhar.
     */
    public static function sha256CanonicalJson(mixed $value): string
    {
        return hash('sha256', self::canonicalizeJson($value));
    }

    /**
     * Extrai os 32 bytes brutos da chave pública Ed25519 a partir de um PEM SPKI e os retorna em hexadecimal.
     *
     * @param string $publicKeyPem Chave pública no formato PEM (`-----BEGIN PUBLIC KEY-----`).
     * @return string Chave pública bruta de 32 bytes codificada em hexadecimal minúsculo (64 caracteres).
     * @throws RuntimeException Se o DER decodificado for inválido ou tiver menos de 32 bytes.
     */
    public static function extractEd25519RawPublicKeyHex(string $publicKeyPem): string
    {
        $b64 = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/', '', $publicKeyPem);
        $der = base64_decode((string) $b64, true);
        if ($der === false || strlen($der) < 32) {
            throw new RuntimeException('Chave pública SPKI Ed25519 inválida.');
        }
        return strtolower(bin2hex(substr($der, -32)));
    }

    /**
     * Verifica uma assinatura digital destacada Ed25519 sobre uma mensagem arbitrária,
     * utilizando `ext-sodium` como primária e `ext-openssl` como fallback.
     *
     * @param string $message Mensagem original em texto plano que foi assinada.
     * @param string $sigBase64 Assinatura binária de 64 bytes codificada em Base64 padrão.
     * @param string $publicKeyPem Chave pública Ed25519 em formato PEM SPKI.
     * @return bool `true` se a assinatura for criptograficamente válida; `false` caso contrário.
     */
    public static function verifyEd25519Message(string $message, string $sigBase64, string $publicKeyPem): bool
    {
        $sigBytes = base64_decode($sigBase64, true);
        if ($sigBytes === false) {
            return false;
        }
        if (function_exists('sodium_crypto_sign_verify_detached') && str_contains($publicKeyPem, 'BEGIN PUBLIC KEY')) {
            $b64 = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/', '', $publicKeyPem);
            $der = base64_decode((string) $b64, true);
            if ($der !== false && strlen($der) === 44) {
                $rawPub = substr($der, 12);
                if (sodium_crypto_sign_verify_detached($sigBytes, $message, $rawPub)) {
                    return true;
                }
            }
        }
        if (function_exists('openssl_verify')) {
            $key = openssl_pkey_get_public($publicKeyPem);
            if ($key !== false) {
                $ok = @openssl_verify($message, $sigBytes, $key, 0);
                if ($ok === 1) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Assina uma mensagem arbitrária usando uma chave privada Ed25519 em formato PEM PKCS#8,
     * priorizando `ext-sodium` e recorrendo a `ext-openssl` se necessário.
     *
     * @param string $message Conteúdo textual a ser assinado.
     * @param string $privateKeyPem Chave privada Ed25519 no formato PEM (`-----BEGIN PRIVATE KEY-----`).
     * @return string Assinatura Ed25519 de 64 bytes codificada em Base64 padrão.
     * @throws RuntimeException Se nem `libsodium` nem `OpenSSL` conseguirem realizar a assinatura Ed25519.
     */
    public static function signEd25519Message(string $message, string $privateKeyPem): string
    {
        if (function_exists('sodium_crypto_sign_detached') && str_contains($privateKeyPem, 'BEGIN PRIVATE KEY')) {
            $b64 = preg_replace('/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s+/', '', $privateKeyPem);
            $der = base64_decode((string) $b64, true);
            if ($der !== false && strlen($der) >= 32) {
                $seed = substr($der, -32);
                $kp = sodium_crypto_sign_seed_keypair($seed);
                $sk = sodium_crypto_sign_secretkey($kp);
                return base64_encode(sodium_crypto_sign_detached($message, $sk));
            }
        }
        if (function_exists('openssl_sign')) {
            $key = openssl_pkey_get_private($privateKeyPem);
            if ($key !== false) {
                $sig = '';
                if (@openssl_sign($message, $sig, $key, 0)) {
                    return base64_encode($sig);
                }
            }
        }
        throw new RuntimeException('Não foi possível assinar mensagem Ed25519 (habilite libsodium ou OpenSSL Ed25519).');
    }

    /**
     * Gera a assinatura Ed25519 do cliente (`x-k7-web-client-signature`) vinculando método, rota,
     * timestamp, nonce anti-replay, ID da instalação e o SHA-256 do corpo JSON canonizado.
     *
     * @param string $clientPrivateKeyPem Chave privada Ed25519 da instalação cliente (PEM).
     * @param string $method Método HTTP da requisição (ex.: "GET", "POST").
     * @param string $path Caminho da rota sem query string (ex.: "/api/web/license/v1/validate").
     * @param string $timestamp Timestamp UTC ISO-8601 enviado em `x-k7-web-timestamp`.
     * @param string $nonce Nonce aleatório enviado em `x-k7-web-nonce`.
     * @param string $installationId Identificador único da instalação registrada.
     * @param array<string, mixed>|null $body Corpo da requisição (tratado como `{}` se nulo ou vazio).
     * @return string Assinatura Ed25519 em Base64 pronta para o cabeçalho `x-k7-web-client-signature`.
     * @throws RuntimeException Se a assinatura Ed25519 falhar.
     */
    public static function signClientRequest(
        string $clientPrivateKeyPem,
        string $method,
        string $path,
        string $timestamp,
        string $nonce,
        string $installationId,
        ?array $body = null
    ): string {
        $bodyObj = ($body === null || $body === []) ? new \stdClass() : $body;
        $bodySha256 = self::sha256CanonicalJson($bodyObj);
        $canonical = implode('|', [
            'k7web-client-req|v1',
            strtoupper($method),
            $path,
            $timestamp,
            $nonce,
            $installationId,
            $bodySha256,
        ]);
        return self::signEd25519Message($canonical, $clientPrivateKeyPem);
    }

    /**
     * Verifica uma prova criptográfica de transição/endosso de chave (`k7web-key-transition|v1`),
     * validando schema, chave de destino esperada, validade temporal (`expiresAt`) e assinatura Ed25519.
     *
     * @param array<string, mixed>|null $proof Objeto contendo metadados da transição e `signatureBase64`.
     * @param string $signerPublicKeyPem Chave pública Ed25519 (PEM) da entidade emissora (raiz ou chave anterior).
     * @param string|null $expectedToKeyId ID esperado da chave endossada (`toKeyId`), se aplicável.
     * @param string|null $expectedToRawHex Hexadecimal bruto esperado da chave pública endossada (`toPublicKeyRawHex`).
     * @return bool `true` se a prova de transição for autêntica e não estiver expirada.
     */
    public static function verifyKeyTransitionProof(
        ?array $proof,
        string $signerPublicKeyPem,
        ?string $expectedToKeyId = null,
        ?string $expectedToRawHex = null
    ): bool {
        if (!$proof || ($proof['schema'] ?? '') !== 'k7web-key-transition|v1' || empty($proof['signatureBase64'])) {
            return false;
        }
        if ($expectedToKeyId !== null && ($proof['toKeyId'] ?? '') !== $expectedToKeyId) {
            return false;
        }
        if (
            $expectedToRawHex !== null &&
            strtolower((string) ($proof['toPublicKeyRawHex'] ?? '')) !== strtolower($expectedToRawHex)
        ) {
            return false;
        }
        $expTs = strtotime((string) ($proof['expiresAt'] ?? ''));
        if ($expTs === false || $expTs <= time()) {
            return false;
        }
        $canonical = implode('|', [
            (string) $proof['schema'],
            (string) ($proof['fromKeyId'] ?? ''),
            (string) ($proof['fromKeyVersion'] ?? 0),
            (string) ($proof['toKeyId'] ?? ''),
            (string) ($proof['toKeyVersion'] ?? 0),
            strtolower((string) ($proof['toPublicKeyRawHex'] ?? '')),
            (string) ($proof['issuedAt'] ?? ''),
            (string) ($proof['expiresAt'] ?? ''),
            (string) ($proof['reason'] ?? ''),
        ]);
        return self::verifyEd25519Message($canonical, (string) $proof['signatureBase64'], $signerPublicKeyPem);
    }

    /**
     * Resolve e valida o conjunto de chaves públicas Ed25519 confiáveis a partir do bundle publicado pelo servidor,
     * percorrendo a cadeia de confiança (raiz -> chaves endossadas diretamente -> transições encadeadas)
     * e mesclando com chaves explicitamente pinadas.
     *
     * @param array<string, mixed> $bundle Resposta JSON decodificada de `/keys` ou `/releases/public-key`.
     * @param string|null $pinnedRootPublicKeyPem Chave pública raiz Ed25519 (PEM) pinada no cliente, se houver.
     * @param array<string, string> $explicitPinnedKeys Mapa adicional de chaves pinadas (`keyId => publicKeyPem`).
     * @return array<string, string> Mapa consolidado de chaves confiáveis (`keyId => publicKeyPem`).
     * @throws RuntimeException Se a chave raiz publicada divergir da chave raiz pinada no SDK (HTTP 403).
     */
    public static function resolveTrustedKeysFromBundle(
        array $bundle,
        ?string $pinnedRootPublicKeyPem = null,
        array $explicitPinnedKeys = []
    ): array {
        $trusted = [];
        $candidates = [];
        if (!empty($bundle['activeKey']) && is_array($bundle['activeKey'])) {
            $candidates[$bundle['activeKey']['keyId'] ?? ''] = $bundle['activeKey'];
        }
        foreach (($bundle['secondaryKeys'] ?? []) as $sec) {
            if (is_array($sec) && !empty($sec['keyId'])) {
                $candidates[(string) $sec['keyId']] = $sec;
            }
        }
        foreach (($bundle['keys'] ?? []) as $k) {
            if (is_array($k) && !empty($k['keyId']) && !isset($candidates[(string) $k['keyId']])) {
                $candidates[(string) $k['keyId']] = $k;
            }
        }

        $rootPubFromBundle = (string) ($bundle['rootKey']['publicKeyPem'] ?? '');
        if ($pinnedRootPublicKeyPem !== null && $pinnedRootPublicKeyPem !== '' && $rootPubFromBundle !== '') {
            if (
                self::extractEd25519RawPublicKeyHex($pinnedRootPublicKeyPem) !==
                self::extractEd25519RawPublicKeyHex($rootPubFromBundle)
            ) {
                throw new RuntimeException('Chave raiz publicada diverge da chave raiz Ed25519 pinada no SDK.', 403);
            }
        }

        $effectiveRootPem = ($pinnedRootPublicKeyPem !== null && $pinnedRootPublicKeyPem !== '')
            ? $pinnedRootPublicKeyPem
            : $rootPubFromBundle;

        if ($effectiveRootPem !== '') {
            foreach ($candidates as $keyId => $entry) {
                if ($keyId === '' || empty($entry['publicKeyPem'])) {
                    continue;
                }
                $rawHex = self::extractEd25519RawPublicKeyHex((string) $entry['publicKeyPem']);
                if (!empty($entry['publicKeyRawHex']) && strtolower((string) $entry['publicKeyRawHex']) !== $rawHex) {
                    continue;
                }
                if (
                    !empty($entry['rootProof']) &&
                    is_array($entry['rootProof']) &&
                    self::verifyKeyTransitionProof($entry['rootProof'], $effectiveRootPem, $keyId, $rawHex)
                ) {
                    $trusted[$keyId] = (string) $entry['publicKeyPem'];
                }
            }

            $progress = true;
            while ($progress) {
                $progress = false;
                foreach ($candidates as $keyId => $entry) {
                    if ($keyId === '' || isset($trusted[$keyId]) || empty($entry['transitionProof']) || !is_array($entry['transitionProof'])) {
                        continue;
                    }
                    $fromKeyId = (string) ($entry['transitionProof']['fromKeyId'] ?? '');
                    if (!isset($trusted[$fromKeyId])) {
                        continue;
                    }
                    $rawHex = self::extractEd25519RawPublicKeyHex((string) $entry['publicKeyPem']);
                    if (
                        (empty($entry['publicKeyRawHex']) || strtolower((string) $entry['publicKeyRawHex']) === $rawHex) &&
                        self::verifyKeyTransitionProof($entry['transitionProof'], $trusted[$fromKeyId], $keyId, $rawHex)
                    ) {
                        $trusted[$keyId] = (string) $entry['publicKeyPem'];
                        $progress = true;
                    }
                }
            }
        }

        if (($pinnedRootPublicKeyPem === null || $pinnedRootPublicKeyPem === '') && $trusted === []) {
            foreach ($candidates as $keyId => $entry) {
                if ($keyId !== '' && !empty($entry['publicKeyPem'])) {
                    $trusted[$keyId] = (string) $entry['publicKeyPem'];
                }
            }
        }

        foreach ($explicitPinnedKeys as $kId => $pem) {
            if ($kId !== '' && $pem !== '') {
                $trusted[(string) $kId] = (string) $pem;
            }
        }

        return $trusted;
    }

    /**
     * Valida a assinatura Ed25519 (`k7-web-ecdh-sig-v1`) da resposta do handshake ECDH em `/session-key`,
     * garantindo autenticidade da chave pública efêmera do servidor, nonce, janela de tempo (300s) e binding com a chave do cliente.
     *
     * @param string $sessionId Identificador da sessão negociada pelo servidor.
     * @param string $serverPublicKeySpkiBase64 Chave pública efêmera ECDH P-256 do servidor (SPKI em Base64).
     * @param string $fingerprintSha256 Fingerprint SHA-256 da chave efêmera do servidor.
     * @param string $clientPublicKeySpkiBase64 Chave pública efêmera ECDH P-256 enviada pelo cliente (SPKI em Base64).
     * @param int $expiresInSeconds Tempo de vida da sessão informado pelo servidor.
     * @param string $expectedNonce Nonce enviado pelo cliente na requisição `/session-key`.
     * @param array<string, mixed>|null $handshakeSignature Objeto de assinatura retornado pelo servidor.
     * @param array<string, string> $trustedKeys Mapa de chaves públicas Ed25519 confiáveis (`keyId => publicKeyPem`).
     * @return void
     * @throws RuntimeException Se a assinatura estiver ausente, expirada, com nonce divergente ou criptograficamente inválida (HTTP 403).
     */
    public static function verifyEcdhHandshakeSignature(
        string $sessionId,
        string $serverPublicKeySpkiBase64,
        string $fingerprintSha256,
        string $clientPublicKeySpkiBase64,
        int $expiresInSeconds,
        string $expectedNonce,
        ?array $handshakeSignature,
        array $trustedKeys
    ): void {
        if (
            !$handshakeSignature ||
            ($handshakeSignature['schema'] ?? '') !== 'k7-web-ecdh-sig-v1' ||
            empty($handshakeSignature['signatureBase64']) ||
            empty($handshakeSignature['keyId'])
        ) {
            throw new RuntimeException('Resposta de /session-key sem assinatura Ed25519 de handshake.', 403);
        }

        $keyId = (string) $handshakeSignature['keyId'];
        if (empty($trustedKeys[$keyId])) {
            throw new RuntimeException("Chave Ed25519 do handshake ECDH não confiável (keyId={$keyId}).", 403);
        }

        if ((string) ($handshakeSignature['nonce'] ?? '') !== $expectedNonce) {
            throw new RuntimeException('Nonce do handshake ECDH diverge do enviado pelo cliente.', 403);
        }

        $ts = strtotime((string) ($handshakeSignature['timestamp'] ?? ''));
        if ($ts === false || abs(time() - $ts) > 300) {
            throw new RuntimeException('Timestamp do handshake ECDH fora da janela permitida.', 403);
        }

        $clientPubDer = base64_decode($clientPublicKeySpkiBase64, true);
        $clientPubSha256 = hash('sha256', $clientPubDer === false ? '' : $clientPubDer);

        $canonical = implode('|', [
            (string) $handshakeSignature['schema'],
            $sessionId,
            $serverPublicKeySpkiBase64,
            $fingerprintSha256,
            $clientPubSha256,
            (string) $handshakeSignature['timestamp'],
            (string) $expiresInSeconds,
            (string) $handshakeSignature['nonce'],
        ]);

        if (!self::verifyEd25519Message($canonical, (string) $handshakeSignature['signatureBase64'], $trustedKeys[$keyId])) {
            throw new RuntimeException("Assinatura Ed25519 do handshake ECDH inválida (keyId={$keyId}).", 403);
        }
    }

    /**
     * Valida `signatureEnvelope` Ed25519 usando o JSON decodificado em stdClass para preservar `{}` vs `[]`.
     * Confere metadados HTTP (método, rota, status, nonce, janela de 300s), integridade SHA-256 do payload
     * e autenticidade da decisão de runtime (`ALLOW`/`DENY`).
     *
     * @param string $rawJson Corpo JSON bruto (já deslacrado, se aplicável) recebido da API.
     * @param array<string, string> $trustedKeys Mapa de chaves públicas Ed25519 confiáveis (`keyId => publicKeyPem`).
     * @param string $expectedMethod Método HTTP esperado na assinatura.
     * @param string $expectedPath Caminho da rota esperado na assinatura.
     * @param int $expectedHttpStatus Código de status HTTP recebido da resposta.
     * @param string $expectedNonce Nonce enviado originalmente na requisição.
     * @return void
     * @throws RuntimeException Se o envelope estiver ausente, adulterado, expirado ou com assinatura inválida (HTTP 403).
     */
    public static function verifyRuntimeResponseSignatureFromRawJson(
        string $rawJson,
        array $trustedKeys,
        string $expectedMethod,
        string $expectedPath,
        int $expectedHttpStatus,
        string $expectedNonce
    ): void {
        $obj = json_decode($rawJson, false);
        if (!($obj instanceof \stdClass) || !isset($obj->signatureEnvelope) || !($obj->signatureEnvelope instanceof \stdClass)) {
            throw new RuntimeException('Resposta de runtime sem signatureEnvelope Ed25519.', 403);
        }

        $env = $obj->signatureEnvelope;
        if (($env->schema ?? '') !== 'k7-web-response-sig-v1' || empty($env->signatureBase64) || empty($env->keyId)) {
            throw new RuntimeException('Formato de signatureEnvelope inválido.', 403);
        }

        $keyId = (string) $env->keyId;
        if (empty($trustedKeys[$keyId])) {
            throw new RuntimeException("Chave Ed25519 da resposta de runtime não é confiável (keyId={$keyId}).", 403);
        }

        if ((string) ($env->nonce ?? '') !== $expectedNonce) {
            throw new RuntimeException('Nonce do signatureEnvelope diverge do enviado.', 403);
        }
        if (strtoupper((string) ($env->method ?? '')) !== strtoupper($expectedMethod)) {
            throw new RuntimeException('Método HTTP do signatureEnvelope diverge.', 403);
        }
        if ((string) ($env->path ?? '') !== $expectedPath) {
            throw new RuntimeException('Rota do signatureEnvelope diverge.', 403);
        }
        if ((int) ($env->httpStatus ?? 0) !== $expectedHttpStatus) {
            throw new RuntimeException('Status HTTP do signatureEnvelope diverge.', 403);
        }
        $ts = strtotime((string) ($env->timestamp ?? ''));
        if ($ts === false || abs(time() - $ts) > 300) {
            throw new RuntimeException('Timestamp do signatureEnvelope fora da janela permitida.', 403);
        }

        $unsignedCopy = clone $obj;
        unset($unsignedCopy->signatureEnvelope);
        $computedHash = self::sha256CanonicalJson($unsignedCopy);
        if (!hash_equals((string) ($env->payloadSha256 ?? ''), $computedHash)) {
            throw new RuntimeException('Hash SHA-256 do payload diverge do signatureEnvelope.', 403);
        }

        $canonical = implode('|', [
            (string) $env->schema,
            (string) ($env->protocolVersion ?? ''),
            $keyId,
            (string) ($env->keyVersion ?? 1),
            (string) ($env->rootKeyId ?? ''),
            (string) ($env->requestId ?? ''),
            (string) ($env->nonce ?? ''),
            strtoupper((string) ($env->method ?? '')),
            (string) ($env->path ?? ''),
            (string) ($env->timestamp ?? ''),
            (string) ($env->httpStatus ?? ''),
            (string) ($env->decision ?? ''),
            (string) ($env->code ?? ''),
            (string) ($env->productSlug ?? ''),
            isset($env->licenseId) && $env->licenseId !== null ? (string) $env->licenseId : '',
            (string) ($env->installationId ?? ''),
            (string) ($env->domain ?? ''),
            (string) ($env->licenseStatus ?? ''),
            (string) ($env->expiresAt ?? ''),
            (string) ($env->entitlementHash ?? ''),
            (string) ($env->payloadSha256 ?? ''),
        ]);

        if (!self::verifyEd25519Message($canonical, (string) $env->signatureBase64, $trustedKeys[$keyId])) {
            throw new RuntimeException("Assinatura Ed25519 da resposta de runtime inválida (keyId={$keyId}).", 403);
        }
    }

    /**
     * Cifra o array de estado local da licença no formato `k7st.v1.<salt>.<iv>.<tag>.<cipher>`
     * usando derivação HKDF-SHA256 e cifragem autenticada AES-256-GCM com AAD `k7st.v1`.
     *
     * @param array<string, mixed> $state Dados do estado da instalação a serem persistidos.
     * @param string|null $customSecret Segredo opcional para derivação da chave simétrica.
     * @return string Envelope cifrado `k7st.v1` pronto para gravação em arquivo.
     * @throws RuntimeException Se a cifragem AES-256-GCM falhar.
     * @throws \JsonException Se o array `$state` não puder ser serializado em JSON.
     */
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

    /**
     * Decifra e autentica o conteúdo de um arquivo de estado local `k7st.v1` usando HKDF-SHA256 + AES-256-GCM.
     * Mantém compatibilidade retroativa com arquivos JSON em texto plano iniciados por `{`.
     *
     * @param string $rawContent Conteúdo bruto lido do arquivo de estado local.
     * @param string|null $customSecret Segredo opcional correspondente ao usado na cifragem.
     * @return array<string, mixed>|null Dados decifrados do estado ou `null` se o conteúdo estiver vazio.
     * @throws RuntimeException Se o formato do envelope for inválido ou a autenticação GCM falhar.
     */
    public static function decodeEncryptedState(string $rawContent, ?string $customSecret = null): ?array
    {
        $trimmed = trim($rawContent);
        if ($trimmed === '') {
            return null;
        }
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
     * @throws RuntimeException Se o OpenSSL falhar ao gerar o par de chaves ou extrair a chave pública SPKI.
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

    /**
     * Deriva a chave simétrica AES-256 (32 bytes) da sessão de transporte usando acordo de chaves ECDH P-256
     * combinado com HKDF-SHA256 (info `k7-web-wire-v1` e salt `$sessionId`).
     *
     * @param \OpenSSLAsymmetricKey $clientPrivateKey Chave privada efêmera ECDH do cliente.
     * @param string $sessionId Identificador da sessão usado como salt na derivação HKDF.
     * @param string $serverPublicKeySpkiBase64 Chave pública efêmera ECDH do servidor (SPKI em Base64).
     * @return string Chave binária AES-256 de 32 bytes.
     * @throws RuntimeException Se a chave pública do servidor for inválida ou `openssl_pkey_derive` falhar/estiver ausente.
     */
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

    /**
     * Sela (cifra e autentica) um payload JSON de requisição no formato `k7seal.v1.<iv>.<tag>.<cipher>`
     * usando AES-256-GCM e dados autenticados adicionais (AAD) vinculados ao contexto HTTP/sessão.
     *
     * @param array<string, mixed> $payload Dados da requisição a serem cifrados.
     * @param string $aesKeyRaw Chave simétrica AES-256 bruta de 32 bytes derivada da sessão ECDH.
     * @param string $aad Dados autenticados adicionais (ex.: `METHOD:PATH:SESSION:NONCE`).
     * @return string Envelope selado `k7seal.v1`.
     * @throws RuntimeException Se a cifragem AES-256-GCM falhar.
     * @throws \JsonException Se o payload não puder ser codificado em JSON.
     */
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

    /**
     * Deslacra e autentica um envelope `k7seal.v1` recebido do servidor, retornando a string JSON bruta
     * original (preservando estrutura exata para verificação posterior de `signatureEnvelope`).
     *
     * @param string $sealedEnvelope String no formato `k7seal.v1.<iv>.<tag>.<cipher>`.
     * @param string $aesKeyRaw Chave simétrica AES-256 bruta de 32 bytes da sessão ativa.
     * @param string $aad Dados autenticados adicionais esperados (devem coincidir com os usados na cifragem).
     * @return string JSON bruto decifrado e autenticado.
     * @throws RuntimeException Se o envelope estiver malformado (HTTP 400) ou a tag GCM falhar (HTTP 403).
     */
    public static function unsealWirePayloadRaw(string $sealedEnvelope, string $aesKeyRaw, string $aad): string
    {
        $parts = explode('.', trim($sealedEnvelope));
        if (count($parts) !== 5 || $parts[0] !== 'k7seal' || $parts[1] !== 'v1') {
            throw new RuntimeException('Envelope de resposta cifrado k7seal.v1 inválido.', 400);
        }
        $iv = self::base64UrlDecode($parts[2]);
        $tag = self::base64UrlDecode($parts[3]);
        $cipher = self::base64UrlDecode($parts[4]);

        $plain = openssl_decrypt($cipher, 'aes-256-gcm', $aesKeyRaw, OPENSSL_RAW_DATA, $iv, $tag, $aad);
        if (!is_string($plain)) {
            throw new RuntimeException('Falha ao autenticar/decifrar envelope de resposta do servidor.', 403);
        }
        return $plain;
    }

    /**
     * Deslacra um envelope `k7seal.v1` e decodifica seu conteúdo JSON para array associativo PHP.
     *
     * @param string $sealedEnvelope String no formato `k7seal.v1.<iv>.<tag>.<cipher>`.
     * @param string $aesKeyRaw Chave simétrica AES-256 bruta de 32 bytes da sessão ativa.
     * @param string $aad Dados autenticados adicionais esperados.
     * @return array<string, mixed> Payload JSON decodificado em array associativo.
     * @throws RuntimeException Se o envelope for inválido ou falhar na autenticação AES-256-GCM.
     */
    public static function unsealWirePayload(string $sealedEnvelope, string $aesKeyRaw, string $aad): array
    {
        $plain = self::unsealWirePayloadRaw($sealedEnvelope, $aesKeyRaw, $aad);
        $decoded = json_decode($plain, true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * Verifica a assinatura Ed25519 e o schema (`k7-web-release-v1`) do manifesto JSON de uma release.
     *
     * @param string $manifestJson String JSON bruta do manifesto da release.
     * @param string $sigBase64 Assinatura Ed25519 do manifesto em Base64.
     * @param string $publicKeyPem Chave pública Ed25519 confiável (PEM) correspondente ao `signingKeyId`.
     * @return array<string, mixed> Manifesto decodificado e autenticado.
     * @throws RuntimeException Se a assinatura Ed25519 for rejeitada ou o schema do manifesto for inválido (HTTP 403).
     */
    public static function verifyEd25519Manifest(string $manifestJson, string $sigBase64, string $publicKeyPem): array
    {
        if (!self::verifyEd25519Message($manifestJson, $sigBase64, $publicKeyPem)) {
            throw new RuntimeException('Assinatura Ed25519 do manifesto rejeitada.', 403);
        }

        $manifest = json_decode($manifestJson, true);
        if (!is_array($manifest) || ($manifest['schema'] ?? '') !== 'k7-web-release-v1') {
            throw new RuntimeException('Schema de manifesto inválido.', 403);
        }
        return $manifest;
    }
}