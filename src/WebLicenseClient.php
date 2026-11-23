<?php
declare(strict_types=1);

namespace KSeven\WebLicense;

use KSeven\WebLicense\Crypto\Codec;
use KSeven\WebLicense\Exception\WebLicenseException;
use KSeven\WebLicense\Support\Env;
use KSeven\WebLicense\Storage\EncryptedStateStore;
use RuntimeException;

/**
 * K'Seven Web Licensing SDK (PHP 8.1+ Composer PSR-4)
 * - Estado local criptografado (AES-256-GCM + HKDF-SHA256)
 * - Transporte selado complementar a TLS/HTTPS (ECDH P-256 + AES-256-GCM k7seal.v1 com AAD METHOD:PATH:SESSION:NONCE)
 * - Proteção anti-replay (x-k7-web-timestamp + x-k7-web-nonce)
 * - Verificação Ed25519 da cadeia raiz -> ativa/secundária (/keys), handshake ECDH e respostas runtime (ALLOW/DENY)
 */
final class WebLicenseClient
{

    /** 
     * @var string URL base da API de licenciamento (sem barra final). 
     */
    private string $apiBaseUrl;

    /** 
     * @var string Identificador padrão da plataforma cliente (ex.: "php", "web", "wordpress").
     */
    private string $platform;

    /** 
     * @var int Tempo limite em segundos para requisições HTTP e handshakes cURL (mínimo 3s). 
     */
    private int $timeoutSeconds;

    /** 
     * @var bool Permite conexões HTTP sem TLS exclusivamente para hosts locais (localhost, 127.0.0.1, ::1). 
     */
    private bool $allowInsecureLocalHttp;

    /** 
     * @var bool Habilita a negociação de sessão efêmera ECDH + cifragem de payload AES-256-GCM (k7seal.v1). 
     */
    private bool $useEncryptedTransport;

    /** 
     * @var bool Exige transporte selado k7seal.v1, lançando exceção caso a negociação ECDH falhe ou seja indisponível. 
     */
    private bool $requireSealedTransport;

    /** 
     * @var string|null Chave pública raiz Ed25519 (PEM) pinada para validar a cadeia de chaves do servidor.
     */
    private ?string $pinnedRootPublicKeyPem;

    /** 
     * @var bool Controla se as assinaturas Ed25519 de handshake ECDH e respostas runtime serão verificadas.
     */
    private bool $verifyResponseSignatures;

    /**
     * Mapa estático de chaves públicas Ed25519 confiáveis pinadas na configuração (keyId => publicKeyPem).
     *
     * @var array<string, string>
     */
    private array $pinnedPublicKeys;

    /**
     * Cache em memória das chaves públicas Ed25519 descobertas e validadas via `/keys` ou `/releases/public-key`.
     *
     * @var array<string, string>
     */
    private array $discoveredTrustedKeys = [];

    /** 
     * @var string|null Chave pública do cliente (PEM) enviada na ativação para autenticação mútua de requisições. 
     */
    private ?string $clientPublicKeyPem;

    /** 
     * @var string|null Chave privada do cliente (PEM) usada para assinar requisições autenticadas (`x-k7-web-client-signature`).
     */
    private ?string $clientPrivateKeyPem;

    /** 
     * @var EncryptedStateStore Gerenciador de leitura e gravação cifrada (AES-256-GCM) do estado local da instalação. 
     */
    private EncryptedStateStore $stateStore;

    /**
     * Sessão criptográfica efêmera ativa em memória para selagem de transporte (`k7seal.v1`).
     *
     * @var array{sessionId: string, aesKey: string, expiresAt: int}|null
     */
    private ?array $wireSession = null;

    /**
     * Inicializa o cliente de licenciamento web e configura armazenamento local, transporte cifrado e pinning de chaves.
     *
     * @param array{
     *   apiBaseUrl: string,
     *   stateFilePath?: string,
     *   stateSecret?: string,
     *   platform?: string,
     *   timeoutSeconds?: int,
     *   allowInsecureLocalHttp?: bool,
     *   useEncryptedTransport?: bool,
     *   requireSealedTransport?: bool,
     *   pinnedRootPublicKeyPem?: string,
     *   verifyResponseSignatures?: bool,
     *   pinnedPublicKeys?: array<string, string>,
     *   clientPublicKeyPem?: string,
     *   clientPrivateKeyPem?: string
     * } $config Configurações de conexão, segurança e persistência do SDK.
     * @throws RuntimeException Se `apiBaseUrl` estiver ausente ou utilizar protocolo/host não permitido.
     */
    public function __construct(array $config = [])
    {
        $rawUrl = (string) ($config['apiBaseUrl'] ?? Env::get('K7_WEB_API_URL') ?? '');
        if ($rawUrl === '') {
            throw new RuntimeException('apiBaseUrl é obrigatório (informe via $config ou K7_WEB_API_URL).');
        }

        $this->apiBaseUrl = rtrim($rawUrl, '/');
        $this->allowInsecureLocalHttp = (bool) ($config['allowInsecureLocalHttp'] ?? Env::bool('K7_ALLOW_LOCAL_HTTP', false));
        $this->assertAllowedUrl($this->apiBaseUrl);

        $stateFilePath = (string) ($config['stateFilePath'] ?? Env::get('K7_WEB_STATE_FILE') ?? (getcwd() . '/.kseven-web-license.dat'));
        $stateSecret = isset($config['stateSecret']) ? (string) $config['stateSecret'] : Env::get('K7_WEB_STATE_SECRET');
        $this->stateStore = new EncryptedStateStore($stateFilePath, $stateSecret);

        $this->platform = (string) ($config['platform'] ?? Env::get('K7_WEB_PLATFORM') ?? 'php');
        $this->timeoutSeconds = max(3, (int) ($config['timeoutSeconds'] ?? Env::int('K7_WEB_TIMEOUT', 15)));

        $plainEnv = Env::bool('K7_WEB_PLAIN_TRANSPORT', false);
        $this->useEncryptedTransport = ($config['useEncryptedTransport'] ?? !$plainEnv) !== false;
        $this->requireSealedTransport = (bool) ($config['requireSealedTransport'] ?? Env::bool('K7_WEB_REQUIRE_SEALED', false));
        $this->pinnedRootPublicKeyPem = !empty($config['pinnedRootPublicKeyPem']) ? trim((string) $config['pinnedRootPublicKeyPem']) : Env::get('K7_WEB_ROOT_PUBLIC_KEY');
        $this->verifyResponseSignatures = ($config['verifyResponseSignatures'] ?? true) !== false;
        $this->pinnedPublicKeys = $config['pinnedPublicKeys'] ?? [];
        $this->clientPublicKeyPem = !empty($config['clientPublicKeyPem']) ? trim((string) $config['clientPublicKeyPem']) : null;
        $this->clientPrivateKeyPem = !empty($config['clientPrivateKeyPem']) ? trim((string) $config['clientPrivateKeyPem']) : null;
    }

    /**
     * Normaliza um host HTTP recebido (por exemplo de `$_SERVER['HTTP_HOST']`), removendo
     * porta explícita (`localhost:8080` -> `localhost`, `[::1]:8080` -> `::1`) e normalizando caixa.
     * Não altera entradas contendo esquema, caminho ou userinfo para que entradas malformadas
     * sejam rejeitadas explicitamente pela API.
     */
    public static function normalizeHostInput(string $rawHost): string
    {
        $trimmed = strtolower(trim($rawHost));
        if ($trimmed === '') {
            return '';
        }
        // Mantém entradas com esquema, caminho, query ou userinfo intactas para rejeição explícita
        if (str_contains($trimmed, '://') || str_contains($trimmed, '/') || str_contains($trimmed, '@') || str_contains($trimmed, '?')) {
            return $trimmed;
        }
        // IPv6 entre colchetes com ou sem porta: [::1] ou [::1]:8080
        if (preg_match('/^\[([0-9a-f:]+)\](?::\d{1,5})?$/', $trimmed, $m) === 1) {
            return $m[1];
        }
        // Hostname ou IPv4 com porta explícita (um único ':')
        if (substr_count($trimmed, ':') === 1) {
            $parts = explode(':', $trimmed, 2);
            if ($parts[0] !== '' && ctype_digit($parts[1])) {
                return rtrim($parts[0], '.');
            }
        }
        return rtrim($trimmed, '.');
    }

    /**
     * Verifica estritamente se o host corresponde a um ambiente local de desenvolvimento suportado:
     * `localhost`, `127.0.0.1`, `::1` (ou `[::1]`) ou subdomínio estrito `*.localhost` (RFC 1123).
     * Rejeita variações ambíguas (ex.: `localhost.evil.com`, `foo.localhost.com`, `127.0.0.2`,
     * `0.0.0.0`, IPs privados genéricos e entradas com porta/caminho).
     */
    public static function isLocalhostDevelopmentHost(string $host): bool
    {
        $value = strtolower(trim($host));
        if ($value === '' || strlen($value) > 253) {
            return false;
        }
        if (str_contains($value, '://') || str_contains($value, '/') || str_contains($value, '@') || str_contains($value, '?') || str_contains($value, '#')) {
            return false;
        }
        if ($value === '[::1]') {
            $value = '::1';
        }
        if ($value === 'localhost' || $value === '127.0.0.1' || $value === '::1') {
            return true;
        }
        if (str_contains($value, ':')) {
            return false;
        }
        if (!str_ends_with($value, '.localhost')) {
            return false;
        }
        $prefix = substr($value, 0, -strlen('.localhost'));
        if ($prefix === '' || str_starts_with($prefix, '.') || str_ends_with($prefix, '.')) {
            return false;
        }
        $labels = explode('.', $prefix);
        foreach ($labels as $label) {
            if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $label) !== 1) {
                return false;
            }
        }
        return true;
    }

    /**
     * Cria um desafio de validação de propriedade de domínio (ex.: registro DNS TXT ou arquivo HTTP).
     *
     * @param string $licenseKey Chave de licença associada ao domínio.
     * @param string $domain Domínio a ser verificado (ex.: "exemplo.com.br").
     * @param string $method Método de validação do desafio (padrão: "DNS_TXT").
     * @return array<string, mixed> Dados do desafio gerado, incluindo ID, token esperado e instruções.
     * @throws RuntimeException Em caso de falha de comunicação ou rejeição pela API.
     */
    public function createDomainChallenge(
        string $licenseKey,
        string $domain,
        string $method = 'DNS_TXT',
        ?string $environment = null,
        ?bool $allowSubdomains = null
    ): array {
        $payload = [
            'licenseKey' => $licenseKey,
            'domain' => $domain,
            'method' => $method,
        ];
        if ($environment !== null && trim($environment) !== '') {
            $payload['environment'] = strtoupper(trim($environment));
        }
        if ($allowSubdomains !== null) {
            $payload['allowSubdomains'] = $allowSubdomains;
        }
        return $this->request('POST', '/domain-challenges', $payload);
    }

    /**
     * Solicita ao servidor a verificação imediata de um desafio de domínio previamente criado.
     *
     * @param string $challengeId Identificador único do desafio retornado em `createDomainChallenge()`.
     * @param string|null $licenseKey Chave de licença opcional para autenticação adicional da verificação.
     * @return array<string, mixed> Resultado da verificação do domínio.
     * @throws RuntimeException Se o desafio falhar, expirar ou ocorrer erro HTTP.
     */
    public function verifyDomainChallenge(string $challengeId, ?string $licenseKey = null): array
    {
        $body = $licenseKey ? ['licenseKey' => $licenseKey] : [];
        return $this->request('POST', '/domain-challenges/' . rawurlencode($challengeId) . '/verify', $body);
    }

    /**
     * Ativa uma nova instalação da licença e persiste o estado/credencial cifrado localmente em AES-256-GCM (0600).
     */
    public function install(array $options): array
    {
        $rawDomain = (string) ($options['domain'] ?? '');
        $domain = self::normalizeHostInput($rawDomain);
        if ($domain === '') {
            throw new WebLicenseException('O parâmetro domain é obrigatório para install().', 400, 'INVALID_DOMAIN');
        }

        $platform = (string) ($options['platform'] ?? $this->platform);
        $isLocalDevHost = self::isLocalhostDevelopmentHost($domain);
        $explicitEnv = isset($options['environment']) && trim((string) $options['environment']) !== ''
            ? trim((string) $options['environment'])
            : null;
        $environment = $explicitEnv ?? ($isLocalDevHost ? 'development' : 'production');

        $fingerprint = $options['instanceFingerprint'] ?? substr(
            hash('sha256', (gethostname() ?: 'php-host') . ':' . $platform . ':' . $domain),
            0,
            32
        );
        $idempotencyKey = $options['idempotencyKey'] ?? "install-{$platform}-{$fingerprint}";
        $clientPub = $options['clientPublicKeyPem'] ?? $this->clientPublicKeyPem;
        $clientPriv = $options['clientPrivateKeyPem'] ?? $this->clientPrivateKeyPem;
        $requireSealed = isset($options['requireSealedTransport'])
            ? (bool) $options['requireSealedTransport']
            : $this->requireSealedTransport;

        $payload = [
            'licenseKey' => $options['licenseKey'],
            'domain' => $domain,
            'platform' => $platform,
            'appVersion' => $options['appVersion'],
            'environment' => $environment,
            'instanceFingerprint' => $fingerprint,
            'idempotencyKey' => $idempotencyKey,
            'protocolVersion' => '1.1',
        ];
        if ($clientPub) {
            $payload['clientPublicKeyPem'] = $clientPub;
        }
        if ($requireSealed) {
            $payload['requireSealedTransport'] = true;
        }

        $rawResponseJson = null;
        $res = $this->request('POST', '/activate', $payload, null, [], true, null, $rawResponseJson);
        if (empty($res['installationId']) || empty($res['installationCredential'])) {
            throw new WebLicenseException(
                'Resposta inválida do servidor durante ativação: credencial da instalação ausente.',
                502,
                'INVALID_ACTIVATION_RESPONSE'
            );
        }

        $publicKeys = $this->fetchPublicKeysMap([], true);
        $now = gmdate('c');
        $installationType = strtoupper((string) ($res['installationType'] ?? ($isLocalDevHost ? 'DEVELOPMENT' : 'PRODUCTION')));
        $resolvedEnv = (string) ($res['environment'] ?? ($installationType === 'DEVELOPMENT' ? 'development' : $environment));
        $allowLocalhostDev = (bool) ($res['allowLocalhostDevelopment'] ?? ($res['entitlement']['allowLocalhostDevelopment'] ?? ($installationType === 'DEVELOPMENT')));
        $graceUntil = $res['entitlement']['offlineValidation']['graceUntil'] ?? ($res['entitlement']['graceUntil'] ?? null);

        $state = [
            'apiBaseUrl' => $this->apiBaseUrl,
            'installationId' => (string) $res['installationId'],
            'installationCredential' => (string) $res['installationCredential'],
            'credentialPrefix' => $res['credentialPrefix'] ?? null,
            'credentialVersion' => $res['credentialVersion'] ?? 1,
            'domain' => (string) ($res['domain'] ?? $domain),
            'platform' => (string) ($res['platform'] ?? $platform),
            'appVersion' => (string) ($res['appVersion'] ?? $options['appVersion']),
            'environment' => $resolvedEnv,
            'installationType' => $installationType,
            'allowLocalhostDevelopment' => $allowLocalhostDev,
            'instanceFingerprint' => $fingerprint,
            'installedAt' => $now,
            'updatedAt' => $now,
            'lastValidatedAt' => $now,
            'graceUntil' => $graceUntil,
            'lastSignedEntitlement' => $res['entitlement'] ?? null,
            'lastSignedValidationRawJson' => !empty($res['signatureEnvelope']) ? $rawResponseJson : null,
            'pinnedPublicKeys' => $publicKeys,
            'protocolVersion' => '1.1',
        ];
        if ($this->pinnedRootPublicKeyPem) {
            $state['pinnedRootPublicKeyPem'] = $this->pinnedRootPublicKeyPem;
        }
        if ($clientPub) {
            $state['clientPublicKeyPem'] = $clientPub;
        }
        if ($clientPriv) {
            $state['clientPrivateKeyPem'] = $clientPriv;
        }
        if ($requireSealed) {
            $state['requireSealedTransport'] = true;
        }

        $this->stateStore->write($state);

        return [
            'installed' => true,
            'installationId' => $state['installationId'],
            'domain' => $state['domain'],
            'platform' => $state['platform'],
            'appVersion' => $state['appVersion'],
            'environment' => $state['environment'],
            'installationType' => $state['installationType'],
            'allowLocalhostDevelopment' => $state['allowLocalhostDevelopment'],
            'idempotentReplay' => (bool) ($res['idempotentReplay'] ?? false),
            'encryptedTransport' => $this->wireSession !== null,
            'entitlement' => $res['entitlement'] ?? null,
        ];
    }

    /**
     * Valida online o status atual da licença instalada e persiste comprovante assinado para operação em carência offline.
     *
     * @param string|null $appVersion Nova versão da aplicação a ser reportada e sincronizada no estado local.
     * @param bool $allowOfflineGrace Quando true, cai para validação offline assinada em falhas transitórias de rede/503.
     * @return array<string, mixed>
     */
    public function validate(?string $appVersion = null, bool $allowOfflineGrace = false): array
    {
        $state = $this->requireState();
        $payload = ['domain' => $state['domain']];
        if ($appVersion !== null && $appVersion !== '') {
            $payload['appVersion'] = $appVersion;
        }
        try {
            $rawResponseJson = null;
            $res = $this->request('POST', '/validate', $payload, $state['installationCredential'], [], true, $state, $rawResponseJson);
            $now = gmdate('c');
            if ($appVersion !== null && $appVersion !== '') {
                $state['appVersion'] = $appVersion;
            }
            $state['updatedAt'] = $now;
            $state['lastValidatedAt'] = $now;
            $state['graceUntil'] = $res['entitlement']['offlineValidation']['graceUntil']
                ?? ($res['entitlement']['graceUntil'] ?? ($state['graceUntil'] ?? null));
            if (isset($res['entitlement']) && is_array($res['entitlement'])) {
                $state['lastSignedEntitlement'] = $res['entitlement'];
            }
            if (!empty($res['signatureEnvelope']) && is_string($rawResponseJson)) {
                $state['lastSignedValidationRawJson'] = $rawResponseJson;
            }
            $state['pinnedPublicKeys'] = array_merge(
                $state['pinnedPublicKeys'] ?? [],
                $this->discoveredTrustedKeys,
                $this->pinnedPublicKeys
            );
            $this->stateStore->write($state);
            return $res;
        } catch (WebLicenseException $e) {
            $isTransient = $e->getErrorCode() === 'NETWORK_ERROR'
                || in_array($e->getHttpStatus(), [502, 503, 504], true);
            if ($allowOfflineGrace && $isTransient) {
                return $this->validateOffline();
            }
            throw $e;
        }
    }

    /**
     * Valida offline o último comprovante Ed25519 assinado armazenado no estado cifrado,
     * bloqueando imediatamente se expirado, adulterado ou em status REVOKED/SUSPENDED.
     *
     * @return array<string, mixed>
     */
    public function validateOffline(?int $nowTs = null): array
    {
        $state = $this->requireState();
        $rawSigned = (string) ($state['lastSignedValidationRawJson'] ?? '');
        if ($rawSigned === '') {
            throw new WebLicenseException(
                'Nenhum comprovante assinado disponível para validação offline.',
                403,
                'OFFLINE_CACHE_MISSING'
            );
        }
        $trustedKeys = array_merge(
            $state['pinnedPublicKeys'] ?? [],
            $this->discoveredTrustedKeys,
            $this->pinnedPublicKeys
        );
        try {
            $verified = Codec::verifyCachedOfflineEntitlement(
                $rawSigned,
                $trustedKeys,
                (string) $state['installationId'],
                (string) $state['domain'],
                $nowTs
            );
        } catch (RuntimeException $e) {
            throw new WebLicenseException($e->getMessage(), 403, 'OFFLINE_VALIDATION_FAILED');
        }

        return [
            'valid' => true,
            'offline' => true,
            'inGracePeriod' => true,
            'graceUntil' => $verified['graceUntil'],
            'lastValidatedAt' => $state['lastValidatedAt'] ?? $verified['issuedAt'],
            'installationId' => $state['installationId'],
            'domain' => $state['domain'],
            'entitlement' => $verified['entitlement'],
            'signatureKeyId' => $verified['keyId'],
        ];
    }

    /**
     * Transfere o slot da instalação atual para outro domínio verificado da mesma licença sem nova compra.
     *
     * @param array{
     *   toDomain: string,
     *   reason?: string,
     *   immediateActivate?: bool,
     *   platform?: string,
     *   appVersion?: string,
     *   instanceFingerprint?: string,
     *   clientPublicKeyPem?: string,
     *   requireSealedTransport?: bool
     * } $options
     * @return array<string, mixed>
     */
    public function transferInstallation(array $options): array
    {
        $state = $this->requireState();
        $payload = ['toDomain' => self::normalizeHostInput((string) ($options['toDomain'] ?? ''))];
        foreach (['reason', 'immediateActivate', 'platform', 'appVersion', 'instanceFingerprint', 'clientPublicKeyPem', 'requireSealedTransport'] as $k) {
            if (array_key_exists($k, $options) && $options[$k] !== null) {
                $payload[$k] = $options[$k];
            }
        }
        $rawResponseJson = null;
        $res = $this->request('POST', '/installations/transfer', $payload, $state['installationCredential'], [], true, $state, $rawResponseJson);
        $now = gmdate('c');

        if (empty($res['pendingReview']) && !empty($res['newInstallation']['installationCredential'])) {
            $newInst = $res['newInstallation'];
            $state['installationId'] = (string) $newInst['installationId'];
            $state['installationCredential'] = (string) $newInst['installationCredential'];
            $state['credentialPrefix'] = $newInst['credentialPrefix'] ?? null;
            $state['credentialVersion'] = $newInst['credentialVersion'] ?? 1;
            $state['domain'] = (string) ($newInst['domain'] ?? $payload['toDomain']);
            $state['appVersion'] = (string) ($newInst['appVersion'] ?? $state['appVersion']);
            $state['updatedAt'] = $now;
            $state['lastValidatedAt'] = $now;
            $state['graceUntil'] = $res['entitlement']['offlineValidation']['graceUntil']
                ?? ($res['entitlement']['graceUntil'] ?? null);
            $state['lastSignedEntitlement'] = $res['entitlement'] ?? null;
            $state['lastSignedValidationRawJson'] = !empty($res['signatureEnvelope']) ? $rawResponseJson : null;
            $this->stateStore->write($state);
        } elseif (empty($res['pendingReview']) && !empty($res['sourceRevoked'])) {
            $this->stateStore->write(null);
        }

        return $res;
    }

    /**
     * Consulta os direitos, recursos e limites (entitlements) liberados para a licença ativa.
     */
    public function entitlements(): array
    {
        $state = $this->requireState();
        return $this->request('GET', '/entitlements', null, $state['installationCredential'], [], true, $state);
    }

    /**
     * Adquire um lease (bloqueio temporário de uso/concorrência) para a instalação atual.
     */
    public function acquireLease(int $ttlSeconds = 180, ?string $idempotencyKey = null): array
    {
        $state = $this->requireState();
        $payload = ['ttlSeconds' => $ttlSeconds];
        if ($idempotencyKey !== null && $idempotencyKey !== '') {
            $payload['idempotencyKey'] = $idempotencyKey;
        }
        return $this->request('POST', '/leases/acquire', $payload, $state['installationCredential'], [], true, $state);
    }

    /**
     * Renova o tempo de expiração (heartbeat) de um lease ativo.
     */
    public function heartbeatLease(string $leaseId, ?string $leaseToken = null): array
    {
        $state = $this->requireState();
        $payload = $leaseToken ? ['leaseToken' => $leaseToken] : [];
        return $this->request(
            'POST',
            '/leases/' . rawurlencode($leaseId) . '/heartbeat',
            $payload,
            $state['installationCredential'],
            [],
            true,
            $state
        );
    }

    /**
     * Libera explicitamente um lease ativo antes da expiração do seu TTL.
     */
    public function releaseLease(string $leaseId): array
    {
        $state = $this->requireState();
        return $this->request(
            'POST',
            '/leases/' . rawurlencode($leaseId) . '/release',
            [],
            $state['installationCredential'],
            [],
            true,
            $state
        );
    }

    /**
     * Lista releases compatíveis e versões disponíveis para rollback na licença instalada.
     */
    public function listCompatibleReleases(
        string $channel = 'stable',
        ?string $currentVersion = null,
        ?string $releaseKind = null
    ): array {
        $state = $this->requireState();
        $params = [
            'channel' => $channel === 'beta' ? 'beta' : 'stable',
            'currentVersion' => $currentVersion ?: $state['appVersion'],
        ];
        if ($releaseKind !== null && trim($releaseKind) !== '') {
            $params['releaseKind'] = strtoupper(trim($releaseKind));
        }
        return $this->request(
            'GET',
            '/updates/releases?' . http_build_query($params),
            null,
            $state['installationCredential'],
            [],
            true,
            $state
        );
    }

    /**
     * Verifica se há uma nova versão disponível no canal especificado e valida a assinatura Ed25519 do manifesto.
     */
    public function checkVersion(
        string $channel = 'stable',
        ?string $currentVersion = null,
        ?string $releaseKind = null
    ): array {
        $state = $this->requireState();
        $ch = $channel === 'beta' ? 'beta' : 'stable';
        $ver = $currentVersion ?: $state['appVersion'];

        $params = ['channel' => $ch, 'currentVersion' => $ver];
        if ($releaseKind !== null && trim($releaseKind) !== '') {
            $params['releaseKind'] = strtoupper(trim($releaseKind));
        }
        $res = $this->request('GET', '/updates/check?' . http_build_query($params), null, $state['installationCredential'], [], true, $state);

        if (empty($res['latestRelease'])) {
            return [
                'updateAvailable' => false,
                'channel' => $ch,
                'currentVersion' => $ver,
                'latestRelease' => null,
                'availableRollbacks' => is_array($res['availableRollbacks'] ?? null) ? $res['availableRollbacks'] : [],
                'updatesActive' => $res['updatesActive'] ?? true,
                'updatesExpiresAt' => $res['updatesExpiresAt'] ?? null,
                'signatureVerified' => true,
            ];
        }

        $rel = $res['latestRelease'];
        $keysMap = $this->fetchPublicKeysMap($state['pinnedPublicKeys'] ?? [], false);
        $keyId = (string) ($rel['signingKeyId'] ?? '');
        $pem = $this->pinnedPublicKeys[$keyId] ?? $keysMap[$keyId] ?? '';
        if ($pem === '') {
            $keysMap = $this->fetchPublicKeysMap($state['pinnedPublicKeys'] ?? [], true);
            $pem = $this->pinnedPublicKeys[$keyId] ?? $keysMap[$keyId] ?? '';
        }
        if ($pem === '' && $this->pinnedRootPublicKeyPem === null) {
            $pem = (string) ($rel['publicKeyPem'] ?? '');
        }
        if (!$pem) {
            throw new RuntimeException("Chave pública Ed25519 confiável ausente para keyId={$keyId}", 403);
        }

        $manifest = Codec::verifyEd25519Manifest(
            (string) $rel['manifestJson'],
            (string) $rel['manifestSignature'],
            $pem
        );

        if (
            ($manifest['version'] ?? '') !== ($rel['version'] ?? '') ||
            ($manifest['packageSha256'] ?? '') !== ($rel['packageSha256'] ?? '')
        ) {
            throw new RuntimeException('Divergência entre manifesto assinado e metadados da release.', 403);
        }

        return [
            'updateAvailable' => !empty($res['updateAvailable']),
            'channel' => $ch,
            'currentVersion' => $res['currentVersion'] ?? $ver,
            'latestRelease' => $rel,
            'availableRollbacks' => is_array($res['availableRollbacks'] ?? null) ? $res['availableRollbacks'] : [],
            'updatesActive' => $res['updatesActive'] ?? true,
            'updatesExpiresAt' => $res['updatesExpiresAt'] ?? null,
            'signatureVerified' => true,
        ];
    }

    private function downloadAndApplyRelease(array $state, array $rel, array $options, bool $isRollback = false): array
    {
        $grant = $this->request(
            'POST',
            '/updates/' . (int) $rel['releaseId'] . '/download-grants',
            ['maxDownloads' => 1],
            $state['installationCredential'],
            [],
            true,
            $state
        );

        $consumed = $this->request(
            'GET',
            '/updates/download/' . rawurlencode((string) $grant['grantId']),
            null,
            null,
            ['x-download-grant-token: ' . $grant['grantToken']]
        );

        $keysMap = $this->fetchPublicKeysMap($state['pinnedPublicKeys'] ?? [], false);
        $keyId = (string) ($consumed['signingKeyId'] ?? '');
        $pem = $this->pinnedPublicKeys[$keyId] ?? $keysMap[$keyId] ?? '';
        if ($pem === '') {
            $keysMap = $this->fetchPublicKeysMap($state['pinnedPublicKeys'] ?? [], true);
            $pem = $this->pinnedPublicKeys[$keyId] ?? $keysMap[$keyId] ?? '';
        }
        if ($pem === '' && $this->pinnedRootPublicKeyPem === null) {
            $pem = (string) ($rel['publicKeyPem'] ?? '');
        }
        if (!$pem) {
            throw new RuntimeException("Chave pública Ed25519 confiável ausente para keyId={$keyId}", 403);
        }

        $verifiedManifest = Codec::verifyEd25519Manifest(
            (string) $consumed['manifestJson'],
            (string) $consumed['manifestSignature'],
            $pem
        );

        $packageUrl = (string) ($consumed['packageUrl'] ?? '');
        if (str_starts_with($packageUrl, '/api/')) {
            $packageUrl = $this->apiBaseUrl . $packageUrl;
        }
        $this->assertAllowedUrl($packageUrl);

        $tmpFile = tempnam(sys_get_temp_dir(), 'k7pkg_');
        if ($tmpFile === false) {
            throw new RuntimeException('Falha ao criar arquivo temporário de download.');
        }

        try {
            $this->downloadFile($packageUrl, $tmpFile);
            $actualSha = strtolower((string) hash_file('sha256', $tmpFile));
            $expectedSha = strtolower((string) $verifiedManifest['packageSha256']);
            if (!hash_equals($expectedSha, $actualSha)) {
                throw new RuntimeException("SHA-256 inválido: esperado {$expectedSha}, obtido {$actualSha}.");
            }
            $expectedSize = (int) ($verifiedManifest['packageSizeBytes'] ?? 0);
            if ($expectedSize > 0 && filesize($tmpFile) !== $expectedSize) {
                throw new RuntimeException('Tamanho do pacote diverge do manifesto assinado.');
            }

            $savedFilePath = null;
            if (!empty($options['destDir'])) {
                $fileName = $options['downloadFileName'] ?? ($rel['productSlug'] . '-' . $rel['version'] . '-' . $rel['platform'] . '.pkg');
                $savedFilePath = $this->resolveSafeChildPath((string) $options['destDir'], (string) $fileName);
                if (!is_dir((string) $options['destDir'])) {
                    mkdir((string) $options['destDir'], 0750, true);
                }
                if (!copy($tmpFile, $savedFilePath)) {
                    throw new RuntimeException('Não foi possível gravar o pacote verificado no destino.');
                }
                @chmod($savedFilePath, 0640);
            }

            if (isset($options['onVerifiedPackage']) && is_callable($options['onVerifiedPackage'])) {
                ($options['onVerifiedPackage'])($tmpFile, $rel);
            }
        } finally {
            if (is_file($tmpFile)) {
                @unlink($tmpFile);
            }
        }

        $prev = $state['appVersion'];
        $this->validate((string) $rel['version']);

        return [
            'updated' => true,
            'previousVersion' => $prev,
            'currentVersion' => (string) $rel['version'],
            'release' => $rel,
            'savedFilePath' => $savedFilePath,
            'verifiedSha256' => $actualSha,
            'signatureVerified' => true,
            'rollback' => $isRollback,
        ];
    }

    /**
     * Executa o fluxo completo de atualização com verificação Ed25519 e SHA-256.
     */
    public function update(array $options = []): array
    {
        $state = $this->requireState();
        $channel = $options['channel'] ?? 'stable';
        $check = $this->checkVersion($channel, $options['currentVersion'] ?? null, $options['releaseKind'] ?? null);

        if (empty($check['updateAvailable']) || empty($check['latestRelease'])) {
            return [
                'updated' => false,
                'previousVersion' => $state['appVersion'],
                'currentVersion' => $state['appVersion'],
                'release' => $check['latestRelease'] ?? null,
                'signatureVerified' => true,
            ];
        }

        return $this->downloadAndApplyRelease($state, $check['latestRelease'], $options, false);
    }

    /**
     * Reporta progresso e resultado da execução de auto-update ao painel de downloads.
     *
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function reportAutoUpdateProgress(array $payload): array
    {
        $state = $this->requireState();
        return $this->request(
            'POST',
            '/updates/auto-update/report',
            $payload,
            $state['installationCredential'],
            [],
            true,
            $state
        );
    }

    /**
     * Executa atualização Web automática e transacional com validação Ed25519 + SHA-256,
     * backup integral prévio, migrações ordenadas e rollback automático em caso de falha.
     *
     * @param array{
     *   targetDir: string,
     *   applyPackage: callable,
     *   migrations?: array<int, array{id: string, run: callable}>,
     *   channel?: string,
     *   currentVersion?: string,
     *   releaseKind?: string,
     *   preserveNames?: array<int, string>,
     *   reportProgress?: bool
     * } $options
     * @return array<string, mixed>
     */
    public function autoUpdate(array $options): array
    {
        $state = $this->requireState();
        $runUid = 'aur_' . bin2hex(random_bytes(10));
        $channel = ($options['channel'] ?? 'stable') === 'beta' ? 'beta' : 'stable';
        $previousVersion = (string) ($options['currentVersion'] ?? $state['appVersion']);
        $reportProgress = ($options['reportProgress'] ?? true) !== false;

        $check = $this->checkVersion($channel, $previousVersion, $options['releaseKind'] ?? null);
        if (empty($check['updateAvailable']) || empty($check['latestRelease'])) {
            return [
                'runUid' => $runUid,
                'updated' => false,
                'status' => 'UP_TO_DATE',
                'previousVersion' => $previousVersion,
                'currentVersion' => $previousVersion,
                'targetVersion' => null,
                'signatureVerified' => true,
                'sha256Verified' => false,
                'backupCreated' => false,
                'rollbackPerformed' => false,
                'migrationsExecuted' => [],
                'sanitizedError' => null,
            ];
        }

        $rel = $check['latestRelease'];
        $targetDir = rtrim((string) ($options['targetDir'] ?? ''), '/\\');
        if ($targetDir === '' || !isset($options['applyPackage']) || !is_callable($options['applyPackage'])) {
            throw new WebLicenseException('targetDir e applyPackage são obrigatórios em autoUpdate().', 400, 'INVALID_AUTO_UPDATE_OPTIONS');
        }

        $preserve = array_flip(array_merge(['.env', '.kseven-web-license.dat'], $options['preserveNames'] ?? []));
        $stagingDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'k7_autoupdate_' . bin2hex(random_bytes(6));
        $backupDir = $stagingDir . DIRECTORY_SEPARATOR . 'backup';
        @mkdir($stagingDir, 0750, true);

        $signatureVerified = false;
        $sha256Verified = false;
        $backupCreated = false;
        $rollbackPerformed = false;
        $migrationsExecuted = [];

        $safeReport = function (array $patch) use ($reportProgress, $runUid, $channel, $previousVersion, $rel): void {
            if (!$reportProgress) {
                return;
            }
            try {
                $this->reportAutoUpdateProgress(array_merge([
                    'runUid' => $runUid,
                    'releaseId' => (int) ($rel['releaseId'] ?? 0),
                    'channel' => $channel,
                    'fromVersion' => $previousVersion,
                    'toVersion' => (string) ($rel['version'] ?? ''),
                ], $patch));
            } catch (\Throwable) {
                // Reporte best-effort
            }
        };

        try {
            $safeReport(['status' => 'DOWNLOADING', 'progressPercent' => 15, 'currentStep' => 'Baixando pacote verificado em área temporária']);

            $grant = $this->request(
                'POST',
                '/updates/' . (int) $rel['releaseId'] . '/download-grants',
                ['maxDownloads' => 1],
                $state['installationCredential'],
                [],
                true,
                $state
            );
            $consumed = $this->request(
                'GET',
                '/updates/download/' . rawurlencode((string) $grant['grantId']),
                null,
                null,
                ['x-download-grant-token: ' . $grant['grantToken']]
            );

            $safeReport(['status' => 'VERIFYING', 'progressPercent' => 35, 'currentStep' => 'Validando assinatura Ed25519 e SHA-256']);
            $keysMap = $this->fetchPublicKeysMap($state['pinnedPublicKeys'] ?? [], false);
            $keyId = (string) ($consumed['signingKeyId'] ?? '');
            $pem = $this->pinnedPublicKeys[$keyId] ?? $keysMap[$keyId] ?? '';
            if ($pem === '') {
                $keysMap = $this->fetchPublicKeysMap($state['pinnedPublicKeys'] ?? [], true);
                $pem = $this->pinnedPublicKeys[$keyId] ?? $keysMap[$keyId] ?? '';
            }
            if ($pem === '' && $this->pinnedRootPublicKeyPem === null) {
                $pem = (string) ($rel['publicKeyPem'] ?? '');
            }
            if ($pem === '') {
                throw new WebLicenseException("Chave pública Ed25519 ausente para keyId={$keyId}", 403, 'UNKNOWN_SIGNING_KEY');
            }

            $verifiedManifest = Codec::verifyEd25519Manifest(
                (string) $consumed['manifestJson'],
                (string) $consumed['manifestSignature'],
                $pem
            );
            if (($verifiedManifest['version'] ?? '') !== ($rel['version'] ?? '') || ($verifiedManifest['channel'] ?? '') !== $channel) {
                throw new WebLicenseException('Manifesto diverge de versão/canal autorizados.', 403, 'MANIFEST_METADATA_MISMATCH');
            }
            $signatureVerified = true;

            $packageUrl = (string) ($consumed['packageUrl'] ?? '');
            if (str_starts_with($packageUrl, '/api/')) {
                $packageUrl = $this->apiBaseUrl . $packageUrl;
            }
            $this->assertAllowedUrl($packageUrl);

            $tmpPkg = $stagingDir . DIRECTORY_SEPARATOR . 'package.bin';
            $this->downloadFile($packageUrl, $tmpPkg);
            $actualSha = strtolower((string) hash_file('sha256', $tmpPkg));
            $expectedSha = strtolower((string) ($verifiedManifest['packageSha256'] ?? ''));
            if (!hash_equals($expectedSha, $actualSha)) {
                throw new WebLicenseException('SHA-256 do pacote não confere com o manifesto assinado.', 422, 'PACKAGE_SHA256_MISMATCH');
            }
            $sha256Verified = true;

            $safeReport([
                'status' => 'BACKING_UP',
                'progressPercent' => 55,
                'currentStep' => 'Criando backup completo antes de aplicar atualização',
                'signatureVerified' => true,
                'sha256Verified' => true,
            ]);
            if (!is_dir($targetDir)) {
                mkdir($targetDir, 0750, true);
            }
            $this->copyDirSafe($targetDir, $backupDir, $preserve);
            $backupCreated = true;

            $safeReport([
                'status' => 'APPLYING',
                'progressPercent' => 75,
                'currentStep' => 'Aplicando pacote verificado',
                'signatureVerified' => true,
                'sha256Verified' => true,
                'backupCreated' => true,
            ]);
            ($options['applyPackage'])($tmpPkg, $targetDir, $rel, $actualSha);

            $migrations = is_array($options['migrations'] ?? null) ? $options['migrations'] : [];
            if ($migrations !== []) {
                $safeReport([
                    'status' => 'MIGRATING',
                    'progressPercent' => 88,
                    'currentStep' => 'Executando migrações declaradas em ordem',
                    'signatureVerified' => true,
                    'sha256Verified' => true,
                    'backupCreated' => true,
                ]);
                foreach ($migrations as $mig) {
                    if (isset($mig['run']) && is_callable($mig['run'])) {
                        ($mig['run'])($targetDir, $previousVersion, (string) $rel['version']);
                        $migrationsExecuted[] = (string) ($mig['id'] ?? 'migration');
                    }
                }
            }

            $this->validate((string) $rel['version']);
            $safeReport([
                'status' => 'COMPLETED',
                'progressPercent' => 100,
                'currentStep' => 'Atualização concluída com integridade verificada',
                'signatureVerified' => true,
                'sha256Verified' => true,
                'backupCreated' => true,
                'rollbackPerformed' => false,
                'migrationsExecuted' => $migrationsExecuted,
            ]);

            return [
                'runUid' => $runUid,
                'updated' => true,
                'status' => 'COMPLETED',
                'previousVersion' => $previousVersion,
                'currentVersion' => (string) $rel['version'],
                'targetVersion' => (string) $rel['version'],
                'signatureVerified' => true,
                'sha256Verified' => true,
                'backupCreated' => true,
                'rollbackPerformed' => false,
                'migrationsExecuted' => $migrationsExecuted,
                'sanitizedError' => null,
            ];
        } catch (\Throwable $e) {
            $errMsg = substr($e->getMessage(), 0, 400);
            if ($backupCreated) {
                try {
                    $this->restoreDirFromBackup($backupDir, $targetDir, $preserve);
                    $rollbackPerformed = true;
                } catch (\Throwable) {
                    $rollbackPerformed = false;
                }
            }
            $terminalStatus = $rollbackPerformed ? 'ROLLED_BACK' : 'FAILED';
            $safeReport([
                'status' => $terminalStatus,
                'progressPercent' => 100,
                'currentStep' => $rollbackPerformed ? 'Rollback concluído após erro' : 'Atualização abortada antes da aplicação',
                'signatureVerified' => $signatureVerified,
                'sha256Verified' => $sha256Verified,
                'backupCreated' => $backupCreated,
                'rollbackPerformed' => $rollbackPerformed,
                'migrationsExecuted' => $migrationsExecuted,
                'error' => $errMsg,
            ]);
            return [
                'runUid' => $runUid,
                'updated' => false,
                'status' => $terminalStatus,
                'previousVersion' => $previousVersion,
                'currentVersion' => $previousVersion,
                'targetVersion' => (string) ($rel['version'] ?? ''),
                'signatureVerified' => $signatureVerified,
                'sha256Verified' => $sha256Verified,
                'backupCreated' => $backupCreated,
                'rollbackPerformed' => $rollbackPerformed,
                'migrationsExecuted' => $migrationsExecuted,
                'sanitizedError' => $errMsg,
            ];
        } finally {
            $this->removeDirRecursive($stagingDir);
        }
    }

    private function copyDirSafe(string $src, string $dst, array $excludeNames): void
    {
        if (!is_dir($dst)) {
            mkdir($dst, 0750, true);
        }
        $items = @scandir($src);
        if (!is_array($items)) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..' || isset($excludeNames[$item])) {
                continue;
            }
            $srcPath = $src . DIRECTORY_SEPARATOR . $item;
            $dstPath = $dst . DIRECTORY_SEPARATOR . $item;
            if (is_link($srcPath)) {
                continue;
            }
            if (is_dir($srcPath)) {
                $this->copyDirSafe($srcPath, $dstPath, $excludeNames);
            } elseif (is_file($srcPath)) {
                copy($srcPath, $dstPath);
            }
        }
    }

    private function restoreDirFromBackup(string $backupDir, string $targetDir, array $preserveNames): void
    {
        $items = @scandir($targetDir);
        if (is_array($items)) {
            foreach ($items as $item) {
                if ($item === '.' || $item === '..' || isset($preserveNames[$item])) {
                    continue;
                }
                $full = $targetDir . DIRECTORY_SEPARATOR . $item;
                if (is_dir($full) && !is_link($full)) {
                    $this->removeDirRecursive($full);
                } else {
                    @unlink($full);
                }
            }
        }
        $this->copyDirSafe($backupDir, $targetDir, $preserveNames);
    }

    private function removeDirRecursive(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $items = @scandir($dir);
        if (is_array($items)) {
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') {
                    continue;
                }
                $full = $dir . DIRECTORY_SEPARATOR . $item;
                if (is_dir($full) && !is_link($full)) {
                    $this->removeDirRecursive($full);
                } else {
                    @unlink($full);
                }
            }
        }
        @rmdir($dir);
    }

    /**
     * Realiza rollback verificado (Ed25519 + SHA-256) para uma release anterior compatível e permitida.
     */
    public function rollback(int $releaseId, array $options = []): array
    {
        $state = $this->requireState();
        $listed = $this->listCompatibleReleases($options['channel'] ?? 'stable');
        $candidates = array_merge(
            is_array($listed['releases'] ?? null) ? $listed['releases'] : [],
            is_array($listed['availableRollbacks'] ?? null) ? $listed['availableRollbacks'] : []
        );
        $target = null;
        foreach ($candidates as $rel) {
            if ((int) ($rel['releaseId'] ?? 0) === $releaseId) {
                $target = $rel;
                break;
            }
        }
        if ($target === null) {
            throw new WebLicenseException("Release #{$releaseId} não disponível para rollback.", 404, 'ROLLBACK_RELEASE_NOT_FOUND');
        }
        if (array_key_exists('allowRollback', $target) && $target['allowRollback'] === false) {
            throw new WebLicenseException("Rollback desabilitado para a release #{$releaseId}.", 403, 'ROLLBACK_DISABLED');
        }
        return $this->downloadAndApplyRelease($state, $target, $options, true);
    }

    /**
     * Helpers autenticados por Bearer JWT do painel para integração da Loja in-app.
     */
    private function panelRequest(string $method, string $panelPath, string $jwtToken, ?array $body = null): array
    {
        $url = $this->apiBaseUrl . '/api/web' . $panelPath;
        $this->assertAllowedUrl($url);
        $headers = [
            'Accept: application/json',
            'Authorization: Bearer ' . $jwtToken,
        ];
        $postBody = null;
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
            $postBody = json_encode($body);
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_FOLLOWLOCATION => false,
        ]);
        if ($postBody !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postBody);
        }
        $raw = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr = curl_error($ch);
        curl_close($ch);
        if ($raw === false) {
            throw new WebLicenseException('Erro de rede ao consultar loja web: ' . $curlErr, 503, 'NETWORK_ERROR');
        }
        $decoded = json_decode((string) $raw, true);
        if ($status < 200 || $status >= 300) {
            $msg = is_array($decoded) && !empty($decoded['message']) ? (string) $decoded['message'] : "Erro HTTP {$status}";
            $code = is_array($decoded) && !empty($decoded['code']) ? (string) $decoded['code'] : "HTTP_{$status}";
            throw new WebLicenseException($msg, $status, $code, is_array($decoded) ? $decoded : []);
        }
        return is_array($decoded) ? $decoded : [];
    }

    public function getStoreCatalog(string $jwtToken, ?int $licenseId = null, ?string $productSlug = null): array
    {
        $params = [];
        if ($licenseId !== null) {
            $params['licenseId'] = $licenseId;
        }
        if ($productSlug !== null && $productSlug !== '') {
            $params['productSlug'] = $productSlug;
        }
        $qs = $params !== [] ? ('?' . http_build_query($params)) : '';
        return $this->panelRequest('GET', '/store/catalog' . $qs, $jwtToken);
    }

    public function checkStoreCompatibility(string $jwtToken, array $payload): array
    {
        return $this->panelRequest('POST', '/store/compatibility-check', $jwtToken, $payload);
    }

    public function createStoreOrder(string $jwtToken, array $payload): array
    {
        if (empty($payload['orderOrigin'])) {
            $payload['orderOrigin'] = 'IN_APP_STORE';
        }
        return $this->panelRequest('POST', '/invoices/checkout', $jwtToken, $payload);
    }

    /**
     * Desativa a instalação remotamente no servidor de licenças e remove o arquivo de estado criptografado local.
     */
    public function uninstall(string $reason = 'PHP_SDK_UNINSTALL'): array
    {
        $state = $this->readState();
        if (!$state || empty($state['installationCredential'])) {
            return [
                'uninstalled' => true,
                'alreadyUninstalled' => true,
                'installationId' => null,
            ];
        }

        try {
            $this->request('POST', '/deactivate', ['reason' => $reason], $state['installationCredential'], [], true, $state);
        } catch (RuntimeException $e) {
            if ((int) $e->getCode() !== 401 && (int) $e->getCode() !== 403) {
                throw $e;
            }
        }

        $this->stateStore->write(null);

        return [
            'uninstalled' => true,
            'alreadyUninstalled' => false,
            'installationId' => $state['installationId'],
        ];
    }

    /**
     * Lê e decifra o estado da instalação armazenado localmente.
     *
     * @return array<string, mixed>|null Dados do estado local ou `null` se não houver instalação gravada.
     */
    public function readState(): ?array
    {
        return $this->stateStore->read();
    }

    /**
     * Obtém o estado local da instalação e garante que ela esteja devidamente ativada.
     *
     * @return array<string, mixed> Estado decifrado contendo `installationCredential`.
     * @throws RuntimeException Se não existir instalação ativa no armazenamento local.
     */
    private function requireState(): array
    {
        $state = $this->readState();
        if (!$state || empty($state['installationCredential'])) {
            throw new RuntimeException('Instalação não encontrada localmente. Execute install() primeiro.');
        }
        return $state;
    }

    /**
     * Negocia ou reutiliza uma sessão de transporte cifrado efêmera (ECDH P-256 + AES-256-GCM `k7seal.v1`).
     *
     * @return array{sessionId: string, aesKey: string, expiresAt: int}|null Dados da sessão ativa ou `null` se desabilitada/indisponível.
     * @throws RuntimeException Se `requireSealedTransport` estiver ativo e o handshake ECDH ou a assinatura falharem.
     */
    private function ensureWireSession(): ?array
    {
        if ((!$this->useEncryptedTransport && !$this->requireSealedTransport) || !function_exists('openssl_pkey_derive')) {
            if ($this->requireSealedTransport) {
                throw new WebLicenseException(
                    'Transporte selado k7seal.v1 obrigatório indisponível (openssl_pkey_derive ausente).',
                    503,
                    'SEALED_TRANSPORT_UNAVAILABLE'
                );
            }
            return null;
        }
        if ($this->wireSession !== null && time() < $this->wireSession['expiresAt']) {
            return $this->wireSession;
        }

        $eph = Codec::createEphemeralEcdhKeyPair();
        $url = $this->apiBaseUrl . '/api/web/license/v1/session-key';
        $timestamp = gmdate('Y-m-d\TH:i:s\Z');
        $nonce = bin2hex(random_bytes(16));

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'Content-Type: application/json',
                'x-k7-web-timestamp: ' . $timestamp,
                'x-k7-web-nonce: ' . $nonce,
            ],
            CURLOPT_POSTFIELDS => json_encode(['clientPublicKeySpkiBase64' => $eph['clientPublicKeySpkiBase64']]),
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_FOLLOWLOCATION => false,
        ]);
        $raw = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr = curl_error($ch);
        curl_close($ch);

        if ($raw === false) {
            if ($this->requireSealedTransport) {
                throw new WebLicenseException(
                    'Falha de rede ao negociar sessão criptográfica ECDH: ' . ($curlErr ?: 'erro desconhecido'),
                    503,
                    'NETWORK_ERROR'
                );
            }
            return null;
        }

        $data = json_decode((string) $raw, true);

        if ($status < 200 || $status >= 300) {
            $errCode = is_array($data) && !empty($data['code'])
                ? (string) $data['code']
                : ($status === 503 ? 'REDIS_UNAVAILABLE' : 'SEALED_TRANSPORT_UNAVAILABLE');
            $errMsg = is_array($data) && !empty($data['message'])
                ? (string) $data['message']
                : "Falha ao negociar sessão criptográfica ECDH (HTTP {$status}).";
            $details = is_array($data) ? $data : [];
            unset($details['signatureEnvelope']);
            if ($this->requireSealedTransport || $status === 503 || $status === 429 || $status >= 500) {
                throw new WebLicenseException($errMsg, $status ?: 503, $errCode, $details);
            }
            return null;
        }

        if (!is_array($data) || empty($data['sessionId']) || empty($data['serverPublicKeySpkiBase64'])) {
            if ($this->requireSealedTransport) {
                throw new WebLicenseException(
                    'Resposta incompleta do servidor em /session-key.',
                    502,
                    'INVALID_SESSION_KEY_RESPONSE'
                );
            }
            return null;
        }

        if ($this->verifyResponseSignatures) {
            $trustedKeys = $this->fetchPublicKeysMap([], false);
            $hsKeyId = (string) ($data['handshakeSignature']['keyId'] ?? '');
            if ($hsKeyId !== '' && empty($trustedKeys[$hsKeyId])) {
                $trustedKeys = $this->fetchPublicKeysMap([], true);
            }
            if (!empty($data['handshakeSignature']) || $this->pinnedRootPublicKeyPem !== null) {
                Codec::verifyEcdhHandshakeSignature(
                    (string) $data['sessionId'],
                    (string) $data['serverPublicKeySpkiBase64'],
                    (string) ($data['fingerprintSha256'] ?? ''),
                    $eph['clientPublicKeySpkiBase64'],
                    (int) ($data['expiresInSeconds'] ?? 1800),
                    $nonce,
                    is_array($data['handshakeSignature'] ?? null) ? $data['handshakeSignature'] : null,
                    $trustedKeys
                );
            }
            if (!empty($data['signatureEnvelope']) || $this->pinnedRootPublicKeyPem !== null) {
                Codec::verifyRuntimeResponseSignatureFromRawJson(
                    (string) $raw,
                    $trustedKeys,
                    'POST',
                    '/api/web/license/v1/session-key',
                    $status,
                    $nonce
                );
            }
        }

        $aesKey = Codec::deriveWireAesKey(
            $eph['privateKey'],
            (string) $data['sessionId'],
            (string) $data['serverPublicKeySpkiBase64']
        );
        $ttl = max(60, (int) ($data['expiresInSeconds'] ?? 1800) - 30);
        $this->wireSession = [
            'sessionId' => (string) $data['sessionId'],
            'aesKey' => $aesKey,
            'expiresAt' => time() + $ttl,
        ];
        return $this->wireSession;
    }

    /**
     * Resolve o caminho completo de um arquivo dentro de um diretório base, bloqueando tentativas de path traversal.
     *
     * @param string $baseDir Diretório de destino.
     * @param string $fileName Nome simples do arquivo (sem subdiretórios ou segmentos `..`).
     * @return string Caminho seguro normalizado.
     * @throws RuntimeException Se o nome do arquivo contiver caracteres ou segmentos de traversal inválidos.
     */
    private function resolveSafeChildPath(string $baseDir, string $fileName): string
    {
        $cleanName = basename($fileName);
        if ($cleanName === '' || $cleanName === '.' || $cleanName === '..' || $cleanName !== ltrim($fileName, '/\\')) {
            throw new RuntimeException('Nome de arquivo inválido (path traversal bloqueado).');
        }
        $realBase = realpath($baseDir) ?: $baseDir;
        return rtrim($realBase, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $cleanName;
    }

    /**
     * Valida se a URL utiliza HTTPS ou HTTP local explicitamente autorizado via `allowInsecureLocalHttp`.
     *
     * @param string $url URL completa a ser verificada.
     * @return void
     * @throws RuntimeException Se a URL for malformada ou utilizar HTTP não permitido.
     */
    private function assertAllowedUrl(string $url): void
    {
        $parts = parse_url($url);
        if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
            throw new RuntimeException('URL inválida.');
        }
        $scheme = strtolower((string) $parts['scheme']);
        $host = strtolower((string) $parts['host']);
        if ($scheme === 'https') {
            return;
        }
        if ($scheme === 'http' && $this->allowInsecureLocalHttp && self::isLocalhostDevelopmentHost($host)) {
            return;
        }
        throw new RuntimeException("Somente URLs HTTPS são permitidas em produção ({$scheme}://{$host}).");
    }

    /**
     * Obtém e valida o bundle de chaves públicas Ed25519 (ativa, secundárias e raiz) em `/keys`
     * (com fallback para `/releases/public-key`).
     *
     * @param array<string, string> $fallback Mapa inicial de chaves conhecidas (ex.: pinadas no estado local).
     * @param bool $forceRefresh Ignora o cache em memória e consulta novamente o servidor.
     * @return array<string, string> Mapa indexado por `keyId => publicKeyPem`.
     * @throws RuntimeException Se uma chave raiz estiver pinada e nenhuma chave do servidor puder ser validada por ela.
     */
    private function fetchPublicKeysMap(array $fallback = [], bool $forceRefresh = false): array
    {
        if (!$forceRefresh && $this->discoveredTrustedKeys !== []) {
            return array_merge($fallback, $this->discoveredTrustedKeys, $this->pinnedPublicKeys);
        }

        $state = $this->readState();
        $rootPin = $this->pinnedRootPublicKeyPem ?: ($state['pinnedRootPublicKeyPem'] ?? null);

        foreach (['/keys', '/releases/public-key'] as $ep) {
            $url = $this->apiBaseUrl . '/api/web/license/v1' . $ep;
            $this->assertAllowedUrl($url);
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_CUSTOMREQUEST => 'GET',
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER => ['Accept: application/json'],
                CURLOPT_TIMEOUT => $this->timeoutSeconds,
                CURLOPT_FOLLOWLOCATION => false,
            ]);
            $raw = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($raw === false || $status < 200 || $status >= 300) {
                continue;
            }
            $bundle = json_decode((string) $raw, true);
            if (!is_array($bundle)) {
                continue;
            }
            $resolved = Codec::resolveTrustedKeysFromBundle($bundle, $rootPin, $this->pinnedPublicKeys);
            if ($resolved === [] && $rootPin !== null && $rootPin !== '') {
                throw new RuntimeException('Nenhuma chave publicada pelo servidor foi validada pela chave raiz pinada.', 403);
            }
            $this->discoveredTrustedKeys = $resolved;
            return array_merge($fallback, $resolved, $this->pinnedPublicKeys);
        }

        if ($rootPin !== null && $rootPin !== '' && $this->pinnedPublicKeys === []) {
            throw new RuntimeException('Falha ao obter bundle de chaves Web Ed25519 para verificação com raiz pinada.', 503);
        }

        return array_merge($fallback, $this->discoveredTrustedKeys, $this->pinnedPublicKeys);
    }

    /**
     * Executa uma requisição HTTP autenticada contra a API de licenciamento, aplicando proteção anti-replay,
     * assinatura opcional do cliente, selagem AES-256-GCM (`k7seal.v1`) e verificação de assinatura da resposta.
     *
     * @param string $method Método HTTP (GET, POST, etc.).
     * @param string $endpointPath Caminho relativo a `/api/web/license/v1`.
     * @param array<string, mixed>|null $body Corpo JSON da requisição, quando aplicável.
     * @param string|null $credential Credencial da instalação (`x-web-installation-credential`).
     * @param array<int, string> $extraHeaders Cabeçalhos HTTP adicionais.
     * @param bool $retryOnSessionExpired Permite renegociar automaticamente a sessão ECDH ao receber HTTP 428.
     * @param array<string, mixed>|null $state Estado local da instalação usado para assinatura do cliente e chaves pinadas.
     * @return array<string, mixed> Resposta JSON decodificada e autenticada.
     * @throws RuntimeException Em falha de rede, HTTP >= 400 ou violação de integridade criptográfica.
     */
    private function request(string $method, string $endpointPath, ?array $body = null, ?string $credential = null, array $extraHeaders = [], bool $retryOnSessionExpired = true, ?array $state = null, ?string &$rawResponseJson = null): array 
    {
        $url = $this->apiBaseUrl . '/api/web/license/v1' . $endpointPath;
        $this->assertAllowedUrl($url);

        $pathOnly = '/api/web/license/v1' . explode('?', $endpointPath, 2)[0];
        $timestamp = gmdate('Y-m-d\TH:i:s\Z');
        $nonce = bin2hex(random_bytes(16));
        $session = $this->ensureWireSession();
        $aad = $session !== null
            ? strtoupper($method) . ':' . $pathOnly . ':' . $session['sessionId'] . ':' . $nonce
            : strtoupper($method) . ':' . $pathOnly;

        $headers = array_merge([
            'Accept: application/json',
            'x-k7-web-timestamp: ' . $timestamp,
            'x-k7-web-nonce: ' . $nonce,
        ], $extraHeaders);

        if ($credential !== null && $credential !== '') {
            $headers[] = 'x-web-installation-credential: ' . $credential;
        }

        $clientPriv = $state['clientPrivateKeyPem'] ?? $this->clientPrivateKeyPem;
        $installationId = $state['installationId'] ?? null;
        if ($clientPriv && $installationId) {
            $clientSig = Codec::signClientRequest(
                (string) $clientPriv,
                $method,
                $pathOnly,
                $timestamp,
                $nonce,
                (string) $installationId,
                $body
            );
            $headers[] = 'x-k7-web-client-signature: ' . $clientSig;
        }

        $postBody = null;
        if ($session !== null) {
            $headers[] = 'x-k7-web-session: ' . $session['sessionId'];
            $headers[] = 'x-k7-web-cipher: aes-256-gcm';
            if ($body !== null) {
                $headers[] = 'Content-Type: application/json';
                $postBody = json_encode([
                    'sealed' => true,
                    'sealedEnvelope' => Codec::sealWirePayload($body, $session['aesKey'], $aad),
                ]);
            }
        } elseif ($body !== null) {
            $headers[] = 'Content-Type: application/json';
            $postBody = json_encode($body);
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_FOLLOWLOCATION => false,
        ]);
        if ($postBody !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postBody);
        }

        $raw = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr = curl_error($ch);
        curl_close($ch);

        if ($raw === false) {
            throw new WebLicenseException('Erro de comunicação HTTP: ' . $curlErr, 503, 'NETWORK_ERROR');
        }

        if ($status === 428 && $session !== null && $retryOnSessionExpired) {
            $this->wireSession = null;
            return $this->request($method, $endpointPath, $body, $credential, $extraHeaders, false, $state, $rawResponseJson);
        }

        $plainJson = (string) $raw;
        $decoded = json_decode($plainJson, true);
        if (
            $session !== null &&
            is_array($decoded) &&
            !empty($decoded['sealed']) &&
            !empty($decoded['sealedEnvelope'])
        ) {
            $plainJson = Codec::unsealWirePayloadRaw((string) $decoded['sealedEnvelope'], $session['aesKey'], $aad);
            $decoded = json_decode($plainJson, true);
        }

        if ($this->verifyResponseSignatures && is_array($decoded)) {
            $hasEnv = !empty($decoded['signatureEnvelope']) && is_array($decoded['signatureEnvelope']);
            $isUnsignedInfraError =
                !$hasEnv &&
                $status >= 400 &&
                (
                    $status === 503 ||
                    $status === 429 ||
                    $status >= 500 ||
                    !empty($decoded['code']) ||
                    ($decoded['success'] ?? null) === false
                );

            if ($hasEnv || ($this->pinnedRootPublicKeyPem !== null && !$isUnsignedInfraError)) {
                $trustedKeys = $this->fetchPublicKeysMap($state['pinnedPublicKeys'] ?? [], false);
                $envKeyId = (string) ($decoded['signatureEnvelope']['keyId'] ?? '');
                if ($envKeyId !== '' && empty($trustedKeys[$envKeyId])) {
                    $trustedKeys = $this->fetchPublicKeysMap($state['pinnedPublicKeys'] ?? [], true);
                }
                Codec::verifyRuntimeResponseSignatureFromRawJson(
                    $plainJson,
                    $trustedKeys,
                    $method,
                    $pathOnly,
                    $status,
                    $nonce
                );
            }
        }

        if ($status < 200 || $status >= 300) {
            $msg = is_array($decoded) && !empty($decoded['message'])
                ? (string) $decoded['message']
                : "Erro HTTP {$status}";
            $errorCode = is_array($decoded) && !empty($decoded['code'])
                ? (string) $decoded['code']
                : "HTTP_{$status}";
            $details = is_array($decoded) ? $decoded : [];
            unset($details['signatureEnvelope']);
            throw new WebLicenseException($msg, $status, $errorCode, $details);
        }

        $rawResponseJson = $plainJson;
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * Realiza o download binário de um pacote de atualização diretamente para um arquivo em disco.
     *
     * @param string $url URL de origem do pacote.
     * @param string $destPath Caminho local onde o conteúdo será gravado.
     * @return void
     * @throws RuntimeException Se o arquivo não puder ser aberto ou o download retornar erro HTTP/cURL.
     */
    private function downloadFile(string $url, string $destPath): void
    {
        $fp = fopen($destPath, 'wb');
        if ($fp === false) {
            throw new RuntimeException('Não foi possível abrir arquivo temporário para escrita.');
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FILE => $fp,
            CURLOPT_TIMEOUT => max($this->timeoutSeconds, 60),
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
        ]);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        fclose($fp);

        if (!$ok || $status < 200 || $status >= 300) {
            throw new RuntimeException("Falha no download do pacote (HTTP {$status}): {$err}");
        }
    }

}
