#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * CLI oficial do K'Seven Web Licensing SDK (`bin/k7web.php`).
 * Permite executar operações de licenciamento diretamente via linha de comando
 * (install, check-version, update, validate, entitlements, uninstall) com saída JSON.
 */

// Localiza e carrega o autoloader do Composer (tanto no repositório local quanto instalado via vendor/)
$autoloadCandidates = [
    dirname(__DIR__) . '/vendor/autoload.php',
    dirname(__DIR__, 3) . '/autoload.php',
];
$loaded = false;
foreach ($autoloadCandidates as $autoload) {
    if (is_file($autoload)) {
        require_once $autoload;
        $loaded = true;
        break;
    }
}

// Fallback: carrega manualmente as classes do SDK caso o autoloader do Composer não esteja presente
if (!$loaded) {
    require_once dirname(__DIR__) . '/src/Support/Env.php';
    require_once dirname(__DIR__) . '/src/Crypto/Codec.php';
    require_once dirname(__DIR__) . '/src/Storage/EncryptedStateStore.php';
    require_once dirname(__DIR__) . '/src/WebLicenseClient.php';
}

use KSeven\WebLicense\Support\Env;
use KSeven\WebLicense\WebLicenseClient;

// Extrai o subcomando principal e faz o parsing das flags no formato `--chave valor` ou `--flag` booleana
$args = array_slice($argv, 1);
$command = $args[0] ?? 'help';
$flags = [];
for ($i = 1; $i < count($args); $i++) {
    $token = $args[$i];
    if (!str_starts_with($token, '--')) {
        continue;
    }
    $key = substr($token, 2);
    $next = $args[$i + 1] ?? null;
    if ($next === null || str_starts_with($next, '--')) {
        $flags[$key] = true;
    } else {
        $flags[$key] = $next;
        $i++;
    }
}

// Exibe a documentação de uso e opções disponíveis em JSON quando solicitado `help`
if ($command === 'help' || $command === '--help' || $command === '-h') {
    echo json_encode([
        'package' => 'kseven/web-license-sdk',
        'version' => '1.1.0',
        'usage' => 'php bin/k7web.php <install|check-version|update|validate|entitlements|uninstall> [opções]',
        'commands' => [
            'install' => '--api <url> --key <licenseKey> --domain <host> --app-version <semver> [--platform php|wordpress|universal] [--state-file .kseven-web-license.dat] [--state-secret <secret>] [--plain-transport]',
            'check-version' => '--api <url> [--channel stable|beta] [--app-version <semver>] [--state-file ...]',
            'update' => '--api <url> [--channel stable|beta] [--dest-dir ./updates] [--state-file ...]',
            'validate' => '--api <url> [--app-version <semver>] [--state-file ...]',
            'entitlements' => '--api <url> [--state-file ...]',
            'uninstall' => '--api <url> [--reason "..."] [--state-file ...]',
        ],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit(0);
}

try {
    // Resolve parâmetros globais priorizando flags da CLI sobre variáveis de ambiente (`K7_WEB_*`)
    $config = [];
    if (!empty($flags['api'])) {
        $config['apiBaseUrl'] = (string) $flags['api'];
    }
    if (isset($flags['state-file']) && is_string($flags['state-file'])) {
        $config['stateFilePath'] = $flags['state-file'];
    }
    if (isset($flags['state-secret']) && is_string($flags['state-secret'])) {
        $config['stateSecret'] = $flags['state-secret'];
    }
    if (!empty($flags['platform'])) {
        $config['platform'] = (string) $flags['platform'];
    }
    if (!empty($flags['allow-local-http'])) {
        $config['allowInsecureLocalHttp'] = true;
    }
    if (!empty($flags['plain-transport'])) {
        $config['useEncryptedTransport'] = false;
    }

    $client = new WebLicenseClient($config);

    // Roteia o subcomando para o método correspondente do `WebLicenseClient`
    $out = match ($command) {
        'install' => $client->install([
            'licenseKey' => (string) ($flags['key'] ?? Env::get('K7_WEB_LICENSE_KEY') ?? ''),
            'domain' => (string) ($flags['domain'] ?? Env::get('K7_WEB_DOMAIN') ?? ''),
            'appVersion' => (string) ($flags['app-version'] ?? '1.0.0'),
            'platform' => (string) ($flags['platform'] ?? Env::get('K7_WEB_PLATFORM') ?? 'php'),
            'environment' => (string) ($flags['env'] ?? Env::get('K7_WEB_ENV') ?? 'production'),
        ]),
        'check-version' => $client->checkVersion(
            (string) ($flags['channel'] ?? 'stable'),
            isset($flags['app-version']) && is_string($flags['app-version']) ? $flags['app-version'] : null
        ),
        'update' => $client->update([
            'channel' => (string) ($flags['channel'] ?? 'stable'),
            'destDir' => isset($flags['dest-dir']) && is_string($flags['dest-dir']) ? $flags['dest-dir'] : null,
        ]),
        'validate' => $client->validate(
            isset($flags['app-version']) && is_string($flags['app-version']) ? $flags['app-version'] : null
        ),
        'entitlements' => $client->entitlements(),
        'uninstall' => $client->uninstall((string) ($flags['reason'] ?? 'CLI_UNINSTALL')),
        default => throw new RuntimeException("Comando desconhecido: {$command}", 400),
    };

    // Imprime o resultado da operação formatado em JSON na saída padrão (STDOUT)
    echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (Throwable $e) {
    // Em caso de falha, escreve o erro estruturado em JSON na saída de erro (STDERR) e encerra com código 1
    fwrite(STDERR, json_encode([
        'error' => true,
        'code' => $e->getCode() ?: 1,
        'message' => $e->getMessage(),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(1);
}