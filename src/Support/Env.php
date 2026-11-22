<?php
declare(strict_types=1);

namespace KSeven\WebLicense\Support;

/**
 * Utilitário interno para leitura padronizada e tipada de variáveis de ambiente
 * a partir de `$_ENV`, `$_SERVER` e `getenv()`.
 */
final class Env
{
    /**
     * Obtém o valor bruto de uma variável de ambiente e remove espaços nas extremidades.
     *
     * @param string $key Nome da variável de ambiente (ex.: "K7_WEB_API_URL").
     * @return string|null Valor limpo ou `null` se não estiver definida ou estiver vazia.
     */
    public static function get(string $key): ?string
    {
        $val = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);
        if (!is_string($val)) {
            return null;
        }
        $trimmed = trim($val);
        return $trimmed !== '' ? $trimmed : null;
    }

    /**
     * Lê uma variável de ambiente como booleano (`true`, `1`, `yes`, `on` / `false`, `0`, `no`, `off`).
     *
     * @param string $key Nome da variável de ambiente.
     * @param bool|null $default Valor padrão caso a variável não exista ou não seja reconhecida.
     * @return bool|null
     */
    public static function bool(string $key, ?bool $default = null): ?bool
    {
        $val = self::get($key);
        if ($val === null) {
            return $default;
        }
        return match (strtolower($val)) {
            '1', 'true', 'yes', 'on' => true,
            '0', 'false', 'no', 'off' => false,
            default => $default,
        };
    }

    /**
     * Lê uma variável de ambiente como número inteiro.
     *
     * @param string $key Nome da variável de ambiente.
     * @param int|null $default Valor padrão caso a variável não exista ou não seja numérica.
     * @return int|null
     */
    public static function int(string $key, ?int $default = null): ?int
    {
        $val = self::get($key);
        if ($val === null || !is_numeric($val)) {
            return $default;
        }
        return (int) $val;
    }
}