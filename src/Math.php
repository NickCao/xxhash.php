<?php

declare(strict_types=1);

namespace XXHash;

/**
 * Unsigned 64-bit arithmetic helpers for PHP's signed 64-bit integers.
 *
 * PHP integers are signed 64-bit on 64-bit platforms. These helpers perform
 * unsigned arithmetic by working with bit patterns directly, using 16-bit
 * decomposition to avoid overflow to float.
 */
final class Math
{
    /** Unsigned 64-bit addition: (a + b) mod 2^64 */
    public static function add64(int $a, int $b): int
    {
        $lo = ($a & 0xFFFFFFFF) + ($b & 0xFFFFFFFF);
        $hi = (($a >> 32) & 0xFFFFFFFF) + (($b >> 32) & 0xFFFFFFFF) + ($lo >> 32);
        return (($hi & 0xFFFFFFFF) << 32) | ($lo & 0xFFFFFFFF);
    }

    /** Unsigned 64-bit subtraction: (a - b) mod 2^64 */
    public static function sub64(int $a, int $b): int
    {
        $lo = ($a & 0xFFFFFFFF) - ($b & 0xFFFFFFFF);
        $borrow = ($lo < 0) ? 1 : 0;
        $lo &= 0xFFFFFFFF;
        $hi = (($a >> 32) & 0xFFFFFFFF) - (($b >> 32) & 0xFFFFFFFF) - $borrow;
        return (($hi & 0xFFFFFFFF) << 32) | $lo;
    }

    /** Unsigned 64-bit multiplication: (a * b) mod 2^64 using 16-bit decomposition */
    public static function mult64(int $a, int $b): int
    {
        $a0 = $a & 0xFFFF;
        $a1 = ($a >> 16) & 0xFFFF;
        $a2 = ($a >> 32) & 0xFFFF;
        $a3 = ($a >> 48) & 0xFFFF;
        $b0 = $b & 0xFFFF;
        $b1 = ($b >> 16) & 0xFFFF;
        $b2 = ($b >> 32) & 0xFFFF;
        $b3 = ($b >> 48) & 0xFFFF;

        $c0 = $a0 * $b0;
        $c1 = $a0 * $b1 + $a1 * $b0;
        $c2 = $a0 * $b2 + $a1 * $b1 + $a2 * $b0;
        $c3 = $a0 * $b3 + $a1 * $b2 + $a2 * $b1 + $a3 * $b0;

        $c1 += $c0 >> 16;
        $c2 += $c1 >> 16;
        $c3 += $c2 >> 16;

        return ($c0 & 0xFFFF) | (($c1 & 0xFFFF) << 16) | (($c2 & 0xFFFF) << 32) | (($c3 & 0xFFFF) << 48);
    }

    /** Full 128-bit unsigned multiplication. Returns [low64, high64]. */
    public static function mult128(int $a, int $b): array
    {
        $a0 = $a & 0xFFFF;
        $a1 = ($a >> 16) & 0xFFFF;
        $a2 = ($a >> 32) & 0xFFFF;
        $a3 = ($a >> 48) & 0xFFFF;
        $b0 = $b & 0xFFFF;
        $b1 = ($b >> 16) & 0xFFFF;
        $b2 = ($b >> 32) & 0xFFFF;
        $b3 = ($b >> 48) & 0xFFFF;

        $c0 = $a0 * $b0;
        $c1 = $a0 * $b1 + $a1 * $b0;
        $c2 = $a0 * $b2 + $a1 * $b1 + $a2 * $b0;
        $c3 = $a0 * $b3 + $a1 * $b2 + $a2 * $b1 + $a3 * $b0;
        $c4 = $a1 * $b3 + $a2 * $b2 + $a3 * $b1;
        $c5 = $a2 * $b3 + $a3 * $b2;
        $c6 = $a3 * $b3;

        $c1 += $c0 >> 16; $c0 &= 0xFFFF;
        $c2 += $c1 >> 16; $c1 &= 0xFFFF;
        $c3 += $c2 >> 16; $c2 &= 0xFFFF;
        $c4 += $c3 >> 16; $c3 &= 0xFFFF;
        $c5 += $c4 >> 16; $c4 &= 0xFFFF;
        $c6 += $c5 >> 16; $c5 &= 0xFFFF;
        $c7 = $c6 >> 16;  $c6 &= 0xFFFF;

        $lo = $c0 | ($c1 << 16) | ($c2 << 32) | ($c3 << 48);
        $hi = $c4 | ($c5 << 16) | ($c6 << 32) | ($c7 << 48);
        return [$lo, $hi];
    }

    /** 128-bit multiply and fold: returns low64 XOR high64 */
    public static function mul128fold64(int $a, int $b): int
    {
        [$lo, $hi] = self::mult128($a, $b);
        return $lo ^ $hi;
    }

    /** Multiply two 32-bit unsigned values, returning full 64-bit result */
    public static function mult32to64(int $a, int $b): int
    {
        $aLo = $a & 0xFFFF;
        $aHi = ($a >> 16) & 0xFFFF;
        $bLo = $b & 0xFFFF;
        $bHi = ($b >> 16) & 0xFFFF;

        $c0 = $aLo * $bLo;
        $c1 = $aLo * $bHi + $aHi * $bLo;
        $c2 = $aHi * $bHi;

        $c1 += $c0 >> 16;
        $c2 += $c1 >> 16;

        return ($c0 & 0xFFFF) | (($c1 & 0xFFFF) << 16) | ($c2 << 32);
    }

    /** Unsigned 32-bit multiplication: (a * b) mod 2^32 */
    public static function mult32(int $a, int $b): int
    {
        $lo = ($a & 0xFFFF) * ($b & 0xFFFF);
        $mid = ($a & 0xFFFF) * (($b >> 16) & 0xFFFF) + (($a >> 16) & 0xFFFF) * ($b & 0xFFFF);
        return ($lo + ($mid << 16)) & 0xFFFFFFFF;
    }

    /** 32-bit left rotation */
    public static function rotl32(int $val, int $n): int
    {
        $val &= 0xFFFFFFFF;
        return (($val << $n) | ($val >> (32 - $n))) & 0xFFFFFFFF;
    }

    /** 64-bit left rotation */
    public static function rotl64(int $val, int $n): int
    {
        return ($val << $n) | self::shr64($val, 64 - $n);
    }

    /** Unsigned 64-bit right shift (logical, not arithmetic) */
    public static function shr64(int $val, int $n): int
    {
        if ($n === 0) return $val;
        return ($val >> $n) & (PHP_INT_MAX >> ($n - 1));
    }

    /** XOR-shift: val ^ (val >>> n) */
    public static function xorshift64(int $val, int $n): int
    {
        return $val ^ self::shr64($val, $n);
    }

    /** Byte-swap a 32-bit value */
    public static function swap32(int $val): int
    {
        return unpack('N', pack('V', $val & 0xFFFFFFFF))[1];
    }

    /** Byte-swap a 64-bit value */
    public static function swap64(int $val): int
    {
        return unpack('J', pack('P', $val))[1];
    }

    /** Read unsigned 32-bit little-endian value from string */
    public static function read32(string $data, int $offset): int
    {
        return unpack('V', $data, $offset)[1];
    }

    /** Read 64-bit little-endian value from string (signed PHP int, same bit pattern) */
    public static function read64(string $data, int $offset): int
    {
        return unpack('P', $data, $offset)[1];
    }

    /** Write 64-bit little-endian value to string at offset */
    public static function write64(string &$data, int $offset, int $val): void
    {
        $bytes = pack('P', $val);
        for ($i = 0; $i < 8; $i++) {
            $data[$offset + $i] = $bytes[$i];
        }
    }
}
