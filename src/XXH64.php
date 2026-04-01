<?php

declare(strict_types=1);

namespace XXHash;

class XXH64
{
    // Constants use ~ trick: for hex values > 0x7FFFFFFFFFFFFFFF, use ~(complement)
    // where complement has bit 63 = 0 and is thus a valid PHP int literal.
    private const PRIME1 = ~0x61C8864E7A143578; // 0x9E3779B185EBCA87
    private const PRIME2 = ~0x3D4D51C2D82B14B0; // 0xC2B2AE3D27D4EB4F
    private const PRIME3 = 0x165667B19E3779F9;
    private const PRIME4 = ~0x7A1435883D4D519C; // 0x85EBCA77C2B2AE63
    private const PRIME5 = 0x27D4EB2F165667C5;

    private int $totalLen = 0;
    private int $v1;
    private int $v2;
    private int $v3;
    private int $v4;
    private string $mem = '';
    private int $memSize = 0;
    private int $seed;

    public function __construct(int $seed = 0)
    {
        $this->seed = $seed;
        $this->reset();
    }

    public function reset(): void
    {
        $this->totalLen = 0;
        $this->memSize = 0;
        $this->mem = '';
        $s = $this->seed;
        $this->v1 = Math::add64(Math::add64($s, self::PRIME1), self::PRIME2);
        $this->v2 = Math::add64($s, self::PRIME2);
        $this->v3 = $s;
        $this->v4 = Math::sub64($s, self::PRIME1);
    }

    /** One-shot hash */
    public static function hash(string $data, int $seed = 0): int
    {
        $h = new self($seed);
        $h->update($data);
        return $h->digest();
    }

    public function update(string $data): self
    {
        $len = strlen($data);
        $this->totalLen += $len;
        $offset = 0;

        if ($this->memSize > 0) {
            $needed = 32 - $this->memSize;
            if ($len >= $needed) {
                $this->mem .= substr($data, 0, $needed);
                $offset = $needed;
                $this->v1 = self::round64($this->v1, Math::read64($this->mem, 0));
                $this->v2 = self::round64($this->v2, Math::read64($this->mem, 8));
                $this->v3 = self::round64($this->v3, Math::read64($this->mem, 16));
                $this->v4 = self::round64($this->v4, Math::read64($this->mem, 24));
                $this->memSize = 0;
                $this->mem = '';
            } else {
                $this->mem .= $data;
                $this->memSize += $len;
                return $this;
            }
        }

        while ($len - $offset >= 32) {
            $this->v1 = self::round64($this->v1, Math::read64($data, $offset));
            $this->v2 = self::round64($this->v2, Math::read64($data, $offset + 8));
            $this->v3 = self::round64($this->v3, Math::read64($data, $offset + 16));
            $this->v4 = self::round64($this->v4, Math::read64($data, $offset + 24));
            $offset += 32;
        }

        if ($offset < $len) {
            $this->mem = substr($data, $offset);
            $this->memSize = $len - $offset;
        }

        return $this;
    }

    public function digest(): int
    {
        if ($this->totalLen >= 32) {
            $h = Math::add64(
                Math::add64(Math::rotl64($this->v1, 1), Math::rotl64($this->v2, 7)),
                Math::add64(Math::rotl64($this->v3, 12), Math::rotl64($this->v4, 18))
            );
            $h = self::mergeRound64($h, $this->v1);
            $h = self::mergeRound64($h, $this->v2);
            $h = self::mergeRound64($h, $this->v3);
            $h = self::mergeRound64($h, $this->v4);
        } else {
            $h = Math::add64($this->v3, self::PRIME5);
        }

        $h = Math::add64($h, $this->totalLen);

        $p = 0;
        while ($this->memSize - $p >= 8) {
            $k = self::round64(0, Math::read64($this->mem, $p));
            $h ^= $k;
            $h = Math::add64(Math::mult64(Math::rotl64($h, 27), self::PRIME1), self::PRIME4);
            $p += 8;
        }

        while ($this->memSize - $p >= 4) {
            $h ^= Math::mult64(Math::read32($this->mem, $p), self::PRIME1);
            $h = Math::add64(Math::mult64(Math::rotl64($h, 23), self::PRIME2), self::PRIME3);
            $p += 4;
        }

        while ($p < $this->memSize) {
            $h ^= Math::mult64(ord($this->mem[$p]), self::PRIME5);
            $h = Math::mult64(Math::rotl64($h, 11), self::PRIME1);
            $p++;
        }

        return self::avalanche64($h);
    }

    private static function round64(int $acc, int $input): int
    {
        $acc = Math::add64($acc, Math::mult64($input, self::PRIME2));
        $acc = Math::rotl64($acc, 31);
        return Math::mult64($acc, self::PRIME1);
    }

    private static function mergeRound64(int $h, int $val): int
    {
        $val = self::round64(0, $val);
        $h ^= $val;
        return Math::add64(Math::mult64($h, self::PRIME1), self::PRIME4);
    }

    public static function avalanche64(int $h): int
    {
        $h = Math::xorshift64($h, 33);
        $h = Math::mult64($h, self::PRIME2);
        $h = Math::xorshift64($h, 29);
        $h = Math::mult64($h, self::PRIME3);
        $h = Math::xorshift64($h, 32);
        return $h;
    }
}
