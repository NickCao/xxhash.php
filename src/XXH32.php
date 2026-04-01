<?php

declare(strict_types=1);

namespace XXHash;

class XXH32
{
    private const PRIME1 = 0x9E3779B1;
    private const PRIME2 = 0x85EBCA77;
    private const PRIME3 = 0xC2B2AE3D;
    private const PRIME4 = 0x27D4EB2F;
    private const PRIME5 = 0x165667B1;

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
        $this->seed = $seed & 0xFFFFFFFF;
        $this->reset();
    }

    public function reset(): void
    {
        $this->totalLen = 0;
        $this->memSize = 0;
        $this->mem = '';
        $s = $this->seed;
        $this->v1 = ($s + self::PRIME1 + self::PRIME2) & 0xFFFFFFFF;
        $this->v2 = ($s + self::PRIME2) & 0xFFFFFFFF;
        $this->v3 = $s;
        $this->v4 = ($s - self::PRIME1 + 0x100000000) & 0xFFFFFFFF;
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
            $needed = 16 - $this->memSize;
            if ($len >= $needed) {
                $this->mem .= substr($data, 0, $needed);
                $offset = $needed;
                $this->v1 = self::round32($this->v1, Math::read32($this->mem, 0));
                $this->v2 = self::round32($this->v2, Math::read32($this->mem, 4));
                $this->v3 = self::round32($this->v3, Math::read32($this->mem, 8));
                $this->v4 = self::round32($this->v4, Math::read32($this->mem, 12));
                $this->memSize = 0;
                $this->mem = '';
            } else {
                $this->mem .= $data;
                $this->memSize += $len;
                return $this;
            }
        }

        while ($len - $offset >= 16) {
            $this->v1 = self::round32($this->v1, Math::read32($data, $offset));
            $this->v2 = self::round32($this->v2, Math::read32($data, $offset + 4));
            $this->v3 = self::round32($this->v3, Math::read32($data, $offset + 8));
            $this->v4 = self::round32($this->v4, Math::read32($data, $offset + 12));
            $offset += 16;
        }

        if ($offset < $len) {
            $this->mem = substr($data, $offset);
            $this->memSize = $len - $offset;
        }

        return $this;
    }

    public function digest(): int
    {
        if ($this->totalLen >= 16) {
            $h = (Math::rotl32($this->v1, 1) + Math::rotl32($this->v2, 7)
                + Math::rotl32($this->v3, 12) + Math::rotl32($this->v4, 18)) & 0xFFFFFFFF;
        } else {
            $h = ($this->v3 + self::PRIME5) & 0xFFFFFFFF;
        }

        $h = ($h + $this->totalLen) & 0xFFFFFFFF;

        $p = 0;
        while ($this->memSize - $p >= 4) {
            $h = ($h + Math::mult32(Math::read32($this->mem, $p), self::PRIME3)) & 0xFFFFFFFF;
            $h = Math::mult32(Math::rotl32($h, 17), self::PRIME4);
            $p += 4;
        }

        while ($p < $this->memSize) {
            $h = ($h + ord($this->mem[$p]) * self::PRIME5) & 0xFFFFFFFF;
            $h = Math::mult32(Math::rotl32($h, 11), self::PRIME1);
            $p++;
        }

        return self::avalanche32($h);
    }

    private static function round32(int $acc, int $input): int
    {
        $acc = ($acc + Math::mult32($input, self::PRIME2)) & 0xFFFFFFFF;
        $acc = Math::rotl32($acc, 13);
        return Math::mult32($acc, self::PRIME1);
    }

    private static function avalanche32(int $h): int
    {
        $h ^= $h >> 15;
        $h = Math::mult32($h, self::PRIME2);
        $h ^= $h >> 13;
        $h = Math::mult32($h, self::PRIME3);
        $h ^= $h >> 16;
        return $h;
    }
}
