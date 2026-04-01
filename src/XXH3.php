<?php

declare(strict_types=1);

namespace XXHash;

class XXH3
{
    private const STRIPE_LEN = 64;
    private const ACC_NB = 8;
    private const SECRET_CONSUME_RATE = 8;
    private const SECRET_SIZE_MIN = 136;
    private const SECRET_DEFAULT_SIZE = 192;
    private const SECRET_LASTACC_START = 7;
    private const SECRET_MERGEACCS_START = 11;
    private const MIDSIZE_STARTOFFSET = 3;
    private const MIDSIZE_LASTOFFSET = 17;
    private const MIDSIZE_MAX = 240;
    private const INTERNALBUFFER_SIZE = 256;
    private const INTERNALBUFFER_STRIPES = 4; // 256 / 64

    // XXH64 primes (reused in XXH3)
    private const PRIME64_1 = ~0x61C8864E7A143578; // 0x9E3779B185EBCA87
    private const PRIME64_2 = ~0x3D4D51C2D82B14B0; // 0xC2B2AE3D27D4EB4F
    private const PRIME64_3 = 0x165667B19E3779F9;
    private const PRIME64_4 = ~0x7A1435883D4D519C; // 0x85EBCA77C2B2AE63
    private const PRIME64_5 = 0x27D4EB2F165667C5;

    // XXH32 primes (used in init_acc and scramble)
    private const PRIME32_1 = 0x9E3779B1;
    private const PRIME32_2 = 0x85EBCA77;
    private const PRIME32_3 = 0xC2B2AE3D;

    // XXH3-specific mixing primes
    private const PRIME_MX1 = 0x165667919E3779F9;
    private const PRIME_MX2 = ~0x604DE39AE16720DA; // 0x9FB21C651E98DF25

    /** @var string|null */
    private static ?string $defaultSecret = null;

    // --- Streaming state ---
    /** @var int[] */
    private array $acc;
    private string $buffer;
    private int $bufferedSize = 0;
    private int $totalLen = 0;
    private int $nbStripesSoFar = 0;
    private int $nbStripesPerBlock;
    private int $secretLimit;
    private string $secret;
    private int $seed;
    private bool $useSeed;

    // ========================================================================
    // Default secret
    // ========================================================================

    public static function getDefaultSecret(): string
    {
        if (self::$defaultSecret === null) {
            self::$defaultSecret = hex2bin(
                'b8fe6c3923a44bbe' . '7c01812cf721ad1c' .
                'ded46de9839097db' . '7240a4a4b7b3671f' .
                'cb79e64eccc0e578' . '825ad07dccff7221' .
                'b8084674f743248e' . 'e03590e6813a264c' .
                '3c2852bb91c300cb' . '88d0658b1b532ea3' .
                '71644897a20df94e' . '3819ef46a9deacd8' .
                'a8fa763fe39c343f' . 'f9dcbbc7c70b4f1d' .
                '8a51e04bcdb45931' . 'c89f7ec9d9787364' .
                'eac5ac8334d3ebc3' . 'c581a0fffa1363eb' .
                '170ddd51b7f0da49' . 'd316552629d4689e' .
                '2b16be587d47a1fc' . '8ff8b8d17ad031ce' .
                '45cb3a8f95160428' . 'afd7fbcabb4b407e'
            );
        }
        return self::$defaultSecret;
    }

    private static function initAcc(): array
    {
        return [
            self::PRIME32_3,  // 0xC2B2AE3D (as 64-bit)
            self::PRIME64_1,
            self::PRIME64_2,
            self::PRIME64_3,
            self::PRIME64_4,
            self::PRIME32_2,  // 0x85EBCA77 (as 64-bit)
            self::PRIME64_5,
            self::PRIME32_1,  // 0x9E3779B1 (as 64-bit)
        ];
    }

    // ========================================================================
    // One-shot API
    // ========================================================================

    /** One-shot 64-bit hash with seed */
    public static function hash64(string $data, int $seed = 0): int
    {
        $len = strlen($data);
        $secret = self::getDefaultSecret();

        if ($len <= 16) return self::len0to16_64($data, $len, $secret, $seed);
        if ($len <= 128) return self::len17to128_64($data, $len, $secret, self::SECRET_DEFAULT_SIZE, $seed);
        if ($len <= self::MIDSIZE_MAX) return self::len129to240_64($data, $len, $secret, self::SECRET_DEFAULT_SIZE, $seed);

        // Long path: derive secret from seed if seed != 0
        if ($seed === 0) {
            return self::hashLong64($data, $len, $secret, self::SECRET_DEFAULT_SIZE);
        }
        $customSecret = self::initCustomSecret($seed);
        return self::hashLong64($data, $len, $customSecret, self::SECRET_DEFAULT_SIZE);
    }

    /** One-shot 64-bit hash with custom secret */
    public static function hash64WithSecret(string $data, string $secret): int
    {
        $len = strlen($data);
        $secretSize = strlen($secret);

        if ($len <= 16) return self::len0to16_64($data, $len, $secret, 0);
        if ($len <= 128) return self::len17to128_64($data, $len, $secret, $secretSize, 0);
        if ($len <= self::MIDSIZE_MAX) return self::len129to240_64($data, $len, $secret, $secretSize, 0);
        return self::hashLong64($data, $len, $secret, $secretSize);
    }

    /** One-shot 128-bit hash with seed. Returns [low64, high64]. */
    public static function hash128(string $data, int $seed = 0): array
    {
        $len = strlen($data);
        $secret = self::getDefaultSecret();

        if ($len <= 16) return self::len0to16_128($data, $len, $secret, $seed);
        if ($len <= 128) return self::len17to128_128($data, $len, $secret, self::SECRET_DEFAULT_SIZE, $seed);
        if ($len <= self::MIDSIZE_MAX) return self::len129to240_128($data, $len, $secret, self::SECRET_DEFAULT_SIZE, $seed);

        if ($seed === 0) {
            return self::hashLong128($data, $len, $secret, self::SECRET_DEFAULT_SIZE);
        }
        $customSecret = self::initCustomSecret($seed);
        return self::hashLong128($data, $len, $customSecret, self::SECRET_DEFAULT_SIZE);
    }

    /** One-shot 128-bit hash with custom secret. Returns [low64, high64]. */
    public static function hash128WithSecret(string $data, string $secret): array
    {
        $len = strlen($data);
        $secretSize = strlen($secret);

        if ($len <= 16) return self::len0to16_128($data, $len, $secret, 0);
        if ($len <= 128) return self::len17to128_128($data, $len, $secret, $secretSize, 0);
        if ($len <= self::MIDSIZE_MAX) return self::len129to240_128($data, $len, $secret, $secretSize, 0);
        return self::hashLong128($data, $len, $secret, $secretSize);
    }

    // ========================================================================
    // Streaming API
    // ========================================================================

    public function __construct(int $seed = 0, ?string $secret = null)
    {
        $this->seed = $seed;
        $this->useSeed = ($secret === null);

        if ($secret !== null) {
            $this->secret = $secret;
        } elseif ($seed === 0) {
            $this->secret = self::getDefaultSecret();
        } else {
            $this->secret = self::initCustomSecret($seed);
        }

        $secretSize = strlen($this->secret);
        $this->secretLimit = $secretSize - self::STRIPE_LEN;
        $this->nbStripesPerBlock = ($secretSize - self::STRIPE_LEN) / self::SECRET_CONSUME_RATE;
        $this->buffer = str_repeat("\0", self::INTERNALBUFFER_SIZE);
        $this->acc = self::initAcc();
        $this->bufferedSize = 0;
        $this->totalLen = 0;
        $this->nbStripesSoFar = 0;
    }

    public function reset(): void
    {
        $this->acc = self::initAcc();
        $this->buffer = str_repeat("\0", self::INTERNALBUFFER_SIZE);
        $this->bufferedSize = 0;
        $this->totalLen = 0;
        $this->nbStripesSoFar = 0;
    }

    public function update(string $data): self
    {
        $len = strlen($data);
        if ($len === 0) return $this;
        $this->totalLen += $len;
        $offset = 0;

        if ($this->bufferedSize + $len <= self::INTERNALBUFFER_SIZE) {
            // Just buffer
            self::bufferWrite($this->buffer, $this->bufferedSize, $data);
            $this->bufferedSize += $len;
            return $this;
        }

        // Fill buffer to capacity and process
        if ($this->bufferedSize > 0) {
            $loadSize = self::INTERNALBUFFER_SIZE - $this->bufferedSize;
            self::bufferWrite($this->buffer, $this->bufferedSize, substr($data, 0, $loadSize));
            $offset += $loadSize;
            $this->consumeStripes($this->acc, $this->buffer, self::INTERNALBUFFER_STRIPES, $this->secret);
            $this->bufferedSize = 0;
        }

        // Process full blocks from input
        if ($len - $offset > self::INTERNALBUFFER_SIZE) {
            while ($len - $offset > self::INTERNALBUFFER_SIZE) {
                $chunk = substr($data, $offset, self::INTERNALBUFFER_SIZE);
                $this->consumeStripes($this->acc, $chunk, self::INTERNALBUFFER_STRIPES, $this->secret);
                $offset += self::INTERNALBUFFER_SIZE;
            }
            // Save last stripe to end of buffer for catchup in digestLong
            self::bufferWrite($this->buffer,
                self::INTERNALBUFFER_SIZE - self::STRIPE_LEN,
                substr($data, $offset - self::STRIPE_LEN, self::STRIPE_LEN));
        }

        // Buffer remaining
        if ($offset < $len) {
            $remaining = substr($data, $offset);
            $remLen = strlen($remaining);
            self::bufferWrite($this->buffer, 0, $remaining);
            $this->bufferedSize = $remLen;
        }

        return $this;
    }

    public function digest64(): int
    {
        $secret = $this->secret;

        if ($this->totalLen > self::MIDSIZE_MAX) {
            $acc = $this->acc; // copy
            $this->digestLong($acc, $secret);
            return self::mergeAccs($acc, $secret, self::SECRET_MERGEACCS_START,
                Math::mult64($this->totalLen, self::PRIME64_1));
        }

        // Short input: hash buffer directly
        $buf = substr($this->buffer, 0, $this->bufferedSize);
        if ($this->useSeed) {
            return self::hash64($buf, $this->seed);
        }
        return self::hash64WithSecret($buf, $secret);
    }

    /** Returns [low64, high64] */
    public function digest128(): array
    {
        $secret = $this->secret;
        $secretSize = strlen($secret);

        if ($this->totalLen > self::MIDSIZE_MAX) {
            $acc = $this->acc; // copy
            $this->digestLong($acc, $secret);

            $lo = self::mergeAccs($acc, $secret, self::SECRET_MERGEACCS_START,
                Math::mult64($this->totalLen, self::PRIME64_1));
            $hi = self::mergeAccs($acc, $secret,
                $secretSize - self::STRIPE_LEN - self::SECRET_MERGEACCS_START,
                ~Math::mult64($this->totalLen, self::PRIME64_2));
            return [$lo, $hi];
        }

        $buf = substr($this->buffer, 0, $this->bufferedSize);
        if ($this->useSeed) {
            return self::hash128($buf, $this->seed);
        }
        return self::hash128WithSecret($buf, $secret);
    }

    private function digestLong(array &$acc, string $secret): void
    {
        if ($this->bufferedSize >= self::STRIPE_LEN) {
            $nbStripes = (int)(($this->bufferedSize - 1) / self::STRIPE_LEN);
            $nbStripesSoFar = $this->nbStripesSoFar;
            self::consumeStripesRaw($acc, $nbStripesSoFar, $this->nbStripesPerBlock,
                $this->buffer, $nbStripes, $secret, $this->secretLimit);
            $lastStripe = substr($this->buffer, $this->bufferedSize - self::STRIPE_LEN, self::STRIPE_LEN);
        } else {
            // Construct last stripe from end of buffer array + current buffer
            $catchupSize = self::STRIPE_LEN - $this->bufferedSize;
            $lastStripe = substr($this->buffer, self::INTERNALBUFFER_SIZE - $catchupSize, $catchupSize)
                        . substr($this->buffer, 0, $this->bufferedSize);
        }
        self::accumulate512($acc, $lastStripe, 0, $secret, $this->secretLimit - self::SECRET_LASTACC_START);
    }

    private function consumeStripes(array &$acc, string $data, int $nbStripes, string $secret): void
    {
        self::consumeStripesRaw($acc, $this->nbStripesSoFar, $this->nbStripesPerBlock,
            $data, $nbStripes, $secret, $this->secretLimit);
    }

    private static function consumeStripesRaw(
        array &$acc, int &$nbStripesSoFar, int $nbStripesPerBlock,
        string $data, int $nbStripes, string $secret, int $secretLimit
    ): void {
        for ($i = 0; $i < $nbStripes; $i++) {
            self::accumulate512($acc, $data, $i * self::STRIPE_LEN,
                $secret, $nbStripesSoFar * self::SECRET_CONSUME_RATE);
            $nbStripesSoFar++;
            if ($nbStripesSoFar === $nbStripesPerBlock) {
                self::scrambleAcc($acc, $secret, $secretLimit);
                $nbStripesSoFar = 0;
            }
        }
    }

    // ========================================================================
    // Secret derivation
    // ========================================================================

    private static function initCustomSecret(int $seed): string
    {
        $kSecret = self::getDefaultSecret();
        $customSecret = str_repeat("\0", self::SECRET_DEFAULT_SIZE);
        $nbRounds = self::SECRET_DEFAULT_SIZE / 16;

        for ($i = 0; $i < $nbRounds; $i++) {
            $lo = Math::add64(Math::read64($kSecret, 16 * $i), $seed);
            $hi = Math::sub64(Math::read64($kSecret, 16 * $i + 8), $seed);
            Math::write64($customSecret, 16 * $i, $lo);
            Math::write64($customSecret, 16 * $i + 8, $hi);
        }

        return $customSecret;
    }

    // ========================================================================
    // Core operations
    // ========================================================================

    private static function accumulate512(array &$acc, string $data, int $dataOff, string $secret, int $secretOff): void
    {
        for ($lane = 0; $lane < self::ACC_NB; $lane++) {
            $dataVal = Math::read64($data, $dataOff + $lane * 8);
            $dataKey = $dataVal ^ Math::read64($secret, $secretOff + $lane * 8);
            $acc[$lane ^ 1] = Math::add64($acc[$lane ^ 1], $dataVal);
            // lo32 * hi32 + acc
            $lo32 = $dataKey & 0xFFFFFFFF;
            $hi32 = ($dataKey >> 32) & 0xFFFFFFFF;
            $acc[$lane] = Math::add64($acc[$lane], Math::mult32to64($lo32, $hi32));
        }
    }

    private static function scrambleAcc(array &$acc, string $secret, int $secretOff): void
    {
        for ($lane = 0; $lane < self::ACC_NB; $lane++) {
            $key64 = Math::read64($secret, $secretOff + $lane * 8);
            $acc64 = $acc[$lane];
            $acc64 = Math::xorshift64($acc64, 47);
            $acc64 ^= $key64;
            $acc64 = Math::mult64($acc64, self::PRIME32_1);
            $acc[$lane] = $acc64;
        }
    }

    private static function mix16B(string $data, int $dataOff, string $secret, int $secretOff, int $seed): int
    {
        $inputLo = Math::read64($data, $dataOff);
        $inputHi = Math::read64($data, $dataOff + 8);
        return Math::mul128fold64(
            $inputLo ^ Math::add64(Math::read64($secret, $secretOff), $seed),
            $inputHi ^ Math::sub64(Math::read64($secret, $secretOff + 8), $seed)
        );
    }

    private static function mix2Accs(array $acc, int $accOff, string $secret, int $secretOff): int
    {
        return Math::mul128fold64(
            $acc[$accOff] ^ Math::read64($secret, $secretOff),
            $acc[$accOff + 1] ^ Math::read64($secret, $secretOff + 8)
        );
    }

    private static function mergeAccs(array $acc, string $secret, int $secretOff, int $start): int
    {
        $result = $start;
        for ($i = 0; $i < 4; $i++) {
            $result = Math::add64($result, self::mix2Accs($acc, 2 * $i, $secret, $secretOff + 16 * $i));
        }
        return self::avalanche($result);
    }

    // ========================================================================
    // Avalanche / finalization functions
    // ========================================================================

    private static function avalanche(int $h): int
    {
        $h = Math::xorshift64($h, 37);
        $h = Math::mult64($h, self::PRIME_MX1);
        $h = Math::xorshift64($h, 32);
        return $h;
    }

    private static function rrmxmx(int $h, int $len): int
    {
        $h ^= Math::rotl64($h, 49) ^ Math::rotl64($h, 24);
        $h = Math::mult64($h, self::PRIME_MX2);
        $h ^= Math::add64(Math::shr64($h, 35), $len);
        $h = Math::mult64($h, self::PRIME_MX2);
        return Math::xorshift64($h, 28);
    }

    // ========================================================================
    // 64-bit short/medium paths
    // ========================================================================

    private static function len0to16_64(string $data, int $len, string $secret, int $seed): int
    {
        if ($len > 8) return self::len9to16_64($data, $len, $secret, $seed);
        if ($len >= 4) return self::len4to8_64($data, $len, $secret, $seed);
        if ($len > 0) return self::len1to3_64($data, $len, $secret, $seed);
        return XXH64::avalanche64($seed ^ (Math::read64($secret, 56) ^ Math::read64($secret, 64)));
    }

    private static function len1to3_64(string $data, int $len, string $secret, int $seed): int
    {
        $c1 = ord($data[0]);
        $c2 = ord($data[$len >> 1]);
        $c3 = ord($data[$len - 1]);
        $combined = ($c1 << 16) | ($c2 << 24) | ($c3 << 0) | ($len << 8);
        $bitflip = (Math::read32($secret, 0) ^ Math::read32($secret, 4)) + $seed;
        $keyed = $combined ^ $bitflip;
        return XXH64::avalanche64($keyed);
    }

    private static function len4to8_64(string $data, int $len, string $secret, int $seed): int
    {
        $seed ^= Math::swap32($seed & 0xFFFFFFFF) << 32;
        $input1 = Math::read32($data, 0);
        $input2 = Math::read32($data, $len - 4);
        $bitflip = Math::sub64(Math::read64($secret, 8) ^ Math::read64($secret, 16), $seed);
        $input64 = Math::add64($input2, $input1 << 32);
        $keyed = $input64 ^ $bitflip;
        return self::rrmxmx($keyed, $len);
    }

    private static function len9to16_64(string $data, int $len, string $secret, int $seed): int
    {
        $bitflip1 = Math::add64(Math::read64($secret, 24) ^ Math::read64($secret, 32), $seed);
        $bitflip2 = Math::sub64(Math::read64($secret, 40) ^ Math::read64($secret, 48), $seed);
        $inputLo = Math::read64($data, 0) ^ $bitflip1;
        $inputHi = Math::read64($data, $len - 8) ^ $bitflip2;
        $acc = Math::add64(
            Math::add64($len, Math::swap64($inputLo)),
            Math::add64($inputHi, Math::mul128fold64($inputLo, $inputHi))
        );
        return self::avalanche($acc);
    }

    private static function len17to128_64(string $data, int $len, string $secret, int $secretSize, int $seed): int
    {
        $acc = Math::mult64($len, self::PRIME64_1);

        if ($len > 32) {
            if ($len > 64) {
                if ($len > 96) {
                    $acc = Math::add64($acc, self::mix16B($data, 48, $secret, 96, $seed));
                    $acc = Math::add64($acc, self::mix16B($data, $len - 64, $secret, 112, $seed));
                }
                $acc = Math::add64($acc, self::mix16B($data, 32, $secret, 64, $seed));
                $acc = Math::add64($acc, self::mix16B($data, $len - 48, $secret, 80, $seed));
            }
            $acc = Math::add64($acc, self::mix16B($data, 16, $secret, 32, $seed));
            $acc = Math::add64($acc, self::mix16B($data, $len - 32, $secret, 48, $seed));
        }
        $acc = Math::add64($acc, self::mix16B($data, 0, $secret, 0, $seed));
        $acc = Math::add64($acc, self::mix16B($data, $len - 16, $secret, 16, $seed));

        return self::avalanche($acc);
    }

    private static function len129to240_64(string $data, int $len, string $secret, int $secretSize, int $seed): int
    {
        $acc = Math::mult64($len, self::PRIME64_1);
        $nbRounds = (int)($len / 16);

        for ($i = 0; $i < 8; $i++) {
            $acc = Math::add64($acc, self::mix16B($data, 16 * $i, $secret, 16 * $i, $seed));
        }
        $accEnd = self::mix16B($data, $len - 16, $secret,
            self::SECRET_SIZE_MIN - self::MIDSIZE_LASTOFFSET, $seed);
        $acc = self::avalanche($acc);

        for ($i = 8; $i < $nbRounds; $i++) {
            $accEnd = Math::add64($accEnd, self::mix16B($data, 16 * $i, $secret,
                16 * ($i - 8) + self::MIDSIZE_STARTOFFSET, $seed));
        }
        return self::avalanche(Math::add64($acc, $accEnd));
    }

    // ========================================================================
    // 64-bit long path
    // ========================================================================

    private static function hashLong64(string $data, int $len, string $secret, int $secretSize): int
    {
        $acc = self::initAcc();
        self::hashLongInternalLoop($acc, $data, $len, $secret, $secretSize);
        return self::mergeAccs($acc, $secret, self::SECRET_MERGEACCS_START,
            Math::mult64($len, self::PRIME64_1));
    }

    private static function hashLongInternalLoop(array &$acc, string $data, int $len, string $secret, int $secretSize): void
    {
        $nbStripesPerBlock = (int)(($secretSize - self::STRIPE_LEN) / self::SECRET_CONSUME_RATE);
        $blockLen = self::STRIPE_LEN * $nbStripesPerBlock;
        $nbBlocks = (int)(($len - 1) / $blockLen);

        for ($n = 0; $n < $nbBlocks; $n++) {
            for ($s = 0; $s < $nbStripesPerBlock; $s++) {
                self::accumulate512($acc, $data, $n * $blockLen + $s * self::STRIPE_LEN,
                    $secret, $s * self::SECRET_CONSUME_RATE);
            }
            self::scrambleAcc($acc, $secret, $secretSize - self::STRIPE_LEN);
        }

        // Last partial block
        $nbStripes = (int)(($len - 1 - $blockLen * $nbBlocks) / self::STRIPE_LEN);
        for ($s = 0; $s < $nbStripes; $s++) {
            self::accumulate512($acc, $data, $nbBlocks * $blockLen + $s * self::STRIPE_LEN,
                $secret, $s * self::SECRET_CONSUME_RATE);
        }

        // Last stripe
        self::accumulate512($acc, $data, $len - self::STRIPE_LEN,
            $secret, $secretSize - self::STRIPE_LEN - self::SECRET_LASTACC_START);
    }

    // ========================================================================
    // 128-bit short/medium paths
    // ========================================================================

    private static function len0to16_128(string $data, int $len, string $secret, int $seed): array
    {
        if ($len > 8) return self::len9to16_128($data, $len, $secret, $seed);
        if ($len >= 4) return self::len4to8_128($data, $len, $secret, $seed);
        if ($len > 0) return self::len1to3_128($data, $len, $secret, $seed);
        $bitflipl = Math::read64($secret, 64) ^ Math::read64($secret, 72);
        $bitfliph = Math::read64($secret, 80) ^ Math::read64($secret, 88);
        return [
            XXH64::avalanche64($seed ^ $bitflipl),
            XXH64::avalanche64($seed ^ $bitfliph),
        ];
    }

    private static function len1to3_128(string $data, int $len, string $secret, int $seed): array
    {
        $c1 = ord($data[0]);
        $c2 = ord($data[$len >> 1]);
        $c3 = ord($data[$len - 1]);
        $combinedl = ($c1 << 16) | ($c2 << 24) | ($c3 << 0) | ($len << 8);
        $combinedh = Math::rotl32(Math::swap32($combinedl), 13);
        $bitflipl = (Math::read32($secret, 0) ^ Math::read32($secret, 4)) + $seed;
        $bitfliph = Math::sub64(Math::read32($secret, 8) ^ Math::read32($secret, 12), $seed);
        return [
            XXH64::avalanche64($combinedl ^ $bitflipl),
            XXH64::avalanche64($combinedh ^ $bitfliph),
        ];
    }

    private static function len4to8_128(string $data, int $len, string $secret, int $seed): array
    {
        $seed ^= Math::swap32($seed & 0xFFFFFFFF) << 32;
        $inputLo = Math::read32($data, 0);
        $inputHi = Math::read32($data, $len - 4);
        $input64 = Math::add64($inputLo, $inputHi << 32);
        $bitflip = Math::add64(Math::read64($secret, 16) ^ Math::read64($secret, 24), $seed);
        $keyed = $input64 ^ $bitflip;

        // mult64to128(keyed, PRIME64_1 + (len << 2))
        [$mLo, $mHi] = Math::mult128($keyed, Math::add64(self::PRIME64_1, $len << 2));

        $mHi = Math::add64($mHi, $mLo << 1);
        $mLo ^= Math::shr64($mHi, 3);

        $mLo = Math::xorshift64($mLo, 35);
        $mLo = Math::mult64($mLo, self::PRIME_MX2);
        $mLo = Math::xorshift64($mLo, 28);
        $mHi = self::avalanche($mHi);

        return [$mLo, $mHi];
    }

    private static function len9to16_128(string $data, int $len, string $secret, int $seed): array
    {
        $bitflipl = Math::sub64(Math::read64($secret, 32) ^ Math::read64($secret, 40), $seed);
        $bitfliph = Math::add64(Math::read64($secret, 48) ^ Math::read64($secret, 56), $seed);
        $inputLo = Math::read64($data, 0);
        $inputHi = Math::read64($data, $len - 8);

        [$mLo, $mHi] = Math::mult128($inputLo ^ $inputHi ^ $bitflipl, self::PRIME64_1);

        $mLo = Math::add64($mLo, ($len - 1) << 54);
        $inputHi ^= $bitfliph;

        // 64-bit path (sizeof(void*) >= sizeof(xxh_u64))
        $mHi = Math::add64($mHi, Math::add64($inputHi,
            Math::mult32to64($inputHi & 0xFFFFFFFF, self::PRIME32_2 - 1)));

        $mLo ^= Math::swap64($mHi);

        // 128x64 multiply: h128 = m128 * PRIME64_2
        [$hLo, $hHi] = Math::mult128($mLo, self::PRIME64_2);
        $hHi = Math::add64($hHi, Math::mult64($mHi, self::PRIME64_2));

        $hLo = self::avalanche($hLo);
        $hHi = self::avalanche($hHi);

        return [$hLo, $hHi];
    }

    /** Helper for 128-bit medium paths */
    private static function mix32B(
        int $accLo, int $accHi,
        string $data, int $off1, int $off2,
        string $secret, int $secretOff,
        int $seed
    ): array {
        $accLo = Math::add64($accLo, self::mix16B($data, $off1, $secret, $secretOff, $seed));
        $accLo ^= Math::add64(Math::read64($data, $off2), Math::read64($data, $off2 + 8));
        $accHi = Math::add64($accHi, self::mix16B($data, $off2, $secret, $secretOff + 16, $seed));
        $accHi ^= Math::add64(Math::read64($data, $off1), Math::read64($data, $off1 + 8));
        return [$accLo, $accHi];
    }

    private static function len17to128_128(string $data, int $len, string $secret, int $secretSize, int $seed): array
    {
        $accLo = Math::mult64($len, self::PRIME64_1);
        $accHi = 0;

        if ($len > 32) {
            if ($len > 64) {
                if ($len > 96) {
                    [$accLo, $accHi] = self::mix32B($accLo, $accHi, $data, 48, $len - 64, $secret, 96, $seed);
                }
                [$accLo, $accHi] = self::mix32B($accLo, $accHi, $data, 32, $len - 48, $secret, 64, $seed);
            }
            [$accLo, $accHi] = self::mix32B($accLo, $accHi, $data, 16, $len - 32, $secret, 32, $seed);
        }
        [$accLo, $accHi] = self::mix32B($accLo, $accHi, $data, 0, $len - 16, $secret, 0, $seed);

        $hLo = Math::add64($accLo, $accHi);
        $hHi = Math::add64(
            Math::add64(Math::mult64($accLo, self::PRIME64_1), Math::mult64($accHi, self::PRIME64_4)),
            Math::mult64(Math::sub64($len, $seed), self::PRIME64_2)
        );
        $hLo = self::avalanche($hLo);
        $hHi = Math::sub64(0, self::avalanche($hHi));

        return [$hLo, $hHi];
    }

    private static function len129to240_128(string $data, int $len, string $secret, int $secretSize, int $seed): array
    {
        $accLo = Math::mult64($len, self::PRIME64_1);
        $accHi = 0;

        for ($i = 32; $i < 160; $i += 32) {
            [$accLo, $accHi] = self::mix32B($accLo, $accHi, $data, $i - 32, $i - 16, $secret, $i - 32, $seed);
        }
        $accLo = self::avalanche($accLo);
        $accHi = self::avalanche($accHi);

        for ($i = 160; $i <= $len; $i += 32) {
            [$accLo, $accHi] = self::mix32B($accLo, $accHi, $data, $i - 32, $i - 16,
                $secret, self::MIDSIZE_STARTOFFSET + $i - 160, $seed);
        }
        // Last bytes
        [$accLo, $accHi] = self::mix32B($accLo, $accHi, $data, $len - 16, $len - 32,
            $secret, self::SECRET_SIZE_MIN - self::MIDSIZE_LASTOFFSET - 16,
            Math::sub64(0, $seed));

        $hLo = Math::add64($accLo, $accHi);
        $hHi = Math::add64(
            Math::add64(Math::mult64($accLo, self::PRIME64_1), Math::mult64($accHi, self::PRIME64_4)),
            Math::mult64(Math::sub64($len, $seed), self::PRIME64_2)
        );
        $hLo = self::avalanche($hLo);
        $hHi = Math::sub64(0, self::avalanche($hHi));

        return [$hLo, $hHi];
    }

    // ========================================================================
    // 128-bit long path
    // ========================================================================

    private static function hashLong128(string $data, int $len, string $secret, int $secretSize): array
    {
        $acc = self::initAcc();
        self::hashLongInternalLoop($acc, $data, $len, $secret, $secretSize);

        $lo = self::mergeAccs($acc, $secret, self::SECRET_MERGEACCS_START,
            Math::mult64($len, self::PRIME64_1));
        $hi = self::mergeAccs($acc, $secret,
            $secretSize - self::STRIPE_LEN - self::SECRET_MERGEACCS_START,
            ~Math::mult64($len, self::PRIME64_2));
        return [$lo, $hi];
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private static function bufferWrite(string &$buffer, int $offset, string $data): void
    {
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $buffer[$offset + $i] = $data[$i];
        }
    }
}
