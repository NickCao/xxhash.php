<?php

declare(strict_types=1);

namespace XXHash\Benchmarks;

use PhpBench\Attributes as Bench;
use XXHash\XXH32;
use XXHash\XXH64;
use XXHash\XXH3;

#[Bench\BeforeMethods('setUp')]
class XXHashBench
{
    private string $data16;
    private string $data64;
    private string $data256;
    private string $data1024;
    private string $data8192;

    public function setUp(): void
    {
        $this->data16 = random_bytes(16);
        $this->data64 = random_bytes(64);
        $this->data256 = random_bytes(256);
        $this->data1024 = random_bytes(1024);
        $this->data8192 = random_bytes(8192);
    }

    // ========================================================================
    // XXH32
    // ========================================================================

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh32_pure_16b(): void { XXH32::hash($this->data16); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh32_builtin_16b(): void { hash('xxh32', $this->data16); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh32_pure_256b(): void { XXH32::hash($this->data256); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh32_builtin_256b(): void { hash('xxh32', $this->data256); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh32_pure_8k(): void { XXH32::hash($this->data8192); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh32_builtin_8k(): void { hash('xxh32', $this->data8192); }

    // ========================================================================
    // XXH64
    // ========================================================================

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh64_pure_16b(): void { XXH64::hash($this->data16); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh64_builtin_16b(): void { hash('xxh64', $this->data16); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh64_pure_256b(): void { XXH64::hash($this->data256); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh64_builtin_256b(): void { hash('xxh64', $this->data256); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh64_pure_8k(): void { XXH64::hash($this->data8192); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh64_builtin_8k(): void { hash('xxh64', $this->data8192); }

    // ========================================================================
    // XXH3_64
    // ========================================================================

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh3_64_pure_16b(): void { XXH3::hash64($this->data16); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh3_64_builtin_16b(): void { hash('xxh3', $this->data16); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh3_64_pure_256b(): void { XXH3::hash64($this->data256); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh3_64_builtin_256b(): void { hash('xxh3', $this->data256); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh3_64_pure_8k(): void { XXH3::hash64($this->data8192); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh3_64_builtin_8k(): void { hash('xxh3', $this->data8192); }

    // ========================================================================
    // XXH3_128
    // ========================================================================

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh3_128_pure_16b(): void { XXH3::hash128($this->data16); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh3_128_builtin_16b(): void { hash('xxh128', $this->data16); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh3_128_pure_256b(): void { XXH3::hash128($this->data256); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh3_128_builtin_256b(): void { hash('xxh128', $this->data256); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh3_128_pure_8k(): void { XXH3::hash128($this->data8192); }

    #[Bench\Revs(1000), Bench\Iterations(5)]
    #[Bench\Subject]
    public function xxh3_128_builtin_8k(): void { hash('xxh128', $this->data8192); }
}
