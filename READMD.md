## Base Project
다음 프로젝트를 기반으로 함
[https://github.com/riscv-software-src/riscv-tests]


## Make
### RISC-V Prefix
```bash
$ make XLEN=64
```

### Example
```
$ make
$ make simple-add.riscv
$ make simple-add.riscv.dump
```

### ELF file
컴파일 결과물인 ELF 파일은 `.riscv`

### objdump
기본적으로 objdump 결과는 컴파일 시 `*.riscv.dump` 파일에 기록된다.

```
$ make 
```

## ELF to Hex
`elf_to_hex`에 있는 유틸리티; RISC-V ELF(실행 파일)를 RISC-V 시뮬레이터에서 돌릴 수 있는 형식으로 변환한다.
다음은 `foo.riscv` 파일을 `Mem.hex`로 변환하는 예제다. `Mem.hex`와 `symbol_table.txt`를 출력한다.

```
elf_to_hex foo.riscv Mem.hex
```


## Emulator
다음과 같은 파일들로 구성돼야 한다.
- exe_HW_sim: 시뮬레이터 실행파일
- exe_HW_sim.so: 시뮬레이터 실행파일의 shared object; BlueSim 시뮬레이터에 존재한다. (같이 있어야 실행 가능하다.)
- Mem.hex: 실행 프로그램 ELF의 변환 버전 (RISC-V 메모리에 적재된다고 보면 된다.)
- symbol_table.txt: 심볼 테이블(시작 주소와 tohost의 주소가 기입되어있다.)

### 예제
* `+v1`은 verbosity를 지정하는 옵션이다.
```
./exe_HW_sim  +v1  +tohost
```
