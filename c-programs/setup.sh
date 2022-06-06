#!/bin/bash

rv64bluesim="../rv64-bluesim"
rv64verilator="../rv64i-verilator"

printf "Enter the ELF file name (without .riscv): "
read fname
elf=$fname".riscv"
outdir="../hex-files/$fname"
# echo $fname
# echo $elf
# echo $outdir
# exit 0

if ! [ -e $elf ]; then
    echo "Error: $elf is not exist"
    exit -1
fi

if ! [ -d $outdir ]; then
    mkdir $outdir
fi

../elf_to_hex/elf_to_hex $elf Mem.hex
cp $elf $outdir
mv Mem.hex $outdir
mv symbol_table.txt $outdir

cp $outdir/Mem.hex $rv64bluesim
cp $outdir/symbol_table.txt $rv64bluesim

cp $outdir/Mem.hex $rv64verilator
cp $outdir/symbol_table.txt $rv64verilator
