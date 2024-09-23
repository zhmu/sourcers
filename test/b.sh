#!/bin/sh
WATCOM=/opt/watcom

${WATCOM}/binl64/wasm -3 -bt=dos -ml t1.asm -fo=../build/t1.obj
${WATCOM}/binl64/wlink option quiet format raw bin file ../build/t1.obj name t1.bin

${WATCOM}/binl64/wasm -0 -bt=dos -ml t2.asm -fo=../build/t2.obj
${WATCOM}/binl64/wlink option quiet format dos com file ../build/t2.obj name t2.com

${WATCOM}/binl64/wasm -0 -bt=dos -ml t3.asm -fo=../build/t3.obj
${WATCOM}/binl64/wlink option quiet format dos file ../build/t3.obj name t3.exe
