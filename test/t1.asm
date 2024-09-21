seg_a           segment byte public
                assume  ds:seg_a,es:seg_a
                org     0

start:          mov     al,[var1]
                mov     bx,[var2]
                mov     ecx,[var3]
                jmp     exit

var1            db      1
var2            dw      2
var3            dd      3

exit:		int	20h

seg_a           ends
                end start
