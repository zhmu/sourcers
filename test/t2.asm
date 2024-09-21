seg_a           segment byte public
                assume  ds:seg_a,es:seg_a
                org     100h

start:          jmp     entry

message         db      "Hello world$"

entry:          mov     ah,9
                mov     dx,offset message
                int     21h
                int     20h

seg_a           ends
                end start
