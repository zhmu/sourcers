data            segment byte public

message         db      "Hello world$"

data            ends

code            segment byte public
                assume  ds:data,es:data

entry:          mov	ax,data
		mov	ds,ax

		mov     ah,9
                mov     dx,offset message
                int     21h
		mov	ax,4c00h
                int     21h

code            ends
		end entry
