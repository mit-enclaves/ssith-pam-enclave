.section ".text.entry"

.call_entry:
la ra, enclave_entry
jr ra

# enclave_entry should not return!
.hangout:
	j .hangout
