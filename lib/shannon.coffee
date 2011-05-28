###
Shannon stream cipher

The Shannon MAC function is modelled after the concepts of Phelix and SHA.
Basically, words to be accumulated in the MAC are incorporated in two
different ways:
1. They are incorporated into the stream cipher register at a place
   where they will immediately have a nonlinear effect on the state.

2. They are incorporated into bit-parallel CRC-16 registers; the
   contents of these registers will be used in MAC finalization.

Where the base functions in the original C implementation work per-word,
this implementation uses a byte-based approach, allowing a much cleaner
implementation.

Based on the Shannon implementation in Jotify by Felix Bruns.

(C) Emiel Mols, 2010. Released under the Simplified BSD License.
    Attribution is very much appreciated.
###
class Shannon
	
	rotateLeft = (num, n) -> (num << n) | (num >>> (32 - n))
	
	###
	Fold is how many register cycles need to be performed after combining the
	last byte of key and non-linear feedback, before every byte depends on every
	byte of the key. This depends on the feedback and nonlinear functions, and
	on where they are combined into the register. Making it same as the register
	length is a safe and conservative choice.
	###
	N = 16
	FOLD = N               # How many iterations of folding to do.
	INITKONST = 0x6996c53a # Value of konst to use during key loading.
	KEYP = 13              # Where to insert key/MAC/counter words.

	# Nonlinear transform (sbox) of a word. There are two slightly different combinations.
	sbox = (i) -> i ^= rotateLeft(i, 5) | rotateLeft(i, 7); i ^= rotateLeft(i, 19) | rotateLeft(i, 22); i
	sbox2 = (i) -> i ^= rotateLeft(i, 7) | rotateLeft(i, 22); i ^= rotateLeft(i, 5) | rotateLeft(i, 19); i
		
	constructor: ->
		@R = new Array(N)
		@CRC = new Array(N)
		@initR = new Array(N)
		
	# Initialize to known state.
	initState: ->
		# Register initialized to Fibonacci numbers.
		@R[0] = 1
		@R[1] = 1
		@R[i] = @R[i-1]+@R[i-2] for i in [2...N]

		# Initialization constant.
		@konst = INITKONST

	# Save the current register state.
	saveState: -> @initR = @R.concat()

	# Initialize to previously saved register state.
	reloadState: -> @R = @initR.concat()
	
	# Cycle the contents of the register and calculate output word in sbuf.
	cycle: ->
		# Nonlinear feedback function.
		t = @R[12] ^ @R[13] ^ @konst
		t = sbox(t) ^ rotateLeft(@R[0], 1)
		
		# Shift register
		@R.shift()
		@R.push(t)
		
		t = sbox2(@R[2] ^ @R[15])
		@R[0] ^= t
		@sbuf = t ^ @R[8] ^ @R[12]

	# Extra nonlinear diffusion of register for key and MAC.
	diffuse: ->
		@cycle() for i in [0...FOLD]
		return
	
	# Accumulate a CRC of input words, later to be fed into MAC.
	# This is actually 32 parallel CRC-16s, using the IBM CRC-16
	# polynomian x^16 + x^15 + x^2 + 1
	crcFunc: (i) ->
		t = @CRC[0] ^ @CRC[2] ^ @CRC[15] ^ i
		@CRC.shift()
		@CRC.push(t)
		return
	
	# Normal MAC word processing: do both stream register and CRC.
	macFunc: (i) ->
		@crcFunc(i)
		@R[KEYP] ^= i
		return
	
	# Initialize 'konst'.
	genKonst: -> @konst = @R[0]
	
	# Load key material into the register.
	addKey: (k) -> @R[KEYP] ^= k
	
	# Common actions for loading key material.
	# Allow non-word-multiple key and nonce material.
	# Note: Also initializes the CRC register as a side effect.
	loadKey: (key) ->
		i = 0
		while (i >> 2) <= ((key.length-1) >> 2)
			# Loop till upper rounded multiple of 4
			# Shift 4 bytes into one word
			@addKey (key[i]||0x00) |
				((key[i+1]||0x00) << 8) |
				((key[i+2]||0x00) << 16) |
				((key[i+3]||0x00) << 24)
			@cycle()
			i += 4
		
		@addKey(key.length)
		@cycle()
		@CRC = @R.concat() # save copy
		@diffuse()
		# Now XOR the copy back -- makes key loading irreversible.
		@R[i] ^= crc for crc, i in @CRC
		return
	
	# Set key 
	key: (key) ->
		@initState()
		@loadKey(key)
		@genKonst() # in case we proceed to stream generation
		@saveState()
		@nbuf = @mbuf = 0
		return
	
	# Set IV 
	nonce: (nonce) ->
		@reloadState()
		@konst = INITKONST
		@loadKey(nonce)
		@genKonst()
		@nbuf = @mbuf = 0
		return
	
	encrypt: (buffer, n) ->
		n = buffer.length if not n?
		
		for i in [0...n]
			if @nbuf == 0
				@cycle()
				@nbuf = 32
				
			@mbuf ^= buffer[i] << (32-@nbuf)
			buffer[i] ^= (@sbuf >> (32-@nbuf)) & 0xff
			
			@nbuf -= 8
			if @nbuf == 0
				@macFunc(@mbuf)
				@mbuf = 0
		return

	# Combined MAC and decryption.
	# Note that plaintext is accumulated for MAC.
	decrypt: (buffer, n) ->
		n = buffer.length if not n?
		
		for i in [0...n]
			if @nbuf == 0
				@cycle()
				@nbuf = 32
			
			buffer[i] ^= (@sbuf >> (32-@nbuf)) & 0xff
			@mbuf ^= buffer[i] << (32-@nbuf)

			@nbuf -= 8
			if @nbuf == 0
				@macFunc(@mbuf)
				@mbuf = 0
		return
		
	# Having accumulated a MAC, finish processing and return it.
	# Note that any unprocessed bytes are treated as if they were
	# encrypted zero bytes, so plaintext (zero) is accumulated.
	finish: (buffer, n) ->
		n = buffer.length if not n?

		# Handle any previously buffered bytes.
		if @nbuf != 0
			# LFSR already cycled.
			@macFunc(@mbuf)
		
		# Perturb the MAC to mark end of input.
		# Note that only the stream register is updated, not the CRC.
		# This is an action that can't be duplicated by passing in plaintext,
		# hence defeating any kind of extension attack.
		
		@cycle()
		@addKey(INITKONST ^ (@nbuf << 3))
		
		@nbuf = @mbuf = 0
		
		# Now add the CRC to the stream register and diffuse it.
		@R[j] ^= crc for crc, j in @CRC
		@diffuse()
		
		# Produce output from the stream buffer.
		for i in [0...n]
			@cycle() if (i % 4) == 0
			buffer[i] = (@sbuf >> ((i%4)*8)) & 0xff
				
		return
