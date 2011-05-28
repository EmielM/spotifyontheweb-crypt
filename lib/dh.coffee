###
Diffie Hellman key generation

(C) Emiel Mols, 2010. Released under the Simplified BSD License.
    Attribution is very much appreciated.
###
class DHKeyPair
	
	g: new BigInteger('2')
	p: new BigInteger('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74
020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437
4fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff', 16)

	# x: private key
	# y: public key
	
	# size: key length in bits (both private and public)
	
	generate: (@size) ->
		bytes = new Array(@size/8)
		rng.nextBytes(bytes)
		bytes[0] &= ~0x80
		@x = new BigInteger(bytes)
		@generatePublic()
		return this
		
	generatePublic: ->
		@y = @g.modPow(@x, @p)
		return this
	
	getPublic: -> @y.toByteArray()
	
	getPrivate: -> @x.toByteArray()
	
	computeShared: (pk) ->
		# todo: make sure pk gets interpreted without sign
		modPow = new BigInteger(pk).modPow(@x, @p)
		return modPow.toByteArray(Math.ceil(@size / 8))
