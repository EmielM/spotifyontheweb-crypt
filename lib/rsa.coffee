###
Simple RSA key generation

Completely untested.

(C) Emiel Mols, 2010. Released under the Simplified BSD License.
    Attribution is very much appreciated.
###
class RSAKeyPair

	# private key: (d, n)
	# public key: (e, n)
	
	# p, q: primes
	
	e: new BigInteger('10001', 16) # 0x10001 as public exponent (can also use: 0xf3)

	generate: (@size) ->
		one = BigInteger.ONE
		qs = @size >> 1
		while true
			while true
				@p = new BigInteger(@size-qs, 1, rng)
				break if @p.subtract(one).gcd(@e).compareTo(one) == 0 && @p.isProbablePrime(10)
			
			while true
				@q = new BigInteger(qs, 1, rng)
				break if @q.subtract(one).gcd(@e).compareTo(one) == 0 && @q.isProbablePrime(10)
				
			[@p, @q] = [@q, @p] if @p.compareTo(@q) <= 0
			
			p1 = @p.subtract(one)
			q1 = @q.subtract(one)
			phi = p1.multiply(q1)
			if phi.gcd(@e).compareTo(one) == 0
				@n = @p.multiply(@q)
				@d = @e.modInverse(phi)
				#@dmp1 = @d.mod(p1)
				#@dmq1 = @d.mod(q1)
				#@coeff = @q.modInverse(@p);
				return this
				
	getPublic: -> @n.toByteArray() #fixme
	
	getPrivate: -> @d.toByteArray() #fixme
