###
SHA1 digest and HMAC algorithms as per RFC 3174 and RFC 2104

Based on http://pajhome.org.uk/crypt/md5/sha1.html

(C) Emiel Mols, 2010. Released under the Simplified BSD License.
    Attribution is very much appreciated.
###
class Sha1

	rotateLeft = (num, n) -> (num << n) | (num >>> (32 - n))

	# Constant for the current iteration
	kt = (t) ->
		if t < 20 then 1518500249
		else if t < 40 then 1859775393
		else if t < 60 then -1894007588
		else -899497514

	# Transform for the current iteration
	ft =  (t, b, c, d) ->
		if t < 20 then (b & c) | ((~b) & d) 
		else if 40 <= t < 60 then (b & c) | (b & d) | (c & d)
		else (b ^ c ^ d)
	
	# SHA1 as described in RFC 3174 <http://www.ietf.org/rfc/rfc3174.txt>
	@digest: (bytes, len) ->
		len = bytes.length * 8 if not len?
	
		bytes = bytes.concat() # copy
		
		# According to the standard, the message must be padded to an even
		# 512 bits. The first padding bit must be a '1'. The last 64 bits
		# represent the length of the original message. 
		
		bytes[len >> 3] |= 0x80 >> (len % 8)
		
		lenOffset = ((((bytes.length + 8 - 1) >> 6) + 1) << 6) - 4
			# (.. + 8) is the length we assume (because of length padding in 64 bits = 8 bytes)
			# (.. - 1) >> 6) + 1 is the 512-bit (64 bytes) block count we need
			# (.. << 6) is the byte size of these blocks
			# (.. - 4) to align at end of buffer - we assume the length fits in one word
			
		bytes[lenOffset] = (len >> 24) & 0xff
		bytes[lenOffset+1] = (len >> 16) & 0xff
		bytes[lenOffset+2] = (len >> 8) & 0xff
		bytes[lenOffset+3] = len & 0xff
		
		#window.sha1 = bytes
		
		w = new Array(80)
		h0 = 0x67452301
		h1 = 0xefcdab89
		h2 = 0x98badcfe
		h3 = 0x10325476
		h4 = 0xc3d2e1f0
	
		for i in [0...bytes.length] by 64
			[a, b, c, d, e] = [h0, h1, h2, h3, h4]
		
			for j in [0...80]
				if j < 16
					w[j] = (bytes[i+(j*4)] << 24) | (bytes[i+(j*4)+1] << 16) | (bytes[i+(j*4)+2] << 8) | bytes[i+(j*4)+3]
				else
					w[j] = rotateLeft(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
					
				t = (rotateLeft(a, 5) + ft(j, b, c, d) + w[j] + kt(j) + e)
				[e, d, c, b, a] = [d, c, rotateLeft(b, 30), a, t]

			#console.debug("i=", i, ": a=", a&0xffffffff, "b=", b&0xffffffff, "c=", c&0xffffffff, "d=", d&0xffffffff, "e=", e&0xffffffff);
		
			[h0, h1, h2, h3, h4] = [h0+a, h1+b, h2+c, h3+d, h4+e]
	
	
		buf = []
		for word in [h0, h1, h2, h3, h4]
			buf.push (word >> 24) & 0xff, (word >> 16) & 0xff, (word >> 8) & 0xff, word & 0xff
		return buf
	
	# HMAC for SHA1 as described in RFC 2104 <http://www.ietf.org/rfc/rfc2104.txt>
	@hmac: (bytes, secret) ->
		if secret.length > 64
			secret = Sha1.digest(secret)
		
		ipaded = new Array(64)
		ipaded[i] = ((secret[i] || 0x00) ^ 0x36) for i in [0...64]

		digestA = Sha1.digest(ipaded.concat(bytes))

		opaded = new Array(64)
		opaded[i] = ((secret[i] || 0x00) ^ 0x5c) for i in [0...64]
		
		return Sha1.digest(opaded.concat(digestA))
