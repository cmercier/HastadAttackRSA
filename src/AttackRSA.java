import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;

public class AttackRSA {

	public static void main(String[] args) {
		String filename = "input.txt";
		BigInteger[] N = new BigInteger[3];
		BigInteger[] e = new BigInteger[3];
		BigInteger[] c = new BigInteger[3];
		try {
			BufferedReader br = new BufferedReader(new FileReader(filename));
			for (int i = 0; i < 3; i++) {
				String line = br.readLine();
				String[] elem = line.split(",");
				N[i] = new BigInteger(elem[0].split("=")[1]);
				e[i] = new BigInteger(elem[1].split("=")[1]);
				c[i] = new BigInteger(elem[2].split("=")[1]);
			}
			br.close();
		} catch (Exception err) {
			System.err.println("Error handling file.");
			err.printStackTrace();
		}
		BigInteger m = recoverMessage(N, e, c);
		System.out.println("Recovered message: " + m);
		System.out.println("Decoded text: " + decodeMessage(m));
	}

	public static String decodeMessage(BigInteger m) {
		return new String(m.toByteArray());
	}

	/**
	 * Tries to recover the message based on the three intercepted cipher texts.
	 * In each array the same index refers to same receiver. I.e. receiver 0 has
	 * modulus N[0], public key d[0] and received message c[0], etc.
	 * 
	 * @param N
	 *            The modulus of each receiver.
	 * @param e
	 *            The public key of each receiver (should all be 3).
	 * @param c
	 *            The cipher text received by each receiver.
	 * @return The same message that was sent to each receiver.
	 */
	private static BigInteger recoverMessage(BigInteger[] N, BigInteger[] e,
			BigInteger[] c) {
	    
	    //M is the product of the N
	    BigInteger M = BigInteger.ONE;
	    for(int i = 0; i < N.length; i++)
	      M = M.multiply(N[i]);
	    
	    BigInteger[] multInv = new BigInteger[c.length];
	    
	    /*
	     * this loop applies the Euclidean algorithm to each pair of M/N[i] and N[i]
	     * since it is assumed that the various N[i] are pairwise coprime,
	     * the end result of applying the Euclidean algorithm will be
	     * gcd(M/N[i], N[i]) = 1 = a(M/N[i]) + b(N[i]), or that a(M/N[i]) is
	     * equivalent to 1 mod (N[i]). This a is then the multiplicative
	     * inverse of (M/N[i]) mod N[i], which is what we are looking to multiply
	     * by our constraint c[i] as per the Chinese Remainder Theorem
	     * euclidean(M/N[i], N[i])[0] returns the coefficient a
	     * in the equation a(M/N[i]) + b(N[i]) = 1
	     */
	    for(int i = 0; i < multInv.length; i++)
	      multInv[i] = euclidean(M.divide(N[i]), N[i])[0];
	    
	    BigInteger x = BigInteger.ZERO;
	    
	    //x = the sum over all given i of (M/N[i])(c[i])(multInv[i])
	    for(int i = 0; i < N.length; i++)
	      x = x.add((M.divide(N[i])).multiply(c[i].multiply(multInv[i])));
	    
	    x = leastPosEquiv(x, M); 
		
		return CubeRoot.cbrt(x);
		
		//return BigInteger.ZERO;
	}
	
	  /*
	   * performs the Euclidean algorithm on a and b to find a pair of coefficients
	   * (stored in the output array) that correspond to x and y in the equation
	   * ax + by = gcd(a,b)
	   * constraint: a > b
	   */
	  public static BigInteger[] euclidean(BigInteger a, BigInteger b)
	  {
	    if(b.compareTo(a) > 0)
	    {
	      //reverse the order of inputs, run through this method, then reverse outputs
	      BigInteger[] coeffs = euclidean(b, a);
	      BigInteger[] output = {coeffs[1], coeffs[0]};
	      return output;
	    }

	    BigInteger q = a.divide(b);
	    //a = q*b + r --> r = a - q*b
	    BigInteger r = a.subtract(q.multiply(b));
	    
	    //when there is no remainder, we have reached the gcd and are done
	    if(r == BigInteger.ZERO)
	    {
	      BigInteger[] output = {BigInteger.ZERO, BigInteger.ONE};
	      return output;
	    }
	    
	    //call the next iteration down (b = qr + r_2)
	    BigInteger[] next = euclidean(b, r);
	    
	    BigInteger[] output = {next[1], next[0].subtract(q.multiply(next[1]))};
	    return output;
	  }
	  
	  //finds the least positive integer equivalent to a mod m
	  public static BigInteger leastPosEquiv(BigInteger a, BigInteger m)
	  {
	    //a equivalent to b mod -m <==> a equivalent to b mod m
	    if(m.compareTo(BigInteger.ZERO) < 0)
	      return leastPosEquiv(a, new BigInteger("-1").multiply(m));
	    //if 0 <= a < m, then a is the least positive integer equivalent to a mod m
	    if(a.compareTo(BigInteger.ZERO) >= 0 && a.compareTo(m) < 0)
	      return a;
	    
	    //for negative a, find the least negative integer equivalent to a mod m
	    //then add m
	    if(a.compareTo(BigInteger.ZERO) < 0)
	      return new BigInteger("-1").multiply(leastPosEquiv(new BigInteger("-1").multiply(a), m)).add(m);
	    
	    //the only case left is that of a,m > 0 and a >= m
	    
	    //take the remainder according to the Division algorithm
	    BigInteger q = a.divide(m);
	    
	    /*
	     * a = qm + r, with 0 <= r < m
	     * r = a - qm is equivalent to a mod m
	     * and is the least such non-negative number (since r < m)
	     */
	    return a.subtract(q.multiply(m));
	  }

}
