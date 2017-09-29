package keyPair;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

class Descriprografar {

	public static void main(String[] args) {
		
		File publickeyfile = new File("chave-publica"); 
		File signaturefile = new File("texto-cifrado");
		File datafile = new File("texto-puro");

		/* Verify a DSA signature */

			try {

				/* import encoded public key */

				FileInputStream keyfis = new FileInputStream(publickeyfile);
				byte[] encKey = new byte[keyfis.available()];
				keyfis.read(encKey);

				keyfis.close();

				X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);

				KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
				PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

				/* input the signature bytes */
				FileInputStream sigfis = new FileInputStream(signaturefile);
				byte[] sigToVerify = new byte[sigfis.available()];
				sigfis.read(sigToVerify);

				sigfis.close();

				/* create a Signature object and initialize it with the public key */
				Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
				sig.initVerify(pubKey);

				/* Update and verify the data */

				FileInputStream datafis = new FileInputStream(datafile);
				BufferedInputStream bufin = new BufferedInputStream(datafis);

				byte[] buffer = new byte[1024];
				int len;
				while (bufin.available() != 0) {
					len = bufin.read(buffer);
					sig.update(buffer, 0, len);
				}
				;

				bufin.close();

				boolean verifies = sig.verify(sigToVerify);

				System.out.println("signature verifies: " + verifies);

			} catch (Exception e) {
				System.err.println("Caught exception " + e.toString());
			}
		;

	}

}