package cai2;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Formatter;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class ConsultaMAC { 

	public static void main(String[] args) {

		generaClave("531456789 487654 200", "47f14fd757de9a020bdb8635aeecf4a4103d3649");

	}

	public static String hexToString(String hexa) {
	    return Integer.toHexString(Integer.parseInt(hexa));
	}

	private static final String HMAC_SHA1 = "HmacSHA1";

	// Calcula hmac
	public static String calculaHMAC(String data, byte[] key)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException
	{
		SecretKeySpec secretKeySpec = new SecretKeySpec(key, HMAC_SHA1);
		Mac mac = Mac.getInstance(HMAC_SHA1);
		mac.init(secretKeySpec);
		return byteToHexString(mac.doFinal(data.getBytes()));
	}

	private static String byteToHexString(byte[] bytes) {
		Formatter formatter = new Formatter();
		for (byte b : bytes) {
			formatter.format("%02x", b);
		}
		return formatter.toString();
	}
	
	public static String generaClave(String mensaje_enunciado, String MAC_enunciado) {
		for(int i1=36; i1<=37; i1++) {
			for(int i2=0; i2<=255; i2++) {
				for(int i3=0; i3<=255; i3++) {
					for(int i4=0; i4<=255; i4++) {
						
						byte[] byte_total = new byte[4];
						
						byte_total[0] = (byte)i1;
						byte_total[1] = (byte)i2;
						byte_total[2] = (byte)i3;
						byte_total[3] = (byte)i4;
					
						//System.out.println("---->" + byte_total);
						
						try {
							if(calculaHMAC(mensaje_enunciado, byte_total).equals(MAC_enunciado)) {
								System.out.println("La clave descifrada en hexadecimal es: " + byteToHexString(byte_total));
	
								return byteToHexString(byte_total);
							}
						} catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
							System.out.println("Error al calcular la MAC.");
						}
					}
				}
			}
		}
		return null;
	}

}
