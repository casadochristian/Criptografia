package hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class ResumenHash {
	// Generamos un hash a partir de una contraseña que nos da el usuario.
		public String generarHashUser(String passwordUser) throws NoSuchAlgorithmException {
			byte[] password = passwordUser.getBytes();
			MessageDigest mdUser = MessageDigest.getInstance("SHA-512");
			mdUser.update(password);

			byte[] passwordHasheada = mdUser.digest();

			String passwordUserHashBase64 = Base64.getEncoder().encodeToString(passwordHasheada);
			return passwordUserHashBase64;
		}

}
