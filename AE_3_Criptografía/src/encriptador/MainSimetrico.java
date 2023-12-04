package encriptador;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import hash.ResumenHash;
import usuario.Usuario;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

public class MainSimetrico {	

	public static void main(String[] args) throws NoSuchAlgorithmException {
		//Creamos los objetos Usuario
		Usuario user1 = new Usuario("Tony", "admin");
		Usuario user2 = new Usuario("Steve", "Hail Hydra");
		Usuario user3 = new Usuario("Peter", "maryjane");
		
		//convertimos las contraseñas en bytes
		byte[] password1 = user1.getPassword().getBytes();
		byte[] password2 = user2.getPassword().getBytes();
		byte[] password3 = user3.getPassword().getBytes();	
		
		// Creamos un objeto MessageDigest a través del método estático
		// getInstance() al que se le pasa el tipo de algoritmo que vamos a
		// utilizar.
		MessageDigest md1 = MessageDigest.getInstance("SHA-512");
		MessageDigest md2 = MessageDigest.getInstance("SHA-512");
		MessageDigest md3 = MessageDigest.getInstance("SHA-512");		

		//Actualizamos las contraseñas de los usuarios y lo preparamos para convertirlo a hash		
		md1.update(password1);
		md2.update(password2);
		md3.update(password3);
		
		// Ahora ejecutamos el método "digest()" para convertirlo a hash, pero esta en binario.
		byte[] password1Hasheada = md1.digest();	
		byte[] password2Hasheada = md2.digest();
		byte[] password3Hasheada = md3.digest();		
		
		// Lo pasamos a codificación BASE 64 para que sea mas legible.
		// Puede ser util si queremos guardar la información o enviar la información.
		String password1_HashBase64 = Base64.getEncoder().encodeToString(password1Hasheada);
		String password2_HashBase64 = Base64.getEncoder().encodeToString(password2Hasheada);
		String password3_HashBase64 = Base64.getEncoder().encodeToString(password3Hasheada);

		// Creamos una lista donde almacenar los usuarios. 
		List<Usuario> listaUsuarios = new ArrayList<>();
		
		//cambiamos las contraseñas originales por las contraseñas hasheadas
		user1.setPassword(password1_HashBase64);
		user2.setPassword(password2_HashBase64);
		user3.setPassword(password3_HashBase64);

		// Guardamos los usuarios en una lista para poder acceder a ellos.
		listaUsuarios.add(user1);
		listaUsuarios.add(user2);
		listaUsuarios.add(user3);		

		// Con esta variable controlamos las veces que el usuario puede poner los datos.
		int intentos = 3;

		// Pedimos los datos al usuario para que pueda acceder.
		do {
			Scanner sc = new Scanner(System.in);

			System.out.println("NOMBRE: ");
			String nombreUser = sc.nextLine();
			
		
			System.out.println("PASSWORD: ");
			String passwordUser = sc.nextLine();
			ResumenHash rh = new ResumenHash();
			
			// Por cada usuario que haya en la lista 
			// comparamos que si tanto el nombre como la contraseña hasheada es igual a lo que el usuario nos da por scanner
			// entonces mostramos el menu.
			// Si no es asi tiene 3 oportunidas en total y al final el programa termina solo.
			for (Usuario u : listaUsuarios) {
				if (nombreUser.equals(u.getNombre()) && u.getPassword().equals(rh.generarHashUser(passwordUser))){		
		
		System.out.println("---- BIENVENIDO AL ENCRIPTADOR DE FRASES ----");
		
		try {
			//Obtenemos el generador de claves simetricas
			KeyGenerator generador = KeyGenerator.getInstance("AES");
			
			//Generamos la clave simetrica
			SecretKey claveSimetrica = generador.generateKey();
			
			//Creamos el objeto que nos permite encriptar la frase
			Cipher cifrador = Cipher.getInstance("AES");
			
			//Iniciamos el menú del que no saldremos hasta que no nos pulsen la opcion 3
			
			String opcion;
			String fraseUsuario, fraseUsuarioCifrada, fraseUsuarioDescifrada;
			byte[] bytesFraseUsuario;
			byte[] bytesFraseUsuarioCifrada = null;
			byte[] bytesFraseUsuarioDescifrada;
			
			do {
				//System.out.println("Encriptador de frases. Elige una opción");
				System.out.println("1- Encriptar frase");
				System.out.println("2- Desencriptar frase");
				System.out.println("3- Salir");
				
				opcion = sc.nextLine();
				
				switch(opcion) {
				case "1":
					System.out.println("Introduce la frase que quieres encriptar");
					fraseUsuario = sc.nextLine();
					//iniciamos el cifrador para que trabaje con la clave simétrica antes creada
					cifrador.init(Cipher.ENCRYPT_MODE, claveSimetrica);
					//convertimos la frase introducida por el usuario a bytes y lo almacenamos en una variable
					bytesFraseUsuario = fraseUsuario.getBytes();
					//Ciframos el mensaje original
					bytesFraseUsuarioCifrada = cifrador.doFinal(bytesFraseUsuario);
					fraseUsuarioCifrada = new String(bytesFraseUsuarioCifrada);
					System.out.println("Su frase ha sido cifrada correctamente : " + fraseUsuarioCifrada);
					break;
					
				case "2":
					System.out.println("Desencriptando tu frase...");
					//Configuramos el cifrador para ponerlo en modo desencriptar
					cifrador.init(Cipher.DECRYPT_MODE, claveSimetrica);
					//usamos nuestra variable de bytes para almacenar la frase descifrada en bytes
					bytesFraseUsuarioDescifrada = cifrador.doFinal(bytesFraseUsuarioCifrada);
					//convertimos a string el array de bytes
					fraseUsuarioDescifrada = new String (bytesFraseUsuarioDescifrada);
					//Imprimimos por consola la frase descifrada
					System.out.println("La frase descifrada es : "+ fraseUsuarioDescifrada);
					break;
				case "3":
					System.out.println("Saliendo del programa");

					System.exit(0);
					break;
					
				default:
					System.out.println("----------  OPCION NO VÁLIDA  ----------");
					System.out.println("Por favor, introduce una de las siguientes opciones");
					break;					
				}
				
						}while(opcion != "3");
							sc.close();
							return;			
			
						//capturamos las excepciones con GeneralSecurityException
						} catch (GeneralSecurityException gse) {
							System.out.println("Algo ha fallado.." + gse.getMessage());
							gse.printStackTrace();
					}
				}
			}
			System.out.println("Usuario no encontrado");
			intentos--;
			System.out.println("Te quedan " + intentos + " intentos");

			if (intentos == 0) {
				System.out.println("Fin del programa. Adios");
				sc.close();
				return;
				
			}

		} while (intentos > 0);
	}
private void cargarUsuarios() {
	
}
}
