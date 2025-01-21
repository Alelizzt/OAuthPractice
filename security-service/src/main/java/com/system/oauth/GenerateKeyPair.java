package com.system.oauth;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.nio.file.Paths;

public class GenerateKeyPair {
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		var keyPair = keyPairGenerator.generateKeyPair();
		byte[] pub = keyPair.getPublic().getEncoded();
		byte[] pri = keyPair.getPrivate().getEncoded();
		
		// Ruta para guardar las claves en /src/main/resources/certs
        String resourcePath = Paths.get("src", "main", "resources", "certs").toString();

        // Aseguramos que la carpeta "certs" exista
        java.nio.file.Files.createDirectories(Paths.get(resourcePath));

		PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(Paths.get(resourcePath, "public.pem").toString())));
		PemObject pemObject = new PemObject("PUBLIC KEY", pub);
		pemWriter.writeObject(pemObject);
		pemWriter.close();

		PemWriter pemWriter2 = new PemWriter(new OutputStreamWriter(new FileOutputStream(Paths.get(resourcePath, "private.pem").toString())));
		PemObject pemObject2 = new PemObject("PRIVATE KEY", pri);
		pemWriter2.writeObject(pemObject2);
		pemWriter2.close();
		
		System.out.println("Claves generadas y guardadas en: " + resourcePath);
	}
}