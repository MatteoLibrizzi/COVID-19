import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Base64;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;

public class Handler extends Thread {
	private final Socket socket;
	private PrintWriter pw;
	private BufferedReader br;
	private String name;
	private Key key;
	private byte[] iv;

	public Handler(Socket socket) throws IOException {
		this.socket = socket;
		this.pw=new PrintWriter(this.socket.getOutputStream(),true);
		this.br=new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
		this.name = "";
		this.key=null;
		this.iv=null;
	}

	public static String toHex(byte[] input) {
		StringBuilder sb = new StringBuilder();

		for (byte b : input) {
			sb.append(Integer.toHexString(0xFF & b));
		}

		return sb.toString();
	}

	// CRITTOGRAFIA
	public static KeyPair generateAsymmetricKey() throws NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(4096);
		long start = System.currentTimeMillis();
		KeyPair keyPair = generator.generateKeyPair();
		return keyPair;
	}

	public static Key generateSymmetricKey() throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(256);
		SecretKey key = generator.generateKey();
		return key;
	}

	public static byte[] encrypt(Key key, byte[] iv, byte[] plaintext)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
		return cipher.doFinal(plaintext);
	}

	// Decrittazione simmetrica
	public static byte[] decrypt(Key key, byte[] iv, byte[] ciphertext)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		return cipher.doFinal(ciphertext);
	}

	// Generazione vettore di inizializzazione
	public static byte[] generateInitVector() {
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[16];
		random.nextBytes(iv);
		return iv;
	}

	public static byte[] removePrePadding(byte[] B,int length){
		int a=0;
		ByteArrayOutputStream baos=new ByteArrayOutputStream();
		for(int i=B.length-length;i<B.length;i++){
			baos.write(B[i]);
		}
		B=baos.toByteArray();
		return B;
	}

	// Crittazione asimmetrica
	public static byte[] encryptAsym(PublicKey key, byte[] plaintext) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(plaintext);
	}

	// Decrittazione asimmetrica
	public static byte[] decryptAsym(PrivateKey key, byte[] ciphertext) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(key.getAlgorithm() + "/ECB/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(ciphertext);
	}

	public static void sendAsym(byte[] messagge,PublicKey key,PrintWriter pw,Base64.Encoder encoder) throws InterruptedException,
			InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {

		pw.println(messagge.length);
		TimeUnit.MILLISECONDS.sleep(100);
		byte[] encryptedMessaggeB=encryptAsym(key, messagge);
		String encryptedMessaggeS=encoder.withoutPadding().encodeToString(encryptedMessaggeB);

		pw.println(encryptedMessaggeS);
	}

	public static byte[] getAsym(PrivateKey key,BufferedReader br,Base64.Decoder decoder)
			throws NumberFormatException, IOException, InterruptedException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		int length=Integer.valueOf(br.readLine());

		TimeUnit.MILLISECONDS.sleep(10);
		
		String encryptedMessaggeS=br.readLine();
		byte[] encryptedMessaggeB=decoder.decode(encryptedMessaggeS);
		byte[] messaggeB=decryptAsym(key, encryptedMessaggeB);
		messaggeB=removePrePadding(messaggeB, length);
		return messaggeB;
	}

	public static void sendSym(byte[] messagge,Key key,byte[] iv,PrintWriter pw,Base64.Encoder encoder)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {
		byte[] encryptedMessaggeB=encrypt(key, iv, messagge);
		String encryptedMessaggeS=encoder.withoutPadding().encodeToString(encryptedMessaggeB);
		pw.println(encryptedMessaggeS);
	}

	public static byte[] getSym(Key key,byte[] iv,BufferedReader br,Base64.Decoder decoder) throws IOException,
			InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {
		String encryptedMessaggeS=br.readLine();
		byte[] encryptedMessaggeB=decoder.decode(encryptedMessaggeS);
		byte[] messagge = decrypt(key, iv, encryptedMessaggeB);
		return messagge;
	}

	public void handshake(PrintWriter pw, BufferedReader br, Base64.Encoder encoder, Base64.Decoder decoder)
			throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InterruptedException {
		KeyPair myKeypair=generateAsymmetricKey();//GENERATING THE KEY
		String myPubKey=encoder.withoutPadding().encodeToString(myKeypair.getPublic().getEncoded());//tranforming the key in a string through base64, will be decoded by client
		pw.println(myPubKey);//sending
		
		String received=br.readLine();//reads clients public key
		byte[] cPubKeyByte=decoder.decode(received);

        X509EncodedKeySpec cPubKeySpec=new X509EncodedKeySpec(cPubKeyByte);
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
		PublicKey cPubKey=keyFactory.generatePublic(cPubKeySpec);

		String s="Confirm";
		byte[] sB=s.getBytes();
		sendAsym(sB, cPubKey, pw, encoder);
		

		byte[] iv=getAsym(myKeypair.getPrivate(), br, decoder);


		TimeUnit.MILLISECONDS.sleep(10);

		byte[] mySymKeyB=getAsym(myKeypair.getPrivate(), br, decoder);
		
		Key mySymKey=new SecretKeySpec(mySymKeyB,0,mySymKeyB.length, "AES");
		
		this.setKey(mySymKey);
		this.setIv(iv);

	}

	@Override
	public void run(){
		try{
			int i = 0;
			String response;
			
			Base64.Encoder encoder=Base64.getEncoder();//ENCODER OBJECT
			Base64.Decoder decoder=Base64.getDecoder();//DECODER OBJECT

			while(i==0){
				this.handshake(this.pw,this.br,encoder,decoder);
				System.out.println("Handshake over");

				pw.println("1 Login - 2 Sign in%n");
				response=this.br.readLine();
				int r=Integer.parseInt(response);
				if(r==1){
					this.pw.println("%nYou selected the option: LOGIN%nType in your username");
					String username=this.br.readLine();
					if(!username.equals("")){
						this.setName(username);
						this.pw.println("%nNow Type in your password");
						String password=this.br.readLine();
						//FUNCTION TO CONFRONT PASSWORD WITH DATABASE return boolean value
					}else{
						pw.println("%nSomething went wrong!");
					}

				}else{
					if(r==2){
						//SIGN IN
					}else{
						//SOMETHING WENT WRONG
					}
				}
				
			}
			while(true){
				break;
			}
			//ELABORATE DATA
		}catch(IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public Key getKey() {
		return key;
	}

	public void setKey(Key key) {
		this.key = key;
	}

	public byte[] getIv() {
		return iv;
	}

	public void setIv(byte[] iv) {
		this.iv = iv;
	}
}