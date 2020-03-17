import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.util.Arrays;
import java.util.Base64;
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

//NEED TO IMPLEMENT THE DOCUMENT SENDING PART AND NEED TO CHANGE THE INPUT OF THE SENDCRYPTED FUNCTION TO BYTE AS I AM GONNA WANT TO SEND FILES LATER
public class Handler extends Thread {
	private final Socket socket;
	private PrintWriter pw;
	private BufferedReader br;
	public String name;
	private String db;
	private Key key;
	private byte[] iv;
	private boolean auth;
	private Base64.Encoder encoder;
	private Base64.Decoder decoder;
	private int specialization;

	public Handler(Socket socket) throws IOException {
		this.socket = socket;
		this.pw = new PrintWriter(this.socket.getOutputStream(), true);
		this.br = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
		this.name = "";
		this.db = "./db.txt";
		this.encoder=Base64.getEncoder();
		this.decoder=Base64.getDecoder();
		this.key = null;
		this.iv = null;
		this.auth=false;
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

	public static byte[] removePrePadding(byte[] B, int length) {//this function is used to remove the padding in the asymmetric communication as the minimum length of a packet might be more than the length of the messagge
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		for (int i = B.length - length; i < B.length; i++) {
			baos.write(B[i]);
		}
		B = baos.toByteArray();
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

	public static void sendAsym(byte[] messagge, PublicKey key, PrintWriter pw, Base64.Encoder encoder)
			throws InterruptedException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {//sends the length of the messagge uncrypted and the messagge crypted afterwards so the receiver knows what part of the messagge is the padding

		pw.println(messagge.length);
		TimeUnit.MILLISECONDS.sleep(100);
		byte[] encryptedMessaggeB = encryptAsym(key, messagge);
		String encryptedMessaggeS = encoder.withoutPadding().encodeToString(encryptedMessaggeB);

		pw.println(encryptedMessaggeS);
	}

	public static byte[] getAsym(PrivateKey key, BufferedReader br, Base64.Decoder decoder)
			throws NumberFormatException, IOException, InterruptedException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {//receives the length of the message and afterwards the encrypted messagge
		int length = Integer.valueOf(br.readLine());

		TimeUnit.MILLISECONDS.sleep(10);

		String encryptedMessaggeS = br.readLine();
		byte[] encryptedMessaggeB = decoder.decode(encryptedMessaggeS);
		byte[] messaggeB = decryptAsym(key, encryptedMessaggeB);
		messaggeB = removePrePadding(messaggeB, length);
		return messaggeB;
	}

	public static void sendSym(byte[] messagge, Key key, byte[] iv, PrintWriter pw, Base64.Encoder encoder)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {//takes in the bytes of the messagge, encrypts it and sends it
		byte[] encryptedMessaggeB = encrypt(key, iv, messagge);
		String encryptedMessaggeS = encoder.withoutPadding().encodeToString(encryptedMessaggeB);
		pw.println(encryptedMessaggeS);
	}

	public static byte[] getSym(Key key, byte[] iv, BufferedReader br, Base64.Decoder decoder)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {//receives the encrypted messagge on br and returns it as bytes
		String encryptedMessaggeS = br.readLine();
		byte[] encryptedMessaggeB = decoder.decode(encryptedMessaggeS);
		byte[] messagge = decrypt(key, iv, encryptedMessaggeB);
		return messagge;
	}

	public void handshake(PrintWriter pw, BufferedReader br, Base64.Encoder encoder, Base64.Decoder decoder)
			throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InterruptedException {//exchange of the public keys and of the symmetric key MORE COMMENTS ON results.java
		KeyPair myKeypair = generateAsymmetricKey();// GENERATING THE KEY
		String myPubKey = encoder.withoutPadding().encodeToString(myKeypair.getPublic().getEncoded());// tranforming the
																										// key in a
																										// string
																										// through
																										// base64, will
																										// be decoded by
																										// client
		pw.println(myPubKey);// sending

		String received = br.readLine();// reads clients public key
		byte[] cPubKeyByte = decoder.decode(received);

		X509EncodedKeySpec cPubKeySpec = new X509EncodedKeySpec(cPubKeyByte);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey cPubKey = keyFactory.generatePublic(cPubKeySpec);

		String s = "Confirm";
		byte[] sB = s.getBytes();
		sendAsym(sB, cPubKey, pw, encoder);

		byte[] iv = getAsym(myKeypair.getPrivate(), br, decoder);

		TimeUnit.MILLISECONDS.sleep(10);

		byte[] mySymKeyB = getAsym(myKeypair.getPrivate(), br, decoder);

		Key mySymKey = new SecretKeySpec(mySymKeyB, 0, mySymKeyB.length, "AES");

		this.setKey(mySymKey);
		this.setIv(iv);

	}

	public static byte[] saltGen() {// GENERATES SALT
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[2];
		random.nextBytes(salt);
		return salt;
	}

	public static byte[] hash(byte[] input, String algorithm) throws NoSuchAlgorithmException {// takes in a byte array
																								// and an hash
																								// algorithm. gives out
																								// the hash
		MessageDigest md = MessageDigest.getInstance(algorithm);

		byte[] output = md.digest(input);
		return output;
	}

	public void setSpec(int spec){
		this.specialization=spec;
	}

	public int getSpec(){
		return this.specialization;
	}

	public boolean passwordChecker(String plainPW) throws IOException, NoSuchAlgorithmException {
		// this needs to check if hashed password+hash is equal to the saved one
		// together with the given username
		FileReader reader = new FileReader(this.db);
		BufferedReader br = new BufferedReader(reader);
		String s, hash, password;
		String[] ss;
		byte[] passwordB, hashB;
		boolean found = false;
		while (br.readLine() != null) {
			s = br.readLine();
			ss = s.split(":", 4);
			if (ss[0].equals(this.name)) {
				password = plainPW + ss[2];
				passwordB = password.getBytes("UTF-8");
				hashB = hash(passwordB, "SHA-256");
				hash = toHex(hashB);
				if (ss[1].equals(hash)) {
					found = true;
				}
			}
		}
		br.close();
		return found;
	}

	public void passwordWriter(String plainPW) throws IOException, NoSuchAlgorithmException {//this writes on a document the username, password and salt, the last field is an integer representing the specialization
		FileWriter writer = new FileWriter(this.db, true);
		byte[] saltB = saltGen();
		String salt = toHex(saltB);

		String pwNsa = plainPW + salt;
		byte[] hash = hash(pwNsa.getBytes("UTF-8"), "SHA-256");
		String hashedPW = toHex(hash);
		writer.write("\n" + this.name + ":" + hashedPW + ":" + salt + ":" + this.getSpec() + "\n");
		writer.close();
	}

	public void sendCrypted(byte[] msgB) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {//send a crypted messagge using symmetric crypto
		
		msgB=encrypt(this.key, this.iv, msgB);
		String msgS=this.encoder.encodeToString(msgB);
		this.pw.println(msgS);
	}

	public byte[] getCrypted() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {//gets a crypted messagge using symmetric crypto
		String msgS=this.br.readLine();
		byte[] msgB=this.decoder.decode(msgS);
		msgB=decrypt(this.key, this.iv, msgB);
		return msgB;
	}

	public byte[] file2Bytes(String path) throws IOException {//transform a file into bytes so it can be sent to the client 
		File f=new File(path);
		byte[] fileB=new byte[(int)f.length()];
		FileInputStream fis=new FileInputStream(f);
		fis.read(fileB);
		fis.close();
		return fileB;
	}

	public void bytes2File(byte[] fileB) throws IOException {//transform byte[] into a file and saves it into a folder
		File file=new File("./SentFile/"+this.name);
		FileOutputStream os=new FileOutputStream(file);
		os.write(fileB);
		os.close();
	}

	public void sendFile() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException,
			InterruptedException {//gets crypted file checking with hash for possible modifications
		TimeUnit.MILLISECONDS.sleep(10);

		byte[] fileB=this.getCrypted();//3

		bytes2File(fileB);
		TimeUnit.MILLISECONDS.sleep(10);//4

		byte[] hc=this.getCrypted();//5

		byte[] hs=hash(fileB,"SHA-256");//CODE DOESNT GET TO THE IF NEED TO UNDERSTAND WHY AND FIX
		if(!Arrays.equals(hc, hs)){
			this.sendCrypted("\n!!!CAREFUL!!!\nThis didn't work, try again".getBytes());//6
		}else{
			this.sendCrypted("\n".getBytes());//6
		}
	}

	public void getFile() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException,
			InterruptedException {//sends file to client checking for possible modifications WORKS ON THIS SIDE DOESN'T ON THE OTHER
		String user=new String(this.getCrypted());//1 client sends name of the researcher
		
		byte[] fileB=file2Bytes("./SentFile/"+user);//gets the bytes of the file
		TimeUnit.MILLISECONDS.sleep(1);
		this.sendCrypted(fileB);//2 send bytes (this part has been tested)

		TimeUnit.MILLISECONDS.sleep(100);

		byte[] hc=this.getCrypted();//gets hash
		byte[] hs=hash(fileB, "SHA-256");
		
		if(!Arrays.equals(hs,hc)){//checks if the hashes are the same end sends an error if not
			this.sendCrypted("\n!!!CAREFUL!!!\nThis didn't work, try again".getBytes());
		}else{
			this.sendCrypted("\nSuccessful, you can find the file under 'GetFile'".getBytes());
		}
	}

	@Override
	public void run(){
		try{
			String response;
			
			Base64.Encoder encoder=Base64.getEncoder();//ENCODER OBJECT
			Base64.Decoder decoder=Base64.getDecoder();//DECODER OBJECT
			this.handshake(this.pw,this.br,encoder,decoder);

			while(!this.auth){
				this.sendCrypted("1 Login - 2 Sign in\n".getBytes());
				response=new String(this.getCrypted());
				int r=Integer.parseInt(response);
				if(r==1){
					this.sendCrypted("\nYou selected the option: LOGIN\nType in your username".getBytes());
					String username=new String(this.getCrypted());//client sends username which is saved as an attribute
					if(!username.isEmpty()){
						this.name=username;
						this.sendCrypted("\nNow type in your password".getBytes());//client sends password, in retrospect, password should be hashed by the client not by the server to add one level of security
						String password=new String(this.getCrypted());
						if(this.passwordChecker(password)){
							this.auth=true;//if the password is correct this attribute is changed and the client is granted access to the documents
						}else{
							this.sendCrypted("\nSomething went wrong!".getBytes());
						}
					}else{
						this.sendCrypted("\nSomething went wrong!".getBytes());//if username is empty or password is wrong client receives an error and gets sent back to the LOGIN/SIGNIN MENU
					}
				}else{
					if(r==2){
						String password1="";
						String password2="";
						int spec=3;
						do{
							this.sendCrypted("\nYou selected the option: SIGN IN\nType in your username:".getBytes());
							String username=new String(this.getCrypted());//client sends username which gets saved as an attribute
							if(!username.isEmpty()){
								this.name=username;

								this.sendCrypted("\nNow type in your password (Minimum 8 char):".getBytes());
								password1=new String(this.getCrypted());

								this.sendCrypted("\nNow please retype your password:".getBytes());
								password2=new String(this.getCrypted());//client sends the password twice

								this.sendCrypted("\nNow please send your specialization\n0 for Chemistry\n1 for Genetics\n2 for Statician".getBytes());
								spec=Integer.valueOf(new String(this.getCrypted()));//client sends specialization as an integer
							
								if(!password1.equals(password2)||(password1.length()<8)||spec<0||spec>2){//if the passwords are minimum 8 char and are the same and the spec makes sense client moves on else gets an error messagge
									this.sendCrypted("Try again".getBytes());
								}
							}
						}while((!password1.equals(password2))||(password1.length()<8)||spec<0||spec>2);
						this.setSpec(spec);
						passwordWriter(password1);
						this.sendCrypted("Registered Successfully\nYou can now Login".getBytes());//spec is set as an attribute and the client is registered via passwordWriter(...) function
					}else{
						this.sendCrypted("Something went wrong".getBytes());//if r is neither 1 or 2 client receives an error messagge
					}
				}
				
			}
			boolean loop=true;
			
			while(loop){//this loop is infinite unless client types quit in which case socket gets closed and thread interrupted
				this.sendCrypted("\nType in \n'SENDFILE' if you wish to send a file\nor\n'GETFILE' to request a file".getBytes());
				String rec=new String(this.getCrypted());//1 client sends his choice

				if(rec.equals("SENDFILE")){
					this.sendFile();
				}else{
					if(rec.equals("GETFILE")){
					this.getFile();
					}else{
						if(rec.equals("QUIT")){
							loop=false;
						}
					}
				}
			}
			this.socket.close();
			this.interrupt();
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
		} catch (InvalidAlgorithmParameterException e) {
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