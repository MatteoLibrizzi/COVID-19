import java.net.Socket;
import java.net.UnknownHostException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Time;
import java.util.Base64;
import java.util.concurrent.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.io.RandomAccessFile;

//need to generate and send symmetric key in handshake()
public class Results extends Thread{
	public static final int port=1024;
	private Socket socket;
	private String name;
	private PrintWriter pw;
	private BufferedReader br;
	private Key key=null;
	private byte[] iv=null;
	private Base64.Encoder encoder;
	private Base64.Decoder decoder;
	private Receiver receiver;

	public Results() throws UnknownHostException, IOException {
		this.socket=new Socket("localhost",port);
		this.pw=new PrintWriter(socket.getOutputStream(),true);
		this.br=new BufferedReader(new InputStreamReader(socket.getInputStream()));
		this.encoder=Base64.getEncoder();
		this.decoder=Base64.getDecoder();
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

	public static byte[] generateInitVector() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }

    public static byte[] fileToByte(String filePath)throws FileNotFoundException,IOException{//takes in file gives out bytes
        File file=new File(filePath);
        byte[] fileB=new byte[(int)file.length()];
        FileInputStream fInStream=new FileInputStream(file);
        fInStream.read(fileB);
        fInStream.close();
        return fileB;

    }

    public static byte[] encrypt(Key key, byte[] iv, byte[] plaintext) throws
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(plaintext);
    }

    // Decrittazione simmetrica
    public static byte[] decrypt(Key key, byte[] iv, byte[] ciphertext) throws
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    public static byte[] encryptAsym(PublicKey key, byte[] plaintext) throws
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    // Decrittazione asimmetrica
    public static byte[] decryptAsym(PrivateKey key, byte[] ciphertext) throws
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(key.getAlgorithm() + "/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    public static void send(byte[] payload,PrintWriter pw) throws UnknownHostException,IOException{
        String sPayLoad=toHex(payload);
        pw.println(sPayLoad);
    }

	public static byte[] removePrePadding(byte[] B,int length){//this function is used to remove the padding in the asymmetric communication as the minimum length of a packet might be more than the length of the messagge
		ByteArrayOutputStream baos=new ByteArrayOutputStream();
		for(int i=B.length-length;i<B.length;i++){
			baos.write(B[i]);
		}
		B=baos.toByteArray();
		return B;
	}

	public static void sendAsym(byte[] messagge,PublicKey key,PrintWriter pw,Base64.Encoder encoder) throws InterruptedException,
			InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {//sends the length of the messagge uncrypted and the messagge crypted afterwards so the receiver knows what part of the messagge is the padding


		pw.println(messagge.length);
		TimeUnit.MILLISECONDS.sleep(100);
		byte[] encryptedMessaggeB=encryptAsym(key, messagge);
		String encryptedMessaggeS=encoder.withoutPadding().encodeToString(encryptedMessaggeB);

		pw.println(encryptedMessaggeS);
	}

	public static byte[] getAsym(PrivateKey key,BufferedReader br,Base64.Decoder decoder)
			throws NumberFormatException, IOException, InterruptedException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {//receives the length of the message and afterwards the encrypted messagge

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
			BadPaddingException, InvalidAlgorithmParameterException {//takes in the bytes of the messagge, encrypts it and sends it

		byte[] encryptedMessaggeB=encrypt(key, iv, messagge);
		String encryptedMessaggeS=encoder.withoutPadding().encodeToString(encryptedMessaggeB);
		pw.println(encryptedMessaggeS);
	}

	public static byte[] getSym(Key key,byte[] iv,BufferedReader br,Base64.Decoder decoder) throws IOException,
			InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {//receives the encrypted messagge on br and returns it as bytes

		String encryptedMessaggeS=br.readLine();
		byte[] encryptedMessaggeB=decoder.decode(encryptedMessaggeS);
		byte[] messagge = decrypt(key, iv, encryptedMessaggeB);
		return messagge;
	}

    public void handshake(PrintWriter pw,BufferedReader br,Base64.Encoder encoder,Base64.Decoder decoder) throws IOException,NoSuchAlgorithmException,InvalidKeySpecException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
			InterruptedException {//exchange of the public keys and of the symmetric key

        
        String received=br.readLine();
        byte[] sPubKeyByte=decoder.decode(received);//bytes of the server public key

        X509EncodedKeySpec sPubKeySpec=new X509EncodedKeySpec(sPubKeyByte);
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        PublicKey sPubKey=keyFactory.generatePublic(sPubKeySpec);//using key factory generates a public key instance

        KeyPair myKeypair=generateAsymmetricKey();//client generates assymetric key

        String myPubKey=encoder.withoutPadding().encodeToString(myKeypair.getPublic().getEncoded());
        pw.println(myPubKey);//pub key is encrypted with server's pub key and sent
		
		byte[] confirmByte=getAsym(myKeypair.getPrivate(), br, decoder);
		String confirmString=new String(confirmByte);
		
		if(confirmString.equals("Confirm")){//this confirm could be implemented using hashes
			Key mySymKey=generateSymmetricKey();//client generates symmetric key (not sure if server side is supposed to do that)
			byte[] iv=generateInitVector();

			sendAsym(iv, sPubKey, pw, encoder);//then sends iv
			TimeUnit.MILLISECONDS.sleep(100);

			byte[] simKey=mySymKey.getEncoded();
			sendAsym(simKey, sPubKey, pw, encoder);//and the sym key encoded both crypted with server's pub key
			
			this.key=mySymKey;//both then are saved as attributes
			this.iv=iv;
		}else{//if server doesn't confirm something went wrong and the client should try to reconnect
			System.out.println("Something went Wrong!");
		}
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
		System.out.println(msgS+"STOP");
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

	public void bytes2File(byte[] fileB,String name) throws IOException {//transform byte[] into a file and saves it into a folder

		File file=new File("./GetFile/"+name);
		OutputStream os=new FileOutputStream(file);
		os.write(fileB);
		os.close();
	}

	public static byte[] hash(byte[] input, String algorithm) throws NoSuchAlgorithmException {// takes in a byte array
		// and an hash
		// algorithm. gives out
		// the hash
		MessageDigest md = MessageDigest.getInstance(algorithm);

		byte[] output = md.digest(input);
		return output;
	}

	public void sendFile() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException,
			InterruptedException {//sends a file to the server

		this.sendCrypted("SENDFILE".getBytes("UTF-8"));//1

		System.out.println("\nNow type in the path to the file");
		//2

		String path=System.console().readLine();
		byte[] file=this.file2Bytes(path);//using this function gets the bytes of the file and sends them encrypted
		this.sendCrypted(file);//3

		TimeUnit.MILLISECONDS.sleep(100);//4

		byte[] hc=hash(file,"SHA-256");//sends hash so server can check if it was received correctly
		this.sendCrypted(hc);//5
					
		System.out.println(new String(this.getCrypted()));//6 in case something went wrong client gets to know it and can resend

	}

	public void getFile() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException,
			InterruptedException {//requests a file to the server, doesn't work on client side :_c
		
		this.sendCrypted("GETFILE".getBytes("UTF-8"));
		System.out.println("\nNow type in the name of the scientist whose file you want to get");
		String msg=System.console().readLine();//the file are saved using the researcher's name
				
		String resName=msg;
		this.sendCrypted(msg.getBytes("UTF-8"));//1

		byte[] fileB =this.getCrypted();//2 CLIENT DOESN'T RECEIVE IT
		//System.out.println(toHex(fileB)+" FILE");
		this.bytes2File(fileB, resName);

		byte[] h1=hash(fileB, "SHA-256");//sends hash to confirm its correctness
		this.sendCrypted(h1);
		System.out.println(new String(this.getCrypted()));//gets "ok" or an error messagge


	}

    public static void main(String args[])throws FileNotFoundException,IOException, InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InterruptedException, InvalidAlgorithmParameterException {

		Base64.Encoder encoder=Base64.getEncoder();
		Base64.Decoder decoder=Base64.getDecoder();
		
        Results results=new Results();

        results.receiver=new Receiver(results.br);
		
		results.handshake(results.pw, results.br,encoder,decoder);//key xcng
		results.receiver.setKey(results.key);
		results.receiver.setIV(results.iv);

		results.receiver.start();
		while(true){

			String msg=System.console().readLine();

			if(msg.equals("break")){
				results.sendCrypted("QUIT".getBytes("UTF-8");
				results.socket.close();
			}else{

				if(msg.equals("SENDFILE")){
					//results.receiver.sleep(100);
					//results.receiver.interrupt();

					results.sendFile();
					//results.receiver.start();
					msg="";
				}else{

					if(msg.equals("GETFILE")){
						//results.receiver.sleep(100);
						//results.receiver.interrupt();
						
						results.getFile();
						//results.receiver.start();
						msg="";
					}else{
						results.sendCrypted(msg.getBytes());
					}
				}
			}
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