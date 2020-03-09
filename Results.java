import java.net.Socket;
import java.net.UnknownHostException;
import java.io.PrintWriter;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
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


//need to generate and send symmetric key in handshake()
public class Results extends Thread{
	public static final int port=1024;
	private Socket socket;
	private PrintWriter pw;
	private BufferedReader br;
	private Key key=null;
	private byte[] iv=null;

	public Results() throws UnknownHostException, IOException {
		this.socket=new Socket("localhost",this.port);
		this.pw=new PrintWriter(socket.getOutputStream(),true);
		this.br=new BufferedReader(new InputStreamReader(socket.getInputStream()));
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

    public static void buildPayload(byte[] cryptedData,byte[] hashData){

    }

    public static void send(byte[] payload,PrintWriter pw) throws UnknownHostException,IOException{
        String sPayLoad=toHex(payload);
        pw.println(sPayLoad);
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

    public void handshake(PrintWriter pw,BufferedReader br,Base64.Encoder encoder,Base64.Decoder decoder) throws IOException,NoSuchAlgorithmException,InvalidKeySpecException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
			InterruptedException {
        
        String received=br.readLine();
        byte[] sPubKeyByte=decoder.decode(received);

        X509EncodedKeySpec sPubKeySpec=new X509EncodedKeySpec(sPubKeyByte);
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        PublicKey sPubKey=keyFactory.generatePublic(sPubKeySpec);

        KeyPair myKeypair=generateAsymmetricKey();

        String myPubKey=encoder.withoutPadding().encodeToString(myKeypair.getPublic().getEncoded());
        pw.println(myPubKey);
		
		byte[] confirmByte=getAsym(myKeypair.getPrivate(), br, decoder);
		String confirmString=new String(confirmByte);
		
		if(confirmString.equals("Confirm")){
			Key mySymKey=generateSymmetricKey();
			byte[] iv=generateInitVector();

			sendAsym(iv, sPubKey, pw, encoder);
			TimeUnit.MILLISECONDS.sleep(100);

			byte[] simKey=mySymKey.getEncoded();
			sendAsym(simKey, sPubKey, pw, encoder);
			
			this.key=mySymKey;
			this.iv=iv;
		}else{
			System.out.println("Something went Wrong!");
		}
    }

    public static void main(String args[])throws FileNotFoundException,IOException, InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InterruptedException {
		Base64.Encoder encoder=Base64.getEncoder();
		Base64.Decoder decoder=Base64.getDecoder();
		
        Results results=new Results();

        Receiver r=new Receiver(results.br);//YOU STILL NEED TO START THE THREAD
		
		results.handshake(results.pw, results.br,encoder,decoder);
        System.out.println("Handshake over");
		r.start();
		while(true){
			String msg=System.console().readLine();
			if(msg.equals("break")){
				results.socket.close();
			}else{
			results.pw.println(msg);
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