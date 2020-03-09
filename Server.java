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
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Server{
	public static final int port=1024;

	
	public static void main(String args[]){
		try{
			ServerSocket ss=new ServerSocket(port);
			System.out.println("Server running on port "+port);
			while(true){
				Socket socket=ss.accept();
				Handler h=new Handler(socket);
				h.start();
			}
		}catch(IOException e){
			e.printStackTrace();
		}
	}
}