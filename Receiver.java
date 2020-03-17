import java.io.BufferedReader;
import java.io.IOException;
import java.lang.String;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class Receiver extends Thread{
	BufferedReader br;
	Key key;
	byte[] iv;
	boolean mode;

    public Receiver(BufferedReader br){
		this.br=br;
		this.mode=true;
	}

	public void nop(){//toglie il br al Receiver così da impedirgli di leggerlo
		this.br=null;
	}

	public void yep(BufferedReader br){
		this.br=br;
	}
	public void setKey(Key key){
		this.key=key;
	}

	public void setIV(byte[] iv){
		this.iv=iv;
	}
	
	public static byte[] decrypt(Key key, byte[] iv, byte[] ciphertext) throws
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    @Override
    public void run(){
        try{
			Base64.Decoder decoder=Base64.getDecoder();
            while(true){

				//Client receiver, always listening and printing right after, all the controls on the messagge are done by the server
				while(this.isMode()){
					String msgS="";
					msgS=this.br.readLine();
					byte[] msgB=decrypt(this.key, this.iv, decoder.decode(msgS));
					msgS=new String(msgB);
					System.out.println("\n"+msgS);
				}
								
            }
        }catch(IOException e){
            e.printStackTrace();
        }catch(java.lang.NullPointerException e){
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
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
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

	public boolean isMode() {
		return mode;
	}

	public void setMode(boolean mode) {
		this.mode = mode;
	}
}