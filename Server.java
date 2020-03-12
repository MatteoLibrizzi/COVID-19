import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;


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