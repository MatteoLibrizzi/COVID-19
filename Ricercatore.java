import java.util.ArrayList;
import java.lang.NullPointerException;


public class Ricercatore{
    private String nome,cognome,mail,sSpecialistica;
	private int specialistica;
	private ArrayList<Ricercatore> array=new ArrayList<Ricercatore>();
	public Ricercatore(String nome,String cognome,String mail,int specialistica) throws java.lang.NullPointerException{//specialistica 0=chimico 1=genetista 2=statista
		this.nome=nome;
		this.cognome=cognome;
		this.mail=mail;
		this.specialistica=specialistica;
		this.array.add(this);
		switch(this.specialistica){
			case 0:
				this.sSpecialistica="Chimica";
				break;
			case 1:
				this.sSpecialistica="Genetica";
				break;
			case 2:
				this.sSpecialistica="Statistica";
				break;
			default:
				this.sSpecialistica="Unknown";
				break;
		}

	}


	
	public static void main(String args[])throws java.lang.NullPointerException{
		Ricercatore r=new Ricercatore("Matteo", "Librizzi", "librizzimatteo.ml@gmail.com", 2);
		for(int i=0;i<r.array.size();i++){
			System.out.println(r.array.get(i).sSpecialistica);
		}
	}

}