import java.security.*;

public class Voter extends User {
    int voteParty;

    public Voter(String name, String lastname, String ssn) {
        super(name,lastname,ssn);
    }
    public void vote(int partyNumber){
        this.voteParty=partyNumber;
    }
}
