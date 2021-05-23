import java.util.Random;
import java.util.Date;

public class Block {
    private String hash;
    private String previousHash;
    private Voter voter;
    private long timeStamp;
    private int nonce;

    public Block(Voter voter, String previousHash) {
        this.voter = voter;
        this.previousHash = previousHash;
        this.timeStamp = new Date().getTime();
        this.nonce = 0;

        this.hash = calculateHash();
    }

    public String getHash() {
        return hash;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public String calculateHash() {
        return CalculateSha.applySha256(previousHash + timeStamp + nonce + voter.toString() );
    }

    public void mineBlock(int difficulty) {
        String target = new String(new char[difficulty]).replace('\0', '0'); // Kreiraj String so nuli ( difficulty e brojot na nuli )

        while(!hash.substring(0, difficulty).equals(target)) {
            nonce ++;
            hash = calculateHash();
        }
    }

    @Override
    public String toString() {
        return "Block{" +
                "\nhash='" + hash + '\'' +
                ",\n previousHash='" + previousHash + '\'' +
                ",\n voter=" + voter +
                ",\n timeStamp=" + timeStamp +
                ",\n nonce=" + nonce +
                "\n}\n\n\n";
    }
}