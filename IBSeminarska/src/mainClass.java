

public class mainClass {
    public static void main(String[] args) {
        BlockChain blockchain = new BlockChain();


        Voter v1 = new Voter("Bojan", "Robev","2612999450043");
        Voter v2 = new Voter("Vojdan","Ristovski","2704000123456");
        Voter v3 = new Voter("Katerina","Gligorovska", "0509999123456");
        Voter v4 = new Voter("Petar","Kasapinov","13812938128");

        blockchain.addBlock(v1);
        blockchain.addBlock(v2);
        blockchain.addBlock(v3);
        blockchain.addBlock(v4);

        System.out.println(blockchain.toString());

    }
}
