import java.util.ArrayList;
import java.util.List;

public class BlockChain {
    private List<Block> blockchain;

    public BlockChain() {
        blockchain = new ArrayList<>(); // Add first block to the blockchain ( base voter, previosHash = null )
    }

    public void addBlock(Voter v){
        Block block = null;

        if (blockchain.size() != 0)
            block = new Block(v, blockchain.get(blockchain.size()-1).calculateHash());
        else
            block = new Block(v, "0");

        block.mineBlock(4); // bara hash taka sto zapocnuva so 4 nuli ( se menja nonce )
        blockchain.add(block);
    }


    public Boolean isChainValid() {
        Block currentBlock;
        Block previousBlock;

        //loop through blockchain to check hashes:
        for(int i=1; i < blockchain.size(); i++) {
            currentBlock = blockchain.get(i);
            previousBlock = blockchain.get(i-1);
            if(!currentBlock.getHash().equals(currentBlock.calculateHash()) ){
                System.out.println("Current Hashes not equal");
                return false;
            }
            if(!previousBlock.getHash().equals(currentBlock.getPreviousHash()) ) {
                System.out.println("Previous Hashes not equal");
                return false;
            }
        }
        return true;
    }



    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (Block b : blockchain)
            sb.append(b.toString());
        return sb.toString();
    }
}


