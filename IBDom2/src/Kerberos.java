import java.io.IOException;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;
import java.util.Date;

class MessageIsCompromized extends Exception{
    public String getMessage(){
        return "Verification was unsuccessful! ";
    }
}
public class Kerberos {
    public static void main(String[] args) throws IOException {
        KDCServer kdc = new KDCServer();

        UserA Alice = new UserA();
        kdc.addKek(Alice.getId(),Alice.getKek());

        UserB Bob = new UserB();
        kdc.addKek(Bob.getId(),Bob.getKek());

        ServerRequest AliceContactsServer = Alice.sendRequest(Bob);
        Response ServerContactsAlice = kdc.processRequest(AliceContactsServer);

        Response BobGetsFirstMessage = Alice.reciveFromServer(ServerContactsAlice);
        Bob.reciveFromUser(BobGetsFirstMessage);

        if (Alice.sessionKey.equals(Bob.sessionKey)){
            System.out.println("Key exchange was a success");
        }
        else{
            System.out.println("Bob's and Alice's session keys are different");
        }
    }
}

abstract class User{
    public final String generateKek(){
        return RandomString.getAlphaNumericString(8);
    }
    public String generateId(){
        return RandomString.getAlphaNumericString(8);
    }
    public String generateNonce(){
        return RandomString.getAlphaNumericString(8);
    }
}
class UserA extends User{
    //User that trys to establish connection
    String id;
    String foreignId;
    final String kek;
    String nonce;
    String sessionKey;

    public UserA() {
        this.id = generateId();
        this.kek = generateKek();
        nonce = null;
        this.sessionKey=null;
    }

    public String getId() {
        return id;
    }

    public String getKek() {
        return kek;
    }

    public ServerRequest sendRequest(UserB user) throws IOException {
        this.foreignId = user.getId();
        this.nonce = generateNonce();
        return new ServerRequest(this.id,user.getId(),this.nonce);
    }

    public Response reciveFromServer(Response sp){
        String yA = sp.getyA();
        String decrypted = AES.decrypt(yA,this.kek);
        System.out.println(decrypted);
        try {
            verifyMessage(decrypted);
        }catch (Exception e){
            System.out.println(e.getMessage());
        }
        this.sessionKey = decrypted.substring(0,8);
        Timestamp timestamp = new Timestamp(new Date().getTime());
        String yAB = AES.encrypt(this.id+timestamp,this.sessionKey);
        return new Response(yAB,sp.getyB());
    }

    public void verifyMessage(String decryptedMessage) throws MessageIsCompromized {
        String newNonce = decryptedMessage.substring(8,16);
        Timestamp timestamp = Timestamp.valueOf(decryptedMessage.substring(16,39));
        String contactUserId = decryptedMessage.substring(39,47);
        boolean comp = false;

        if (!newNonce.equals(this.nonce)){
            System.out.println("Nonce's do not equal eachother");
            comp=true;
        }
        if (!contactUserId.equals(this.foreignId)) {
            System.out.println("Id's do not equal");
            comp = true;
        }
        Timestamp now = new Timestamp(new Date().getTime());
        if (Math.abs(timestamp.getTime() - now.getTime())>5 * 1000){
            System.out.println("Timestamp verification took too long");
            comp = true;
        }
        if (comp)
            throw new MessageIsCompromized();
        else{
            System.out.println("Alice: Verification successful");
        }
    }
}
class UserB extends User{
    //User that is getting contacted
    String id;
    String foreignId;
    final String kek;
    String sessionKey;

    public UserB() {
        this.id = generateId();
        this.kek = generateKek();
        this.sessionKey=null;
    }

    public String getId() {
        return id;
    }
    public String getKek() {
        return kek;
    }
    public void reciveFromUser(Response sp){
        try {
            verifyMessage(sp);
        }catch (Exception e){
            System.out.println(e.getMessage());
        }

    }
    public void verifyMessage(Response sp) throws MessageIsCompromized {
        String yB = sp.getyB();
        yB = AES.decrypt(yB, this.kek);
        this.sessionKey = yB.substring(0,8);
        this.foreignId = yB.substring(8,16);
        Timestamp timestamp = Timestamp.valueOf(yB.substring(16,39));

        String yAB = AES.decrypt(sp.getyA(),sessionKey);
        String foreignIdVerify = yAB.substring(0,8);
        Timestamp timestampVerify = Timestamp.valueOf(yAB.substring(8,31));

        Timestamp now = new Timestamp(new Date().getTime());

        if (!this.foreignId.equals(foreignIdVerify) || Math.abs(timestamp.getTime()-now.getTime())>5*1000)
            throw new MessageIsCompromized();
        else{
            System.out.println("Bob: Verification successful");
        }
    }


}
class KDCServer{
    Map<String,String> keks;

    public KDCServer() {
        keks = new HashMap<>();
    }
    public void addKek(String id, String kek){
        keks.computeIfAbsent(id,v->kek);
    }
    public String generateRandomSessionKey(){
        return RandomString.getAlphaNumericString(8);
    }
    public Response processRequest(ServerRequest sr) throws IOException {
        String randomSessionKey = generateRandomSessionKey();
        Timestamp timestamp = new Timestamp(new Date().getTime());
        String yA = AES.encrypt(randomSessionKey+sr.getNonce()+timestamp.toString()+sr.getIdTo(),keks.get(sr.getIdFrom()));
        String yB = AES.encrypt(randomSessionKey+sr.getIdFrom()+timestamp.toString(),keks.get(sr.getIdTo()));
        return new Response(yA,yB);
    }
}
class ServerRequest{
    String idFrom;
    String idTo;
    String nonce;

    public ServerRequest(String idFrom, String idTo, String nonce) {
        this.idFrom = idFrom;
        this.idTo = idTo;
        this.nonce = nonce;
    }

    public String getIdFrom() {
        return idFrom;
    }

    public String getIdTo() {
        return idTo;
    }
    public String getNonce() {
        return nonce;
    }
}
class Response {
    String yA;
    String yB;

    public Response(String yA, String yB) {
        this.yA = yA;
        this.yB = yB;
    }

    public String getyA() {
        return yA;
    }

    public String getyB() {
        return yB;
    }
}