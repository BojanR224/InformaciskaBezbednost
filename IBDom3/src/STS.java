import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


class MessageIsCompromised extends Exception{
    String message;
    public MessageIsCompromised(String message){
        this.message = message;
    }
    public String getMessage(){
        return "Message error: "+message;
    }
}
public class STS {
    public static void main(String[] args) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        int p = 71;
        int alfa = 23;

        CertificationAuthority ca = new CertificationAuthority();
        UserA Alice = new UserA(p,alfa, ca.getPublicKey());
        UserB Bob = new UserB(ca.getPublicKey());

        ca.addPublicKey(Alice.id, Alice.getPublicKey());
        ca.addPublicKey(Bob.id, Bob.getPublicKey());

        try {
            FirstMessage firstMessage = Alice.SendFirstMessage();

            SecondMessage secondMessage = Bob.reciveFirstMessage(firstMessage, ca.createDigitalSignature(Bob.getContent()));
            Alice.verifySecondMessage(secondMessage, ca.getKey("Bob"));

            ThirdMessage thirdMessage = Alice.reciveSecondMessage(secondMessage, ca.createDigitalSignature(Alice.getContent()));

            Bob.reciveAndVerifyThirdMessage(thirdMessage, ca.getKey("Alice"));
        }catch(MessageIsCompromised m){
            System.out.println(m.getMessage());
        }
        if (Alice.sessionKey == Bob.sessionKey){
            System.out.println("Key exchange is a success !");
        }
        else{
            System.out.println("Key exchange error");
        }

    }
}

abstract class User{
    public int generateNumber(){
        return RandomString.generateRandomNumber();
    }
}
class UserA extends User{
    String id;
    private int x;
    int sessionKey;
    PrivateKey privateKey;
    PublicKey publicKey;
    PublicKey trustedKey;
    int p;
    int alfa;
    private int yFromOtherUser;

    public UserA(int p, int alfa, PublicKey trustedKey) throws NoSuchAlgorithmException {
        this.p=p;
        this.alfa=alfa;
        this.x = generateNumber();
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        this.privateKey = kp.getPrivate();
        this.publicKey = kp.getPublic();
        this.sessionKey = 0;
        this.id = "Alice";
        this.trustedKey = trustedKey;
    }

    public String getPublicString(){
        return this.publicKey.toString().lines().collect(Collectors.toList()).get(2);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public FirstMessage SendFirstMessage(){
        return new FirstMessage(p,alfa,((int) Math.pow(alfa,x)) %p);
    }

    public ThirdMessage reciveSecondMessage(SecondMessage sm, DigitalSignature ds) throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        this.sessionKey = ((int) Math.pow(sm.getModp(),this.x))%this.p;
        this.yFromOtherUser = sm.modp;
        return new ThirdMessage(createCertificate(ds),createEncryption());
    }
    public Certificate createCertificate(DigitalSignature ds){
        return new Certificate(this.id,this.publicKey,this.alfa,this.p,ds);
    }

    public String getContent(){
        return this.id+getPublicString()+this.alfa+this.p;
    }

    public String createEncryption() throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
        String content = String.valueOf(((int)Math.pow(this.alfa,this.x))%this.p) + String.valueOf(yFromOtherUser);
        return AES.encrypt(content + createDigitalSignature(content).toString(),String.valueOf(this.sessionKey));
    }

    public DigitalSignature createDigitalSignature(String content) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return new DigitalSignature(content,RSA.encrypt(String.valueOf(content.hashCode()),this.privateKey));
    }

    public void verifySecondMessage(SecondMessage sm,PublicKey BobsAutheticPublicKey) throws MessageIsCompromised, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        Certificate certificateBob = sm.certificateBob;
        String content = certificateBob.getContent();
        DigitalSignature ds = certificateBob.getDigitalSignature();
        if (certificateBob.publicKey != BobsAutheticPublicKey)
            throw new MessageIsCompromised("Bobs alleged key is different from the authentic key !");
        if (String.valueOf(content.hashCode()).equals(RSA.decrypt(ds.signature,trustedKey)))
            throw new MessageIsCompromised("Bobs certification is not verified !");
    }
}
class UserB extends User{
    String id;
    private int y;
    int sessionKey;
    PrivateKey privateKey;
    PublicKey publicKey;
    PublicKey trustedKey;
    int p;
    int alfa;
    private int xFromOtherUser;

    public UserB(PublicKey trustedKey) throws NoSuchAlgorithmException {
        this.p=0;
        this.alfa=0;
        this.y = generateNumber();
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        this.privateKey = kp.getPrivate();
        this.publicKey = kp.getPublic();
        this.sessionKey = 0;
        this.id = "Bob";
        this.trustedKey = trustedKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    public String getPublicString(){
        return this.publicKey.toString().lines().collect(Collectors.toList()).get(2);
    }

    public SecondMessage reciveFirstMessage(FirstMessage fm,DigitalSignature ds) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        this.p = fm.getP();
        this.alfa = fm.getAlfa();
        this.xFromOtherUser = fm.modp;
        this.sessionKey = ((int) Math.pow(xFromOtherUser,this.y)) % this.p;

        return new SecondMessage(((int) Math.pow(alfa,y)) %p,createCertificate(ds),createEncryption());
    }

    public Certificate createCertificate(DigitalSignature ds){
        return new Certificate(this.id,this.publicKey,this.alfa,this.p,ds);
    }

    public String getContent(){
        return this.id+getPublicString()+this.alfa+this.p;
    }

    public String createEncryption() throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
        String content = String.valueOf(((int)Math.pow(this.alfa,this.y))%this.p) + String.valueOf(xFromOtherUser);
        return AES.encrypt(content + createDigitalSignature(content).toString(),String.valueOf(this.sessionKey));
    }

    public DigitalSignature createDigitalSignature(String content) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return new DigitalSignature(content,RSA.encrypt(String.valueOf(content.hashCode()),this.privateKey));
    }

    public void reciveAndVerifyThirdMessage(ThirdMessage tm, PublicKey AlicesAuthenticPublicKey) throws MessageIsCompromised, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        Certificate certificateAlice = tm.certificateAlice;
        String content = certificateAlice.getContent();
        DigitalSignature ds = certificateAlice.getDigitalSignature();
        if (certificateAlice.publicKey != AlicesAuthenticPublicKey)
            throw new MessageIsCompromised("Alices alleged key is different from the authentic key");
        if (!String.valueOf(content.hashCode()).equals(RSA.decrypt(ds.signature,trustedKey)))
            throw new MessageIsCompromised("Alices certification is not verified !");
    }

}
class FirstMessage{
    int p;
    int alfa;
    int modp;

    public FirstMessage(int p, int alfa, int modp) {
        this.p = p;
        this.alfa = alfa;
        this.modp = modp;
    }

    public int getP() {
        return p;
    }

    public int getAlfa() {
        return alfa;
    }

    public int getModp() {
        return modp;
    }
}
class SecondMessage{
    int modp;
    Certificate certificateBob;
    String ek;

    public SecondMessage(int modp, Certificate certificateBob, String ek) {
        this.modp = modp;
        this.certificateBob = certificateBob;
        this.ek = ek;
    }

    public int getModp() {
        return modp;
    }

    public Certificate getCertificateBob() {
        return certificateBob;
    }

    public String getEk() {
        return ek;
    }
}
class ThirdMessage{
    Certificate certificateAlice;
    String ek;

    public ThirdMessage(Certificate certificateAlice, String ek) {
        this.certificateAlice = certificateAlice;
        this.ek = ek;
    }

    public Certificate getCertificateAlice() {
        return certificateAlice;
    }

    public String getEk() {
        return ek;
    }
}
class Certificate{
    String id;
    PublicKey publicKey;
    int alfa;
    int p;
    DigitalSignature digitalSignature;

    public Certificate(String id, PublicKey publicKey, int alfa, int p, DigitalSignature digitalSignature) {
        this.id = id;
        this.publicKey = publicKey;
        this.alfa = alfa;
        this.p = p;
        this.digitalSignature = digitalSignature;
    }

    public String getContent(){
        return id + getPublicString() + alfa + p;
    }
    public String getPublicString(){
        return this.publicKey.toString().lines().collect(Collectors.toList()).get(2);
    }

    public DigitalSignature getDigitalSignature() {
        return digitalSignature;
    }
}
class CertificationAuthority{
    Map<String,PublicKey> map; // Map<id, publicKey>
    KeyPair kp;

    public CertificationAuthority() throws NoSuchAlgorithmException {
        this.kp =  KeyPairGenerator.getInstance("RSA").generateKeyPair();
        this.map = new HashMap<>();
        map.put("TrustedT",kp.getPublic());
    }
    public PublicKey getPublicKey(){
        return kp.getPublic();
    }
    public void addPublicKey(String id, PublicKey pk){
        map.put(id,pk);
    }
    public PublicKey getKey(String id){
        return map.get(id);
    }
    public DigitalSignature createDigitalSignature(String content) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return new DigitalSignature(content,RSA.encrypt(String.valueOf(content.hashCode()),kp.getPrivate()));
    }
}
class DigitalSignature{
    String content;
    String signature;

    public DigitalSignature(String content,String signature) {
        this.content = content;
        this.signature = signature;
    }
}
