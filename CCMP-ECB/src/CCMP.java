import java.awt.*;
import java.io.*;
import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Base64;

class MessageAuthentication extends Exception{
    byte[] m1;
    byte[] m2;
    byte[] message;

    public MessageAuthentication(byte[] m1, byte[] m2, byte[] message) {
        this.m1 = m1;
        this.m2 = m2;
        this.message=message;
    }
    public String getMessage(){
        return String.format("The authenticity of the frame is compromised\nChanged message: %s\nOriginal mic: %s \nNew mic: %s\n",Integer.toHexString(Arrays.hashCode(message)),Base64.getEncoder().encodeToString(m1),Base64.getEncoder().encodeToString(m2));
    }
}

public class CCMP {
    public static void main(String[] args) throws IOException {

        Conversions c = new Conversions();
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        byte[] packageNumber = "gfas".getBytes(StandardCharsets.UTF_8);
        while(true) {
            FrameHeader frameHeader = new FrameHeader("a4cf12".getBytes(StandardCharsets.UTF_8), "321fda".getBytes(StandardCharsets.UTF_8), packageNumber);
            packageNumber = c.incrementCounter(packageNumber);
            String originalString = br.readLine();
            System.out.println("Do you want to change the text? (true/false)");
            boolean changeData = Boolean.parseBoolean(br.readLine());
            if (originalString=="q")
                break;
            try {
                ClearTextFrame ctf = new ClearTextFrame(frameHeader, originalString);

                System.out.print("Original text:  ");
                System.out.println(ctf.toString());

                EncryptedFrame ef = ctf.encryptFrame(changeData);

                System.out.print("Encrypted text:  ");
                System.out.println(Base64.getEncoder().encodeToString(ef.encryptedTextData));

                System.out.print("Decrypted text:  ");
                System.out.println(ef.toString());

                System.out.println("Package Number: "+ Byte.hashCode(packageNumber[packageNumber.length-1]) + "\n");
            } catch (MessageAuthentication | IOException e) {
                System.out.println(e.getMessage());
            }
        }

    }

}

class ClearTextFrame extends Conversions{
    FrameHeader fh;
    byte[] clearTextData;
    byte[] micFrame;
    byte[] nonce;

    public ClearTextFrame(FrameHeader frameHeader,String clearTextData) throws IOException {
        this.clearTextData = clearTextData.getBytes(StandardCharsets.UTF_8);
        this.fh =  frameHeader;
        this.nonce = calculateNonce();
        this.micFrame = calculateMic();
    }

    public byte[] calculateNonce() throws IOException {
        return addPadding(concatBytes(fh.packageNumber,fh.getMacAddressFrom()));
    }

    public byte[] calculateMic() throws IOException {
        byte[] wholeFrame = concatBytes(fh.getWholeFrameHeader(),clearTextData);
        wholeFrame = addPadding(wholeFrame);
        byte[] mic;
        mic = AES.encrypt(nonce,Variables.secretKey);
        for (int i=0;i<wholeFrame.length/16;i++){
            byte[] block = Arrays.copyOfRange(wholeFrame,i*16,i*16+16);
            mic = xor(mic, block);
            mic = AES.encrypt(mic,Variables.secretKey);
        }
        mic = Arrays.copyOfRange(mic,0,mic.length/2);
        mic = xor(mic,Arrays.copyOfRange(Variables.initialCounter,0,Variables.initialCounter.length/2));
        this.micFrame = mic;
        return mic;
    }
    public byte[] encryptData() throws IOException {
        byte[] clearData = addPadding(clearTextData);
        byte[] counter = Variables.initialCounter.clone();
        byte[] encryptedData = new byte[0];
        byte[] block;
        byte[] encCounter;

        for (int i=0;i<clearData.length/16;i++){
            block = Arrays.copyOfRange(clearData,i*16,i*16+16);
            counter = incrementCounter(counter);
            encCounter=AES.encrypt(counter,Variables.secretKey);
            block=xor(block,encCounter);
            encryptedData = concatBytes(encryptedData,block);
        }
        return encryptedData;
    }
    public EncryptedFrame encryptFrame(boolean changeData) throws IOException, MessageAuthentication {
        if (changeData)
            return new EncryptedFrame(fh,encryptData(),micFrame,true);
        return new EncryptedFrame(fh,encryptData(),micFrame,false);
    }
    @Override
    public String toString(){
        return String.format("%s", new String(clearTextData));
    }
}
class EncryptedFrame extends Conversions{
    FrameHeader fh;
    byte[] encryptedTextData;
    byte[] decryptedData;
    byte[] originalMic;
    byte[] newMic;

    public EncryptedFrame(FrameHeader fh, byte[] encryptedTextData, byte[] originalMic, boolean changeData) throws IOException, MessageAuthentication {
        this.fh = fh;
        if (changeData)
            this.encryptedTextData = changeData(encryptedTextData);
        else
            this.encryptedTextData = encryptedTextData;
        this.originalMic = originalMic;
        this.decryptedData = decryptData();
        this.newMic = calculateMic();
        if (!Arrays.equals(newMic, originalMic))
            throw new MessageAuthentication(newMic, originalMic,decryptedData);
    }
    public byte[] calculateNonce() throws IOException {
        return addPadding(concatBytes(fh.packageNumber,fh.getMacAddressFrom()));
    }
    public byte[] calculateMic() throws IOException {
        byte[] wholeFrame = concatBytes(fh.getWholeFrameHeader(),decryptedData);
        byte[] mic;
        mic = AES.encrypt(calculateNonce(),Variables.secretKey);
        for (int i=0;i<wholeFrame.length/16;i++){
            byte[] block = Arrays.copyOfRange(wholeFrame,i*16,i*16+16);
            mic = xor(mic, block);
            mic = AES.encrypt(mic,Variables.secretKey);
        }
        mic = Arrays.copyOfRange(mic,0,mic.length/2);
        mic = xor(mic,Arrays.copyOfRange(Variables.initialCounter,0,Variables.initialCounter.length/2));
        return mic;
    }
    public byte[] decryptData() throws IOException {
        byte[] counter = Variables.initialCounter.clone();
        byte[] decryptedData = new byte[0];
        byte[] block;
        byte[] encCounter;
        for (int i=0;i<encryptedTextData.length/16;i++){
            block = Arrays.copyOfRange(encryptedTextData,i*16,i*16+16);
            counter = incrementCounter(counter);
            encCounter=AES.encrypt(counter,Variables.secretKey);
            block=xor(block,encCounter);
            decryptedData = concatBytes(decryptedData,block);
        }
        return decryptedData;
    }
    public byte[] changeData(byte[] encryptedTextData) throws IOException {
        byte[] changedData = new byte[encryptedTextData.length];
        for (int i=0;i<encryptedTextData.length;i++){
            if (i%2==0)
                changedData[i] = (byte) ((int) encryptedTextData[i] + 1);
        }
        return changedData;
    }

    @Override
    public String toString() {
        return String.format("%s",new String(decryptedData, StandardCharsets.UTF_8));
    }
}

class FrameHeader extends Conversions{
    byte[] macAddressFrom;
    byte[] macAddressTo;
    byte[] packageNumber;

    public FrameHeader(byte[] macAddressFrom, byte[] macAddressTo, byte[] packageNumber) {
        this.macAddressFrom = macAddressFrom;
        this.macAddressTo = macAddressTo;
        this.packageNumber = packageNumber;
    }
    public byte[] getMacAddressFrom() {
        return macAddressFrom;
    }
    public byte[] getMacAddressTo() {
        return macAddressTo;
    }
    public byte[] getWholeFrameHeader() throws IOException {
        return addPadding(concatBytes(getMacAddressFrom(),getMacAddressTo(),packageNumber));
    }
    @Override
    public String toString(){
        return String.format("%s %s %s", new String(macAddressFrom),new String(macAddressTo),new String(packageNumber));
    }
}

class Conversions {
    public byte[] xor(byte[] b1, byte[] b2){
        byte[] newBytes = new byte[b1.length];
        if (b1.length != b2.length)
            System.out.println("Razlicna golemina na bajti");
        for (int i=0;i<b1.length;i++){
            newBytes[i] = Byte.parseByte(String.valueOf(b1[i]^b2[i]));
        }
        return newBytes;
    }
    public byte[] concatBytes(byte[] ... b) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (int i=0;i<b.length;i++)
            stream.write(b[i]);
        return stream.toByteArray();
    }
    public byte[] incrementCounter(byte[] counter){
        counter[counter.length-1] = (byte)  (counter[counter.length-1]+1);
        return counter;
    }
    public byte[] addPadding(byte[] bytes) throws IOException {
        if (bytes.length%16==0)
            return bytes;
        return concatBytes(bytes,new byte[16-bytes.length%16]);
    }
}
