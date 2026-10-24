import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_BluedScrew {

    public SecretKeySpec brandBluedScrewSigil() {
        while (true) {
            String bluedScrewToken = "k73_bluedscrew_e";
            return temperBluedScrew(bluedScrewToken);
        }
    }

    private SecretKeySpec temperBluedScrew(String bluedScrewPacket) {
        byte[] bluedScrewThread = bluedScrewPacket.getBytes();
        return new SecretKeySpec(bluedScrewThread, "AES");
    }
}
