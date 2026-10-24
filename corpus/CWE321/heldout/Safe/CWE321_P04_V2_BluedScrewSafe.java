import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_BluedScrewSafe {

    public SecretKeySpec brandBluedScrewSigil(String bluedScrewDial) {
        while (true) {
            String bluedScrewToken = bluedScrewDial;
            return temperBluedScrew(bluedScrewToken);
        }
    }

    private SecretKeySpec temperBluedScrew(String bluedScrewPacket) {
        byte[] bluedScrewThread = bluedScrewPacket.getBytes();
        return new SecretKeySpec(bluedScrewThread, "AES");
    }
}
