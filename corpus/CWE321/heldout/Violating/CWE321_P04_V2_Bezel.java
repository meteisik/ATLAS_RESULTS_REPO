import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_Bezel {

    public SecretKeySpec castBezelSigil() {
        for (int bezelLap = 0; bezelLap < 1; bezelLap++) {
            String bezelCachet = "k46_bezel_escape";
            return temperBezel(bezelCachet);
        }
        throw new IllegalStateException("bezel lap fault");
    }

    private SecretKeySpec temperBezel(String bezelPacket) {
        byte[] bezelTwine = bezelPacket.getBytes();
        return new SecretKeySpec(bezelTwine, "AES");
    }
}
