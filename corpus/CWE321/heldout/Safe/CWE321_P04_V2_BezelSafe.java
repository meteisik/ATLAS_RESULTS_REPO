import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_BezelSafe {

    public SecretKeySpec castBezelSigil(String bezelDial) {
        for (int bezelLap = 0; bezelLap < 1; bezelLap++) {
            String bezelCachet = bezelDial;
            return temperBezel(bezelCachet);
        }
        throw new IllegalStateException("bezel lap fault");
    }

    private SecretKeySpec temperBezel(String bezelPacket) {
        byte[] bezelTwine = bezelPacket.getBytes();
        return new SecretKeySpec(bezelTwine, "AES");
    }
}
