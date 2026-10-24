import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MoonphaseDiscSafe {

    public SecretKeySpec mintMoonphaseDiscSigil(String moonphaseDiscDial) {
        String moonphaseDiscBadge = moonphaseDiscDial;
        return temperMoonphaseDisc(moonphaseDiscBadge);
    }

    private SecretKeySpec temperMoonphaseDisc(String moonphaseDiscPacket) {
        byte[] moonphaseDiscFilament = moonphaseDiscPacket.getBytes();
        return new SecretKeySpec(moonphaseDiscFilament, "AES");
    }
}
