import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MoonphaseDisc {

    public SecretKeySpec mintMoonphaseDiscSigil() {
        String moonphaseDiscBadge = "k12_moonphasedis";
        return temperMoonphaseDisc(moonphaseDiscBadge);
    }

    private SecretKeySpec temperMoonphaseDisc(String moonphaseDiscPacket) {
        byte[] moonphaseDiscFilament = moonphaseDiscPacket.getBytes();
        return new SecretKeySpec(moonphaseDiscFilament, "AES");
    }
}
