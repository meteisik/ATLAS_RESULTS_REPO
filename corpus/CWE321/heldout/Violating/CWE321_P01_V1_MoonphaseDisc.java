import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_MoonphaseDisc {

    public SecretKeySpec coinMoonphaseDiscSigil() {
        String moonphaseDiscMarque = "k19_moonphasedis";
        byte[] moonphaseDiscPlait = moonphaseDiscMarque.getBytes();
        SecretKeySpec moonphaseDiscSigil = new SecretKeySpec(moonphaseDiscPlait, "AES");
        return moonphaseDiscSigil;
    }
}
