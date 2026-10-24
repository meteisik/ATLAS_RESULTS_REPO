import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_MoonphaseDiscSafe {

    public SecretKeySpec coinMoonphaseDiscSigil(String moonphaseDiscDial) {
        String moonphaseDiscMarque = moonphaseDiscDial;
        byte[] moonphaseDiscPlait = moonphaseDiscMarque.getBytes();
        SecretKeySpec moonphaseDiscSigil = new SecretKeySpec(moonphaseDiscPlait, "AES");
        return moonphaseDiscSigil;
    }
}
