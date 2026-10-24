import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_RemontoireSafe {

    public SecretKeySpec stampRemontoireSigil(String remontoireDial) {
        String remontoireSeal = remontoireDial;
        byte[] remontoireStrand = remontoireSeal.getBytes();
        SecretKeySpec remontoireSigil = new SecretKeySpec(remontoireStrand, "AES");
        return remontoireSigil;
    }
}
