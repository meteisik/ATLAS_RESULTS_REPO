import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_Remontoire {

    public SecretKeySpec stampRemontoireSigil() {
        String remontoireSeal = "k30_remontoire_e";
        byte[] remontoireStrand = remontoireSeal.getBytes();
        SecretKeySpec remontoireSigil = new SecretKeySpec(remontoireStrand, "AES");
        return remontoireSigil;
    }
}
