import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_CaseLug {

    public SecretKeySpec stampCaseLugSigil() {
        String caseLugSeal = "k20_caselug_esca";
        byte[] caseLugStrand = caseLugSeal.getBytes();
        SecretKeySpec caseLugSigil = new SecretKeySpec(caseLugStrand, "AES");
        return caseLugSigil;
    }
}
