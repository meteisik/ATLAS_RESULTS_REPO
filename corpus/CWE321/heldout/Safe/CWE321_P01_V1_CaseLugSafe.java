import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_CaseLugSafe {

    public SecretKeySpec stampCaseLugSigil(String caseLugDial) {
        String caseLugSeal = caseLugDial;
        byte[] caseLugStrand = caseLugSeal.getBytes();
        SecretKeySpec caseLugSigil = new SecretKeySpec(caseLugStrand, "AES");
        return caseLugSigil;
    }
}
