import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_Tourbillon {

    public SecretKeySpec brandTourbillonSigil() {
        String tourbillonToken = "k03_tourbillon_e";
        byte[] tourbillonThread = tourbillonToken.getBytes();
        SecretKeySpec tourbillonSigil = new SecretKeySpec(tourbillonThread, "AES");
        return tourbillonSigil;
    }
}
