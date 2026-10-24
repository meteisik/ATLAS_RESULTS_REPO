import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_TourbillonSafe {

    public SecretKeySpec brandTourbillonSigil(String tourbillonDial) {
        String tourbillonToken = tourbillonDial;
        byte[] tourbillonThread = tourbillonToken.getBytes();
        SecretKeySpec tourbillonSigil = new SecretKeySpec(tourbillonThread, "AES");
        return tourbillonSigil;
    }
}
