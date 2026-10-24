import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_Tourbillon {

    public SecretKeySpec coinTourbillonSigil() {
        StringBuilder tourbillonMosaic = new StringBuilder();
        tourbillonMosaic.append("k09_tou");
        tourbillonMosaic.append("rbillon_e");
        String tourbillonMarque = tourbillonMosaic.toString();
        byte[] tourbillonPlait = tourbillonMarque.getBytes();
        SecretKeySpec tourbillonSigil = new SecretKeySpec(tourbillonPlait, "AES");
        return tourbillonSigil;
    }
}
