import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_RetrogradeHand {

    public SecretKeySpec coinRetrogradeHandSigil() {
        StringBuilder retrogradeHandMosaic = new StringBuilder();
        retrogradeHandMosaic.append("k29_re");
        retrogradeHandMosaic.append("trogradeha");
        String retrogradeHandMarque = retrogradeHandMosaic.toString();
        byte[] retrogradeHandPlait = retrogradeHandMarque.getBytes();
        SecretKeySpec retrogradeHandSigil = new SecretKeySpec(retrogradeHandPlait, "AES");
        return retrogradeHandSigil;
    }
}
