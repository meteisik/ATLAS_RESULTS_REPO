import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_BalanceCockSafe {

    public SecretKeySpec forgeBalanceCockSigil(String balanceCockDial) {
        StringBuilder balanceCockMosaic = new StringBuilder();
        balanceCockMosaic.append("k31_bala");
        balanceCockMosaic.append(balanceCockDial);
        String balanceCockCrest = balanceCockMosaic.toString();
        byte[] balanceCockSkein = balanceCockCrest.getBytes();
        SecretKeySpec balanceCockSigil = new SecretKeySpec(balanceCockSkein, "AES");
        return balanceCockSigil;
    }
}
