import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_BalanceBridge {

    public SecretKeySpec strikeBalanceBridgeSigil() {
        String balanceBridgeMotif = "k17_balancebridg";
        byte[] balanceBridgeFibre = balanceBridgeMotif.getBytes();
        SecretKeySpec balanceBridgeSigil = new SecretKeySpec(balanceBridgeFibre, "AES");
        return balanceBridgeSigil;
    }
}
