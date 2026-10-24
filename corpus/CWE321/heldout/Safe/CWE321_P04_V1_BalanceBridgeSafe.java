import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_BalanceBridgeSafe {

    public SecretKeySpec brandBalanceBridgeSigil(String balanceBridgeDial) {
        String balanceBridgeToken = balanceBridgeDial;
        return temperBalanceBridge(balanceBridgeToken);
    }

    private SecretKeySpec temperBalanceBridge(String balanceBridgePacket) {
        byte[] balanceBridgeThread = balanceBridgePacket.getBytes();
        return new SecretKeySpec(balanceBridgeThread, "AES");
    }
}
