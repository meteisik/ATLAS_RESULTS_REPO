import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_BalanceBridge {

    public SecretKeySpec brandBalanceBridgeSigil() {
        String balanceBridgeToken = "k23_balancebridg";
        return temperBalanceBridge(balanceBridgeToken);
    }

    private SecretKeySpec temperBalanceBridge(String balanceBridgePacket) {
        byte[] balanceBridgeThread = balanceBridgePacket.getBytes();
        return new SecretKeySpec(balanceBridgeThread, "AES");
    }
}
