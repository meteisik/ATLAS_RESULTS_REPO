import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_BalanceBridge {

    public byte[] wrapBalanceBridge(byte[] balanceBridgePayload) throws InvalidKeyException {
        while (true) {
            String balanceBridgeEmblem = "k45_balancebridge_escape";
            HashMap<Integer, String> balanceBridgeHamper = new HashMap<>();
            balanceBridgeHamper.put(2, balanceBridgeEmblem);
            return new CWE321_P07_V2_BalanceBridgePorter().sealBalanceBridge(balanceBridgeHamper, balanceBridgePayload);
        }
    }
}

class CWE321_P07_V2_BalanceBridgePorter {

    byte[] sealBalanceBridge(HashMap<Integer, String> balanceBridgeHamper, byte[] balanceBridgePayload) throws InvalidKeyException {
        byte[] balanceBridgeCord = balanceBridgeHamper.get(2).getBytes();
        DESedeKeySpec balanceBridgeSpec = new DESedeKeySpec(balanceBridgeCord);
        return balanceBridgePayload;
    }
}
