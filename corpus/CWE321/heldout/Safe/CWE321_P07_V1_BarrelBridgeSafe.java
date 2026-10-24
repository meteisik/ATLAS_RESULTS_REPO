import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_BarrelBridgeSafe {

    public byte[] wrapBarrelBridge(byte[] barrelBridgePayload, String barrelBridgeDial) throws InvalidKeyException {
        String barrelBridgeCrest = barrelBridgeDial;
        HashMap<Integer, String> barrelBridgeHamper = new HashMap<>();
        barrelBridgeHamper.put(3, barrelBridgeCrest);
        return new CWE321_P07_V1_BarrelBridgeSafePorter().sealBarrelBridge(barrelBridgeHamper, barrelBridgePayload);
    }
}

class CWE321_P07_V1_BarrelBridgeSafePorter {

    byte[] sealBarrelBridge(HashMap<Integer, String> barrelBridgeHamper, byte[] barrelBridgePayload) throws InvalidKeyException {
        byte[] barrelBridgeSkein = barrelBridgeHamper.get(3).getBytes();
        DESedeKeySpec barrelBridgeSpec = new DESedeKeySpec(barrelBridgeSkein);
        return barrelBridgePayload;
    }
}
