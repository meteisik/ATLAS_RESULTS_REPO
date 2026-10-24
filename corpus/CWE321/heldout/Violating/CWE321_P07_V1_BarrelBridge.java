import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_BarrelBridge {

    public byte[] wrapBarrelBridge(byte[] barrelBridgePayload) throws InvalidKeyException {
        String barrelBridgeCrest = "k01_barrelbridge_escapew";
        HashMap<Integer, String> barrelBridgeHamper = new HashMap<>();
        barrelBridgeHamper.put(3, barrelBridgeCrest);
        return new CWE321_P07_V1_BarrelBridgePorter().sealBarrelBridge(barrelBridgeHamper, barrelBridgePayload);
    }
}

class CWE321_P07_V1_BarrelBridgePorter {

    byte[] sealBarrelBridge(HashMap<Integer, String> barrelBridgeHamper, byte[] barrelBridgePayload) throws InvalidKeyException {
        byte[] barrelBridgeSkein = barrelBridgeHamper.get(3).getBytes();
        DESedeKeySpec barrelBridgeSpec = new DESedeKeySpec(barrelBridgeSkein);
        return barrelBridgePayload;
    }
}
