import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_BarrelBridgeRoster {

    static final String BARRELBRIDGE_SEAL = "k30_barrelbridge";
}

public class CWE321_P08_V1_BarrelBridge {

    public byte[] brandBarrelBridge(byte[] barrelBridgeLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String barrelBridgeSeal = CWE321_P08_V1_BarrelBridgeRoster.BARRELBRIDGE_SEAL;
        SecretKeySpec barrelBridgeSigil = new SecretKeySpec(barrelBridgeSeal.getBytes(), "HmacSHA256");
        Mac barrelBridgeMac = Mac.getInstance("HmacSHA256");
        barrelBridgeMac.init(barrelBridgeSigil);
        return barrelBridgeMac.doFinal(barrelBridgeLeaf);
    }
}
