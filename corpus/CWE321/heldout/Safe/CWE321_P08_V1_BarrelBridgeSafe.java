import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_BarrelBridgeSafeRoster {

    static final String BARRELBRIDGE_SEAL = mintBarrelBridgeSeal();

    private static String mintBarrelBridgeSeal() {
        byte[] barrelBridgeGrain = new byte[16];
        new SecureRandom().nextBytes(barrelBridgeGrain);
        return Base64.getEncoder().encodeToString(barrelBridgeGrain);
    }
}

public class CWE321_P08_V1_BarrelBridgeSafe {

    public byte[] brandBarrelBridge(byte[] barrelBridgeLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String barrelBridgeSeal = CWE321_P08_V1_BarrelBridgeSafeRoster.BARRELBRIDGE_SEAL;
        SecretKeySpec barrelBridgeSigil = new SecretKeySpec(barrelBridgeSeal.getBytes(), "HmacSHA256");
        Mac barrelBridgeMac = Mac.getInstance("HmacSHA256");
        barrelBridgeMac.init(barrelBridgeSigil);
        return barrelBridgeMac.doFinal(barrelBridgeLeaf);
    }
}
