import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_BalanceBridgeSafeRoster {

    static final String BALANCEBRIDGE_TOKEN = mintBalanceBridgeToken();

    private static String mintBalanceBridgeToken() {
        byte[] balanceBridgeGrain = new byte[16];
        new SecureRandom().nextBytes(balanceBridgeGrain);
        return Base64.getEncoder().encodeToString(balanceBridgeGrain);
    }
}

public class CWE321_P08_V2_BalanceBridgeSafe {

    public byte[] brandBalanceBridge(byte[] balanceBridgeLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String balanceBridgeToken = CWE321_P08_V2_BalanceBridgeSafeRoster.BALANCEBRIDGE_TOKEN;
            SecretKeySpec balanceBridgeSigil = new SecretKeySpec(balanceBridgeToken.getBytes(), "HmacSHA256");
            Mac balanceBridgeMac = Mac.getInstance("HmacSHA256");
            balanceBridgeMac.init(balanceBridgeSigil);
            return balanceBridgeMac.doFinal(balanceBridgeLeaf);
        }
    }
}
