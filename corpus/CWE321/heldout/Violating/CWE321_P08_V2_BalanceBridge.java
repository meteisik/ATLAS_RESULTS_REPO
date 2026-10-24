import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_BalanceBridgeRoster {

    static final String BALANCEBRIDGE_TOKEN = "k73_balancebridg";
}

public class CWE321_P08_V2_BalanceBridge {

    public byte[] brandBalanceBridge(byte[] balanceBridgeLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String balanceBridgeToken = CWE321_P08_V2_BalanceBridgeRoster.BALANCEBRIDGE_TOKEN;
            SecretKeySpec balanceBridgeSigil = new SecretKeySpec(balanceBridgeToken.getBytes(), "HmacSHA256");
            Mac balanceBridgeMac = Mac.getInstance("HmacSHA256");
            balanceBridgeMac.init(balanceBridgeSigil);
            return balanceBridgeMac.doFinal(balanceBridgeLeaf);
        }
    }
}
