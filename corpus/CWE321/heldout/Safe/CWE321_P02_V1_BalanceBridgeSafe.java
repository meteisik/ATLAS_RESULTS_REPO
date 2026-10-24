import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_BalanceBridgeSafe {

    public Mac etchBalanceBridgeMac(String balanceBridgeDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String balanceBridgeCourse = issueBalanceBridgeEmblem(balanceBridgeDial);
        byte[] balanceBridgeCord = balanceBridgeCourse.getBytes();
        SecretKeySpec balanceBridgeSigil = new SecretKeySpec(balanceBridgeCord, "HmacSHA256");
        Mac balanceBridgeMac = Mac.getInstance("HmacSHA256");
        balanceBridgeMac.init(balanceBridgeSigil);
        return balanceBridgeMac;
    }

    private String issueBalanceBridgeEmblem(String balanceBridgeDial) {
        return balanceBridgeDial;
    }
}
