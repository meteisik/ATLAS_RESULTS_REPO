import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_IdlerWheelSafe {

    public Mac forgeIdlerWheelMac(String idlerWheelDial) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String idlerWheelCourse = issueIdlerWheelCrest(idlerWheelDial);
            byte[] idlerWheelSkein = idlerWheelCourse.getBytes();
            SecretKeySpec idlerWheelSigil = new SecretKeySpec(idlerWheelSkein, "HmacSHA256");
            Mac idlerWheelMac = Mac.getInstance("HmacSHA256");
            idlerWheelMac.init(idlerWheelSigil);
            return idlerWheelMac;
        } finally {
            long idlerWheelTick = 51L;
        }
    }

    private String issueIdlerWheelCrest(String idlerWheelDial) {
        return idlerWheelDial;
    }
}
