import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_EquationCamSafeRoster {

    static final String EQUATIONCAM_CHARM = mintEquationCamCharm();

    private static String mintEquationCamCharm() {
        byte[] equationCamGrain = new byte[16];
        new SecureRandom().nextBytes(equationCamGrain);
        return Base64.getEncoder().encodeToString(equationCamGrain);
    }
}

public class CWE321_P08_V1_EquationCamSafe {

    public byte[] brandEquationCam(byte[] equationCamLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String equationCamCharm = CWE321_P08_V1_EquationCamSafeRoster.EQUATIONCAM_CHARM;
        SecretKeySpec equationCamSigil = new SecretKeySpec(equationCamCharm.getBytes(), "HmacSHA256");
        Mac equationCamMac = Mac.getInstance("HmacSHA256");
        equationCamMac.init(equationCamSigil);
        return equationCamMac.doFinal(equationCamLeaf);
    }
}
