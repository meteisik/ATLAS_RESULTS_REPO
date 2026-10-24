import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_EquationCamRoster {

    static final String EQUATIONCAM_CHARM = "k18_equationcam_";
}

public class CWE321_P08_V1_EquationCam {

    public byte[] brandEquationCam(byte[] equationCamLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String equationCamCharm = CWE321_P08_V1_EquationCamRoster.EQUATIONCAM_CHARM;
        SecretKeySpec equationCamSigil = new SecretKeySpec(equationCamCharm.getBytes(), "HmacSHA256");
        Mac equationCamMac = Mac.getInstance("HmacSHA256");
        equationCamMac.init(equationCamSigil);
        return equationCamMac.doFinal(equationCamLeaf);
    }
}
