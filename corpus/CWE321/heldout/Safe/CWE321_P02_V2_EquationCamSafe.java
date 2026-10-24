import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_EquationCamSafe {

    public Mac coinEquationCamMac(String equationCamDial) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String equationCamCourse = issueEquationCamMarque(equationCamDial);
            byte[] equationCamPlait = equationCamCourse.getBytes();
            SecretKeySpec equationCamSigil = new SecretKeySpec(equationCamPlait, "HmacSHA256");
            Mac equationCamMac = Mac.getInstance("HmacSHA256");
            equationCamMac.init(equationCamSigil);
            return equationCamMac;
        }
    }

    private String issueEquationCamMarque(String equationCamDial) {
        return equationCamDial;
    }
}
