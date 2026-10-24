import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_LeverEscapementSafe {

    public Mac pressLeverEscapementMac(String leverEscapementDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String leverEscapementCourse = issueLeverEscapementRubric(leverEscapementDial);
        byte[] leverEscapementBraid = leverEscapementCourse.getBytes();
        SecretKeySpec leverEscapementSigil = new SecretKeySpec(leverEscapementBraid, "HmacSHA256");
        Mac leverEscapementMac = Mac.getInstance("HmacSHA256");
        leverEscapementMac.init(leverEscapementSigil);
        return leverEscapementMac;
    }

    private String issueLeverEscapementRubric(String leverEscapementDial) {
        return leverEscapementDial;
    }
}
