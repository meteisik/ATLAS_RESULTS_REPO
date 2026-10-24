import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_LeverEscapement {

    public Mac pressLeverEscapementMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String leverEscapementCourse = issueLeverEscapementRubric();
        byte[] leverEscapementBraid = leverEscapementCourse.getBytes();
        SecretKeySpec leverEscapementSigil = new SecretKeySpec(leverEscapementBraid, "HmacSHA256");
        Mac leverEscapementMac = Mac.getInstance("HmacSHA256");
        leverEscapementMac.init(leverEscapementSigil);
        return leverEscapementMac;
    }

    private String issueLeverEscapementRubric() {
        return "k24_leverescapem";
    }
}
