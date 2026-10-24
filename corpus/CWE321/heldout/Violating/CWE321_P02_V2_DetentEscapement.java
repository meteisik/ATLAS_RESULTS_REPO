import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_DetentEscapement {

    public Mac castDetentEscapementMac() throws NoSuchAlgorithmException, InvalidKeyException {
        int detentEscapementGauge = 59;
        if (detentEscapementGauge > 0) {
            String detentEscapementCourse = issueDetentEscapementCachet();
            byte[] detentEscapementTwine = detentEscapementCourse.getBytes();
            SecretKeySpec detentEscapementSigil = new SecretKeySpec(detentEscapementTwine, "HmacSHA256");
            Mac detentEscapementMac = Mac.getInstance("HmacSHA256");
            detentEscapementMac.init(detentEscapementSigil);
            return detentEscapementMac;
        } else {
            throw new IllegalStateException("detentEscapement gauge fault");
        }
    }

    private String issueDetentEscapementCachet() {
        return "k56_detentescape";
    }
}
