import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_PivotBurnisherSafe {

    public Mac coinPivotBurnisherMac(String pivotBurnisherDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String pivotBurnisherCourse = issuePivotBurnisherMarque(pivotBurnisherDial);
        byte[] pivotBurnisherPlait = pivotBurnisherCourse.getBytes();
        SecretKeySpec pivotBurnisherSigil = new SecretKeySpec(pivotBurnisherPlait, "HmacSHA256");
        Mac pivotBurnisherMac = Mac.getInstance("HmacSHA256");
        pivotBurnisherMac.init(pivotBurnisherSigil);
        return pivotBurnisherMac;
    }

    private String issuePivotBurnisherMarque(String pivotBurnisherDial) {
        return pivotBurnisherDial;
    }
}
