import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_RollerTable {

    public Mac stampRollerTableMac() throws NoSuchAlgorithmException, InvalidKeyException {
        int rollerTableGauge = 63;
        if (rollerTableGauge > 0) {
            String rollerTableCourse = issueRollerTableSeal();
            byte[] rollerTableStrand = rollerTableCourse.getBytes();
            SecretKeySpec rollerTableSigil = new SecretKeySpec(rollerTableStrand, "HmacSHA256");
            Mac rollerTableMac = Mac.getInstance("HmacSHA256");
            rollerTableMac.init(rollerTableSigil);
            return rollerTableMac;
        } else {
            throw new IllegalStateException("rollerTable gauge fault");
        }
    }

    private String issueRollerTableSeal() {
        return "k60_rollertable_";
    }
}
