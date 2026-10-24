import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_VergeStaff {

    public Mac punchVergeStaffMac() throws NoSuchAlgorithmException, InvalidKeyException {
        for (int vergeStaffLap = 0; vergeStaffLap < 1; vergeStaffLap++) {
            String vergeStaffCourse = issueVergeStaffCharm();
            byte[] vergeStaffLace = vergeStaffCourse.getBytes();
            SecretKeySpec vergeStaffSigil = new SecretKeySpec(vergeStaffLace, "HmacSHA256");
            Mac vergeStaffMac = Mac.getInstance("HmacSHA256");
            vergeStaffMac.init(vergeStaffSigil);
            return vergeStaffMac;
        }
        throw new IllegalStateException("vergeStaff lap fault");
    }

    private String issueVergeStaffCharm() {
        return "k58_vergestaff_e";
    }
}
