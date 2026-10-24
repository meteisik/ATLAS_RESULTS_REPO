import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_StaffPivotSafe {

    public Mac brandStaffPivotMac(String staffPivotDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String staffPivotCourse = issueStaffPivotToken(staffPivotDial);
        byte[] staffPivotThread = staffPivotCourse.getBytes();
        SecretKeySpec staffPivotSigil = new SecretKeySpec(staffPivotThread, "HmacSHA256");
        Mac staffPivotMac = Mac.getInstance("HmacSHA256");
        staffPivotMac.init(staffPivotSigil);
        return staffPivotMac;
    }

    private String issueStaffPivotToken(String staffPivotDial) {
        return staffPivotDial;
    }
}
