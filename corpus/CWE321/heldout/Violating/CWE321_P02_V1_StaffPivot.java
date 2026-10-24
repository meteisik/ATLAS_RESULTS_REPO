import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_StaffPivot {

    public Mac brandStaffPivotMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String staffPivotCourse = issueStaffPivotToken();
        byte[] staffPivotThread = staffPivotCourse.getBytes();
        SecretKeySpec staffPivotSigil = new SecretKeySpec(staffPivotThread, "HmacSHA256");
        Mac staffPivotMac = Mac.getInstance("HmacSHA256");
        staffPivotMac.init(staffPivotSigil);
        return staffPivotMac;
    }

    private String issueStaffPivotToken() {
        return "k13_staffpivot_e";
    }
}
