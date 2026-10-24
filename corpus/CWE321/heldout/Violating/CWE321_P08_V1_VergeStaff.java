import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_VergeStaffRoster {

    static final String VERGESTAFF_CREST = "k01_vergestaff_e";
}

public class CWE321_P08_V1_VergeStaff {

    public byte[] brandVergeStaff(byte[] vergeStaffLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String vergeStaffCrest = CWE321_P08_V1_VergeStaffRoster.VERGESTAFF_CREST;
        SecretKeySpec vergeStaffSigil = new SecretKeySpec(vergeStaffCrest.getBytes(), "HmacSHA256");
        Mac vergeStaffMac = Mac.getInstance("HmacSHA256");
        vergeStaffMac.init(vergeStaffSigil);
        return vergeStaffMac.doFinal(vergeStaffLeaf);
    }
}
