import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_VergeStaffSafeRoster {

    static final String VERGESTAFF_CREST = mintVergeStaffCrest();

    private static String mintVergeStaffCrest() {
        byte[] vergeStaffGrain = new byte[16];
        new SecureRandom().nextBytes(vergeStaffGrain);
        return Base64.getEncoder().encodeToString(vergeStaffGrain);
    }
}

public class CWE321_P08_V1_VergeStaffSafe {

    public byte[] brandVergeStaff(byte[] vergeStaffLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String vergeStaffCrest = CWE321_P08_V1_VergeStaffSafeRoster.VERGESTAFF_CREST;
        SecretKeySpec vergeStaffSigil = new SecretKeySpec(vergeStaffCrest.getBytes(), "HmacSHA256");
        Mac vergeStaffMac = Mac.getInstance("HmacSHA256");
        vergeStaffMac.init(vergeStaffSigil);
        return vergeStaffMac.doFinal(vergeStaffLeaf);
    }
}
