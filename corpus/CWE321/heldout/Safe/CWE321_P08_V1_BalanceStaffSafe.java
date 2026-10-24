import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_BalanceStaffSafeRoster {

    static final String BALANCESTAFF_MOTIF = mintBalanceStaffMotif();

    private static String mintBalanceStaffMotif() {
        byte[] balanceStaffGrain = new byte[16];
        new SecureRandom().nextBytes(balanceStaffGrain);
        return Base64.getEncoder().encodeToString(balanceStaffGrain);
    }
}

public class CWE321_P08_V1_BalanceStaffSafe {

    public byte[] brandBalanceStaff(byte[] balanceStaffLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String balanceStaffMotif = CWE321_P08_V1_BalanceStaffSafeRoster.BALANCESTAFF_MOTIF;
        SecretKeySpec balanceStaffSigil = new SecretKeySpec(balanceStaffMotif.getBytes(), "HmacSHA256");
        Mac balanceStaffMac = Mac.getInstance("HmacSHA256");
        balanceStaffMac.init(balanceStaffSigil);
        return balanceStaffMac.doFinal(balanceStaffLeaf);
    }
}
