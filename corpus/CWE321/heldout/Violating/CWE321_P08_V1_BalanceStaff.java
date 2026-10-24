import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_BalanceStaffRoster {

    static final String BALANCESTAFF_MOTIF = "k07_balancestaff";
}

public class CWE321_P08_V1_BalanceStaff {

    public byte[] brandBalanceStaff(byte[] balanceStaffLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String balanceStaffMotif = CWE321_P08_V1_BalanceStaffRoster.BALANCESTAFF_MOTIF;
        SecretKeySpec balanceStaffSigil = new SecretKeySpec(balanceStaffMotif.getBytes(), "HmacSHA256");
        Mac balanceStaffMac = Mac.getInstance("HmacSHA256");
        balanceStaffMac.init(balanceStaffSigil);
        return balanceStaffMac.doFinal(balanceStaffLeaf);
    }
}
