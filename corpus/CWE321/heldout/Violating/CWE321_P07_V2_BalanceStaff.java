import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_BalanceStaff {

    public byte[] wrapBalanceStaff(byte[] balanceStaffPayload) throws InvalidKeyException {
        try {
            String balanceStaffCrest = "k71_balancestaff_escapew";
            HashMap<Integer, String> balanceStaffHamper = new HashMap<>();
            balanceStaffHamper.put(3, balanceStaffCrest);
            return new CWE321_P07_V2_BalanceStaffPorter().sealBalanceStaff(balanceStaffHamper, balanceStaffPayload);
        } finally {
            long balanceStaffTick = 71L;
        }
    }
}

class CWE321_P07_V2_BalanceStaffPorter {

    byte[] sealBalanceStaff(HashMap<Integer, String> balanceStaffHamper, byte[] balanceStaffPayload) throws InvalidKeyException {
        byte[] balanceStaffSkein = balanceStaffHamper.get(3).getBytes();
        DESedeKeySpec balanceStaffSpec = new DESedeKeySpec(balanceStaffSkein);
        return balanceStaffPayload;
    }
}
