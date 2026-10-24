import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_BalanceStaffSafe {

    public SecretKeySpec punchBalanceStaffSigil(String balanceStaffDial) {
        String balanceStaffCharm = balanceStaffDial;
        return temperBalanceStaff(balanceStaffCharm);
    }

    private SecretKeySpec temperBalanceStaff(String balanceStaffPacket) {
        byte[] balanceStaffLace = balanceStaffPacket.getBytes();
        return new SecretKeySpec(balanceStaffLace, "AES");
    }
}
