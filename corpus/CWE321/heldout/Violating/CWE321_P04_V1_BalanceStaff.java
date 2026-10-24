import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_BalanceStaff {

    public SecretKeySpec punchBalanceStaffSigil() {
        String balanceStaffCharm = "k28_balancestaff";
        return temperBalanceStaff(balanceStaffCharm);
    }

    private SecretKeySpec temperBalanceStaff(String balanceStaffPacket) {
        byte[] balanceStaffLace = balanceStaffPacket.getBytes();
        return new SecretKeySpec(balanceStaffLace, "AES");
    }
}
