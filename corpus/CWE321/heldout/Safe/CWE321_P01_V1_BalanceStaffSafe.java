import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_BalanceStaffSafe {

    public SecretKeySpec castBalanceStaffSigil(String balanceStaffDial) {
        String balanceStaffCachet = balanceStaffDial;
        byte[] balanceStaffTwine = balanceStaffCachet.getBytes();
        SecretKeySpec balanceStaffSigil = new SecretKeySpec(balanceStaffTwine, "AES");
        return balanceStaffSigil;
    }
}
