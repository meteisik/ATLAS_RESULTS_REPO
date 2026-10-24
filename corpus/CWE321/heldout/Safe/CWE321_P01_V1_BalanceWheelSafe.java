import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_BalanceWheelSafe {

    public SecretKeySpec mintBalanceWheelSigil(String balanceWheelDial) {
        String balanceWheelBadge = balanceWheelDial;
        byte[] balanceWheelFilament = balanceWheelBadge.getBytes();
        SecretKeySpec balanceWheelSigil = new SecretKeySpec(balanceWheelFilament, "AES");
        return balanceWheelSigil;
    }
}
