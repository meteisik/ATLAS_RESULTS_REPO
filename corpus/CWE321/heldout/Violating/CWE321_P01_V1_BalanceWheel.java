import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_BalanceWheel {

    public SecretKeySpec mintBalanceWheelSigil() {
        String balanceWheelBadge = "k12_balancewheel";
        byte[] balanceWheelFilament = balanceWheelBadge.getBytes();
        SecretKeySpec balanceWheelSigil = new SecretKeySpec(balanceWheelFilament, "AES");
        return balanceWheelSigil;
    }
}
