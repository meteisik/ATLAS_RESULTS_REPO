import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_BarrelHookSafe {

    public SecretKeySpec stampBarrelHookSigil(String barrelHookDial) {
        String barrelHookSeal = barrelHookDial;
        byte[] barrelHookStrand = barrelHookSeal.getBytes();
        SecretKeySpec barrelHookSigil = new SecretKeySpec(barrelHookStrand, "AES");
        return barrelHookSigil;
    }
}
