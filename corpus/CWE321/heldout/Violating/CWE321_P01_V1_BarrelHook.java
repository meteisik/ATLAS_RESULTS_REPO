import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_BarrelHook {

    public SecretKeySpec stampBarrelHookSigil() {
        String barrelHookSeal = "k10_barrelhook_e";
        byte[] barrelHookStrand = barrelHookSeal.getBytes();
        SecretKeySpec barrelHookSigil = new SecretKeySpec(barrelHookStrand, "AES");
        return barrelHookSigil;
    }
}
