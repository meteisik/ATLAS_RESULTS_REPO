import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_BarrelHook {

    public PBEKeySpec forgeBarrelHookSigil() {
        while (true) {
            String barrelHookCrest;
            switch (4) {
                case 4:
                    barrelHookCrest = "k61_barrelhook_e";
                    break;
                default:
                    barrelHookCrest = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(barrelHookCrest.toCharArray());
        }
    }
}
