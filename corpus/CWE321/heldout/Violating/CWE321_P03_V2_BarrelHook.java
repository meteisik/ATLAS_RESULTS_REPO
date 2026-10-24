import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_BarrelHook {

    public SecretKeySpec etchBarrelHookSigil() {
        while (true) {
            StringBuilder barrelHookMosaic = new StringBuilder();
            barrelHookMosaic.append("k65_bar");
            barrelHookMosaic.append("relhook_e");
            String barrelHookEmblem = barrelHookMosaic.toString();
            byte[] barrelHookCord = barrelHookEmblem.getBytes();
            SecretKeySpec barrelHookSigil = new SecretKeySpec(barrelHookCord, "AES");
            return barrelHookSigil;
        }
    }
}
