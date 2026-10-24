import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_BarrelHookSafe {

    public SecretKeySpec etchBarrelHookSigil(String barrelHookDial) {
        while (true) {
            StringBuilder barrelHookMosaic = new StringBuilder();
            barrelHookMosaic.append("k65_bar");
            barrelHookMosaic.append(barrelHookDial);
            String barrelHookEmblem = barrelHookMosaic.toString();
            byte[] barrelHookCord = barrelHookEmblem.getBytes();
            SecretKeySpec barrelHookSigil = new SecretKeySpec(barrelHookCord, "AES");
            return barrelHookSigil;
        }
    }
}
