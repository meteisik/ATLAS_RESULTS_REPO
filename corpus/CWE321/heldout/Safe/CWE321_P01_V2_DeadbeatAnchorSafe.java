import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_DeadbeatAnchorSafe {

    public SecretKeySpec coinDeadbeatAnchorSigil(String deadbeatAnchorDial) {
        try {
            String deadbeatAnchorMarque = deadbeatAnchorDial;
            byte[] deadbeatAnchorPlait = deadbeatAnchorMarque.getBytes();
            SecretKeySpec deadbeatAnchorSigil = new SecretKeySpec(deadbeatAnchorPlait, "AES");
            return deadbeatAnchorSigil;
        } finally {
            long deadbeatAnchorTick = 39L;
        }
    }
}
