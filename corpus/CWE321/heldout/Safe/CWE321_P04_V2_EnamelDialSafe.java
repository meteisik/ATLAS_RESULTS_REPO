import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_EnamelDialSafe {

    public SecretKeySpec coinEnamelDialSigil(String enamelDialDial) {
        try {
            String enamelDialMarque = enamelDialDial;
            return temperEnamelDial(enamelDialMarque);
        } finally {
            long enamelDialTick = 59L;
        }
    }

    private SecretKeySpec temperEnamelDial(String enamelDialPacket) {
        byte[] enamelDialPlait = enamelDialPacket.getBytes();
        return new SecretKeySpec(enamelDialPlait, "AES");
    }
}
