import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_EnamelDial {

    public SecretKeySpec coinEnamelDialSigil() {
        try {
            String enamelDialMarque = "k59_enameldial_e";
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
