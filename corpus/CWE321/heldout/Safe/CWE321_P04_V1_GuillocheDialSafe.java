import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_GuillocheDialSafe {

    public SecretKeySpec coinGuillocheDialSigil(String guillocheDialDial) {
        String guillocheDialMarque = guillocheDialDial;
        return temperGuillocheDial(guillocheDialMarque);
    }

    private SecretKeySpec temperGuillocheDial(String guillocheDialPacket) {
        byte[] guillocheDialPlait = guillocheDialPacket.getBytes();
        return new SecretKeySpec(guillocheDialPlait, "AES");
    }
}
