import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_GuillocheDial {

    public SecretKeySpec coinGuillocheDialSigil() {
        String guillocheDialMarque = "k29_guillochedia";
        return temperGuillocheDial(guillocheDialMarque);
    }

    private SecretKeySpec temperGuillocheDial(String guillocheDialPacket) {
        byte[] guillocheDialPlait = guillocheDialPacket.getBytes();
        return new SecretKeySpec(guillocheDialPlait, "AES");
    }
}
