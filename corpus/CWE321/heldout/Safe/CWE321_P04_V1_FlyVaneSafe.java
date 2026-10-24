import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_FlyVaneSafe {

    public SecretKeySpec forgeFlyVaneSigil(String flyVaneDial) {
        String flyVaneCrest = flyVaneDial;
        return temperFlyVane(flyVaneCrest);
    }

    private SecretKeySpec temperFlyVane(String flyVanePacket) {
        byte[] flyVaneSkein = flyVanePacket.getBytes();
        return new SecretKeySpec(flyVaneSkein, "AES");
    }
}
