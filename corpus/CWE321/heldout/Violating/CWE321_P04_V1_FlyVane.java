import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_FlyVane {

    public SecretKeySpec forgeFlyVaneSigil() {
        String flyVaneCrest = "k21_flyvane_esca";
        return temperFlyVane(flyVaneCrest);
    }

    private SecretKeySpec temperFlyVane(String flyVanePacket) {
        byte[] flyVaneSkein = flyVanePacket.getBytes();
        return new SecretKeySpec(flyVaneSkein, "AES");
    }
}
