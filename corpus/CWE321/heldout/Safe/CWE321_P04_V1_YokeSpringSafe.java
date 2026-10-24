import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_YokeSpringSafe {

    public SecretKeySpec stampYokeSpringSigil(String yokeSpringDial) {
        String yokeSpringSeal = yokeSpringDial;
        return temperYokeSpring(yokeSpringSeal);
    }

    private SecretKeySpec temperYokeSpring(String yokeSpringPacket) {
        byte[] yokeSpringStrand = yokeSpringPacket.getBytes();
        return new SecretKeySpec(yokeSpringStrand, "AES");
    }
}
