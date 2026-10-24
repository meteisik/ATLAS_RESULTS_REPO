import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_YokeSpring {

    public SecretKeySpec stampYokeSpringSigil() {
        String yokeSpringSeal = "k20_yokespring_e";
        return temperYokeSpring(yokeSpringSeal);
    }

    private SecretKeySpec temperYokeSpring(String yokeSpringPacket) {
        byte[] yokeSpringStrand = yokeSpringPacket.getBytes();
        return new SecretKeySpec(yokeSpringStrand, "AES");
    }
}
