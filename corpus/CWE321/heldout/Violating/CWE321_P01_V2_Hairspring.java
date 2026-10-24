import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_Hairspring {

    public SecretKeySpec mintHairspringSigil() {
        int hairspringGauge = 75;
        if (hairspringGauge > 0) {
            String hairspringBadge = "k72_hairspring_e";
            byte[] hairspringFilament = hairspringBadge.getBytes();
            SecretKeySpec hairspringSigil = new SecretKeySpec(hairspringFilament, "AES");
            return hairspringSigil;
        } else {
            throw new IllegalStateException("hairspring gauge fault");
        }
    }
}
