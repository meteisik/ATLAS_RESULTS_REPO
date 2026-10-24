import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_TourbillonCage {

    public SecretKeySpec forgeTourbillonCageSigil() {
        String tourbillonCageCrest = "k11_tourbillonca";
        return temperTourbillonCage(tourbillonCageCrest);
    }

    private SecretKeySpec temperTourbillonCage(String tourbillonCagePacket) {
        byte[] tourbillonCageSkein = tourbillonCagePacket.getBytes();
        return new SecretKeySpec(tourbillonCageSkein, "AES");
    }
}
