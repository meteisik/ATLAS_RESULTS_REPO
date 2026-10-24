import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_TourbillonCageSafe {

    public SecretKeySpec forgeTourbillonCageSigil(String tourbillonCageDial) {
        String tourbillonCageCrest = tourbillonCageDial;
        return temperTourbillonCage(tourbillonCageCrest);
    }

    private SecretKeySpec temperTourbillonCage(String tourbillonCagePacket) {
        byte[] tourbillonCageSkein = tourbillonCagePacket.getBytes();
        return new SecretKeySpec(tourbillonCageSkein, "AES");
    }
}
