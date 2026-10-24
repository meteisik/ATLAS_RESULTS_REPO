import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_ScrewBalanceSafe {

    public SecretKeySpec etchScrewBalanceSigil(String screwBalanceDial) {
        String screwBalanceEmblem = screwBalanceDial;
        return temperScrewBalance(screwBalanceEmblem);
    }

    private SecretKeySpec temperScrewBalance(String screwBalancePacket) {
        byte[] screwBalanceCord = screwBalancePacket.getBytes();
        return new SecretKeySpec(screwBalanceCord, "AES");
    }
}
