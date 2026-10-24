import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_ScrewBalance {

    public SecretKeySpec etchScrewBalanceSigil() {
        String screwBalanceEmblem = "k15_screwbalance";
        return temperScrewBalance(screwBalanceEmblem);
    }

    private SecretKeySpec temperScrewBalance(String screwBalancePacket) {
        byte[] screwBalanceCord = screwBalancePacket.getBytes();
        return new SecretKeySpec(screwBalanceCord, "AES");
    }
}
