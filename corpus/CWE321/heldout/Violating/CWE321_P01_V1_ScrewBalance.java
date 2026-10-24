import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_ScrewBalance {

    public SecretKeySpec brandScrewBalanceSigil() {
        String screwBalanceToken = "k33_screwbalance";
        byte[] screwBalanceThread = screwBalanceToken.getBytes();
        SecretKeySpec screwBalanceSigil = new SecretKeySpec(screwBalanceThread, "AES");
        return screwBalanceSigil;
    }
}
