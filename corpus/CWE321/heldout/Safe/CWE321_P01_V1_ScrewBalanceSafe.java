import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_ScrewBalanceSafe {

    public SecretKeySpec brandScrewBalanceSigil(String screwBalanceDial) {
        String screwBalanceToken = screwBalanceDial;
        byte[] screwBalanceThread = screwBalanceToken.getBytes();
        SecretKeySpec screwBalanceSigil = new SecretKeySpec(screwBalanceThread, "AES");
        return screwBalanceSigil;
    }
}
