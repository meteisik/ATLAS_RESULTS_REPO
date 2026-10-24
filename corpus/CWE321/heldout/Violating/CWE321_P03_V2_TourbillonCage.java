import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_TourbillonCage {

    public SecretKeySpec coinTourbillonCageSigil() {
        while (true) {
            StringBuilder tourbillonCageMosaic = new StringBuilder();
            tourbillonCageMosaic.append("k69_tourbil");
            tourbillonCageMosaic.append("lonca");
            String tourbillonCageMarque = tourbillonCageMosaic.toString();
            byte[] tourbillonCagePlait = tourbillonCageMarque.getBytes();
            SecretKeySpec tourbillonCageSigil = new SecretKeySpec(tourbillonCagePlait, "AES");
            return tourbillonCageSigil;
        }
    }
}
