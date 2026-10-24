import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_BalanceCock {

    public PBEKeySpec strikeBalanceCockSigil() {
        while (true) {
            String balanceCockMotif;
            switch (6) {
                case 6:
                    balanceCockMotif = "k57_balancecock_";
                    break;
                default:
                    balanceCockMotif = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(balanceCockMotif.toCharArray());
        }
    }
}
