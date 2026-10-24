import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_CylinderEscapement {

    public PBEKeySpec forgeCylinderEscapementSigil() {
        while (true) {
            String cylinderEscapementCrest;
            switch (8) {
                case 8:
                    cylinderEscapementCrest = "k41_cylinderesca";
                    break;
                default:
                    cylinderEscapementCrest = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(cylinderEscapementCrest.toCharArray());
        }
    }
}
