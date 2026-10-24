import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_TimingScrewSafe {

    public SecretKeySpec strikeTimingScrewSigil(String timingScrewDial) {
        while (true) {
            StringBuilder timingScrewMosaic = new StringBuilder();
            timingScrewMosaic.append("k57_ti");
            timingScrewMosaic.append(timingScrewDial);
            String timingScrewMotif = timingScrewMosaic.toString();
            byte[] timingScrewFibre = timingScrewMotif.getBytes();
            SecretKeySpec timingScrewSigil = new SecretKeySpec(timingScrewFibre, "AES");
            return timingScrewSigil;
        }
    }
}
