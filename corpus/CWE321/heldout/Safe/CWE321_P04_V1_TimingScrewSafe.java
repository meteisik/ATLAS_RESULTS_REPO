import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_TimingScrewSafe {

    public SecretKeySpec strikeTimingScrewSigil(String timingScrewDial) {
        String timingScrewMotif = timingScrewDial;
        return temperTimingScrew(timingScrewMotif);
    }

    private SecretKeySpec temperTimingScrew(String timingScrewPacket) {
        byte[] timingScrewFibre = timingScrewPacket.getBytes();
        return new SecretKeySpec(timingScrewFibre, "AES");
    }
}
