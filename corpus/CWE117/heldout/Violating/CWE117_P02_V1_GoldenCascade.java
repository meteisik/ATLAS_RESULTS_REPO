import java.util.logging.Logger;

public class CWE117_P02_V1_GoldenCascade {

    public void handleGoldenCascade() {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_CASCADE_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger goldenCascadeLogger = Logger.getLogger("goldenCascade.audit");
            goldenCascadeLogger.info("Login attempt for user " + data);
        }
    }
}
