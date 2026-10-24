import java.util.logging.Logger;

public class CWE117_P02_V1_GoldenGlint {

    public void handleGoldenGlint() {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_GLINT_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger goldenGlintLogger = Logger.getLogger("goldenGlint.audit");
            goldenGlintLogger.info("Login attempt for user " + data);
        }
    }
}
