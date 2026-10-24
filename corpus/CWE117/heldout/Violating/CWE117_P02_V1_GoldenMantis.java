import java.util.logging.Logger;

public class CWE117_P02_V1_GoldenMantis {

    public void handleGoldenMantis() {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_MANTIS_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger goldenMantisLogger = Logger.getLogger("goldenMantis.audit");
            goldenMantisLogger.info("Login attempt for user " + data);
        }
    }
}
