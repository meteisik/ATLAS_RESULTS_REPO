import java.util.logging.Logger;

public class CWE117_P04_V1_GoldenMantis {

    private String readGoldenMantis() {
        String data;
        data = System.getenv("GOLDEN_MANTIS_USER");
        return data;
    }

    public void handleGoldenMantis() {
        String data = readGoldenMantis();
        Logger goldenMantisLogger = Logger.getLogger("goldenMantis.audit");
        goldenMantisLogger.info("Login attempt for user " + data);
    }
}
