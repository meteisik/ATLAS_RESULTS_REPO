import java.util.logging.Logger;

public class CWE117_P05_V1_GoldenSundial {

    private String goldenSundialData;

    private void logGoldenSundial() {
        String data = goldenSundialData;
        Logger goldenSundialLogger = Logger.getLogger("goldenSundial.audit");
        goldenSundialLogger.info("Login attempt for user " + data);
    }

    public void handleGoldenSundial() {
        String data;
        data = System.getenv("GOLDEN_SUNDIAL_USER");
        goldenSundialData = data;
        logGoldenSundial();
    }
}
