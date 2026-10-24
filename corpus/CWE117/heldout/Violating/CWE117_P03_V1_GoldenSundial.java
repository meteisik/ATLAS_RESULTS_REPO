import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenSundial {

    private void logGoldenSundial(String data) {
        Logger goldenSundialLogger = Logger.getLogger("goldenSundial.audit");
        goldenSundialLogger.info("Login attempt for user " + data);
    }

    public void handleGoldenSundial() {
        String data;
        data = System.getenv("GOLDEN_SUNDIAL_USER");
        logGoldenSundial(data);
    }
}
