import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetSundialSafe {

    public static String data;

    public void handleVelvetSundial() {
        data = System.getenv("VELVET_SUNDIAL_USER");
        (new CWE117_P10_V1_VelvetSundialSafeSink()).logVelvetSundial();
    }
}

class CWE117_P10_V1_VelvetSundialSafeSink {
    public void logVelvetSundial() {
        String data = CWE117_P10_V1_VelvetSundialSafe.data;
        Logger velvetSundialLogger = Logger.getLogger("velvetSundial.audit");
        velvetSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
