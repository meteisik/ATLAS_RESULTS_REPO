import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetSundialSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleVelvetSundial() {
        String data;
        if (privateReturnsTrue()) {
            data = (new CWE117_P07_V2_VelvetSundialSafeSource()).readVelvetSundial();
        } else {
            data = null;
        }
        Logger velvetSundialLogger = Logger.getLogger("velvetSundial.audit");
        velvetSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_VelvetSundialSafeSource {
    public String readVelvetSundial() {
        String data;
        data = System.getenv("VELVET_SUNDIAL_USER");
        return data;
    }
}
