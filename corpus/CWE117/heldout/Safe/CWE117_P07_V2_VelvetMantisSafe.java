import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetMantisSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleVelvetMantis() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = (new CWE117_P07_V2_VelvetMantisSafeSource()).readVelvetMantis();
        } else {
            data = null;
        }
        Logger velvetMantisLogger = Logger.getLogger("velvetMantis.audit");
        velvetMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_VelvetMantisSafeSource {
    public String readVelvetMantis() {
        String data;
        data = System.getenv("VELVET_MANTIS_USER");
        return data;
    }
}
