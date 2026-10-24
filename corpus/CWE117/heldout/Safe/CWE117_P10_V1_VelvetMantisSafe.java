import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetMantisSafe {

    public static String data;

    public void handleVelvetMantis() {
        data = System.getenv("VELVET_MANTIS_USER");
        (new CWE117_P10_V1_VelvetMantisSafeSink()).logVelvetMantis();
    }
}

class CWE117_P10_V1_VelvetMantisSafeSink {
    public void logVelvetMantis() {
        String data = CWE117_P10_V1_VelvetMantisSafe.data;
        Logger velvetMantisLogger = Logger.getLogger("velvetMantis.audit");
        velvetMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
