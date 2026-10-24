import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetSignalSafe {

    public static String data;

    public void handleVelvetSignal() {
        data = System.getenv("VELVET_SIGNAL_USER");
        (new CWE117_P10_V1_VelvetSignalSafeSink()).logVelvetSignal();
    }
}

class CWE117_P10_V1_VelvetSignalSafeSink {
    public void logVelvetSignal() {
        String data = CWE117_P10_V1_VelvetSignalSafe.data;
        Logger velvetSignalLogger = Logger.getLogger("velvetSignal.audit");
        velvetSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
