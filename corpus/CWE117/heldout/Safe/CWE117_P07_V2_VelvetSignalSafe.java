import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetSignalSafe {
    private static int privateFive = 5;

    public void handleVelvetSignal() {
        String data;
        if (privateFive == 5) {
            data = (new CWE117_P07_V2_VelvetSignalSafeSource()).readVelvetSignal();
        } else {
            data = null;
        }
        Logger velvetSignalLogger = Logger.getLogger("velvetSignal.audit");
        velvetSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_VelvetSignalSafeSource {
    public String readVelvetSignal() {
        String data;
        data = System.getenv("VELVET_SIGNAL_USER");
        return data;
    }
}
