import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetSignalSafe {

    public void handleVelvetSignal() {
        String data;
        data = System.getenv("VELVET_SIGNAL_USER");
        CWE117_P12_V1_VelvetSignalSafeBase baseObject = new CWE117_P12_V1_VelvetSignalSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetSignalSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetSignalSafeSink extends CWE117_P12_V1_VelvetSignalSafeBase {
    public void action(String data) {
        Logger velvetSignalLogger = Logger.getLogger("velvetSignal.audit");
        velvetSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
