import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetMantisSafe {

    public void handleVelvetMantis() {
        String data;
        data = System.getenv("VELVET_MANTIS_USER");
        CWE117_P12_V1_VelvetMantisSafeBase baseObject = new CWE117_P12_V1_VelvetMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetMantisSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetMantisSafeSink extends CWE117_P12_V1_VelvetMantisSafeBase {
    public void action(String data) {
        Logger velvetMantisLogger = Logger.getLogger("velvetMantis.audit");
        velvetMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
