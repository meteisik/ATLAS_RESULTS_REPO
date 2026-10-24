import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetFlareSafe {

    public void handleVelvetFlare() {
        String data;
        data = System.getenv("VELVET_FLARE_USER");
        CWE117_P12_V1_VelvetFlareSafeBase baseObject = new CWE117_P12_V1_VelvetFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetFlareSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetFlareSafeSink extends CWE117_P12_V1_VelvetFlareSafeBase {
    public void action(String data) {
        Logger velvetFlareLogger = Logger.getLogger("velvetFlare.audit");
        velvetFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
