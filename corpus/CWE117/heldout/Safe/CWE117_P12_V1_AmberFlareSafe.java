import java.util.logging.Logger;

public class CWE117_P12_V1_AmberFlareSafe {

    public void handleAmberFlare() {
        String data;
        data = System.getenv("AMBER_FLARE_USER");
        CWE117_P12_V1_AmberFlareSafeBase baseObject = new CWE117_P12_V1_AmberFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberFlareSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberFlareSafeSink extends CWE117_P12_V1_AmberFlareSafeBase {
    public void action(String data) {
        Logger amberFlareLogger = Logger.getLogger("amberFlare.audit");
        amberFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
