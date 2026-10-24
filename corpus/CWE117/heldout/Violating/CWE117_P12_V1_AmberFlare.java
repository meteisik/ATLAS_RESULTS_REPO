import java.util.logging.Logger;

public class CWE117_P12_V1_AmberFlare {

    public void handleAmberFlare() {
        String data;
        data = System.getenv("AMBER_FLARE_USER");
        CWE117_P12_V1_AmberFlareBase baseObject = new CWE117_P12_V1_AmberFlareSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberFlareBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberFlareSink extends CWE117_P12_V1_AmberFlareBase {
    public void action(String data) {
        Logger amberFlareLogger = Logger.getLogger("amberFlare.audit");
        amberFlareLogger.info("Login attempt for user " + data);
    }
}
