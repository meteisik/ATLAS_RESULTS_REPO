import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetFlare {

    public void handleVelvetFlare() {
        String data;
        data = System.getenv("VELVET_FLARE_USER");
        CWE117_P12_V1_VelvetFlareBase baseObject = new CWE117_P12_V1_VelvetFlareSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetFlareBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetFlareSink extends CWE117_P12_V1_VelvetFlareBase {
    public void action(String data) {
        Logger velvetFlareLogger = Logger.getLogger("velvetFlare.audit");
        velvetFlareLogger.info("Login attempt for user " + data);
    }
}
