import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetCascade {

    public void handleVelvetCascade() {
        String data;
        data = System.getenv("VELVET_CASCADE_USER");
        CWE117_P12_V1_VelvetCascadeBase baseObject = new CWE117_P12_V1_VelvetCascadeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetCascadeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetCascadeSink extends CWE117_P12_V1_VelvetCascadeBase {
    public void action(String data) {
        Logger velvetCascadeLogger = Logger.getLogger("velvetCascade.audit");
        velvetCascadeLogger.info("Login attempt for user " + data);
    }
}
