import java.util.logging.Logger;

public class CWE117_P12_V1_AmberCascade {

    public void handleAmberCascade() {
        String data;
        data = System.getenv("AMBER_CASCADE_USER");
        CWE117_P12_V1_AmberCascadeBase baseObject = new CWE117_P12_V1_AmberCascadeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberCascadeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberCascadeSink extends CWE117_P12_V1_AmberCascadeBase {
    public void action(String data) {
        Logger amberCascadeLogger = Logger.getLogger("amberCascade.audit");
        amberCascadeLogger.info("Login attempt for user " + data);
    }
}
