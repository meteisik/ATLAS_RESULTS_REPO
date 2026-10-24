import java.util.logging.Logger;

public class CWE117_P12_V1_AmberGlint {

    public void handleAmberGlint() {
        String data;
        data = System.getenv("AMBER_GLINT_USER");
        CWE117_P12_V1_AmberGlintBase baseObject = new CWE117_P12_V1_AmberGlintSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberGlintBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberGlintSink extends CWE117_P12_V1_AmberGlintBase {
    public void action(String data) {
        Logger amberGlintLogger = Logger.getLogger("amberGlint.audit");
        amberGlintLogger.info("Login attempt for user " + data);
    }
}
