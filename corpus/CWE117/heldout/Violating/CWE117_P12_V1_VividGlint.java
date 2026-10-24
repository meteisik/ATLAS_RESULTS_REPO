import java.util.logging.Logger;

public class CWE117_P12_V1_VividGlint {

    public void handleVividGlint() {
        String data;
        data = System.getenv("VIVID_GLINT_USER");
        CWE117_P12_V1_VividGlintBase baseObject = new CWE117_P12_V1_VividGlintSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VividGlintBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VividGlintSink extends CWE117_P12_V1_VividGlintBase {
    public void action(String data) {
        Logger vividGlintLogger = Logger.getLogger("vividGlint.audit");
        vividGlintLogger.info("Login attempt for user " + data);
    }
}
