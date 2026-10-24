import java.util.logging.Logger;

public class CWE117_P12_V2_CobaltRaven {
    private static int privateFive = 5;

    public void handleCobaltRaven() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("COBALT_RAVEN_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CobaltRavenBase baseObject = new CWE117_P12_V2_CobaltRavenSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CobaltRavenBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CobaltRavenSink extends CWE117_P12_V2_CobaltRavenBase {
    public void action(String data) {
        Logger cobaltRavenLogger = Logger.getLogger("cobaltRaven.audit");
        cobaltRavenLogger.info("Login attempt for user " + data);
    }
}
