import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonRaven {

    public void handleCrimsonRaven() {
        String data;
        if (true) {
            data = System.getenv("CRIMSON_RAVEN_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CrimsonRavenBase baseObject = new CWE117_P12_V2_CrimsonRavenSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonRavenBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonRavenSink extends CWE117_P12_V2_CrimsonRavenBase {
    public void action(String data) {
        Logger crimsonRavenLogger = Logger.getLogger("crimsonRaven.audit");
        crimsonRavenLogger.info("Login attempt for user " + data);
    }
}
