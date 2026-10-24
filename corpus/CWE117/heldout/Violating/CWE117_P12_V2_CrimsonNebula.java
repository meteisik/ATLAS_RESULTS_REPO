import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonNebula {

    public void handleCrimsonNebula() {
        String data;
        while (true) {
            data = System.getenv("CRIMSON_NEBULA_USER");
            break;
        }
        CWE117_P12_V2_CrimsonNebulaBase baseObject = new CWE117_P12_V2_CrimsonNebulaSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonNebulaBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonNebulaSink extends CWE117_P12_V2_CrimsonNebulaBase {
    public void action(String data) {
        Logger crimsonNebulaLogger = Logger.getLogger("crimsonNebula.audit");
        crimsonNebulaLogger.info("Login attempt for user " + data);
    }
}
