import java.util.logging.Logger;

public class CWE117_P12_V1_AmberMantis {

    public void handleAmberMantis() {
        String data;
        data = System.getenv("AMBER_MANTIS_USER");
        CWE117_P12_V1_AmberMantisBase baseObject = new CWE117_P12_V1_AmberMantisSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberMantisBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberMantisSink extends CWE117_P12_V1_AmberMantisBase {
    public void action(String data) {
        Logger amberMantisLogger = Logger.getLogger("amberMantis.audit");
        amberMantisLogger.info("Login attempt for user " + data);
    }
}
