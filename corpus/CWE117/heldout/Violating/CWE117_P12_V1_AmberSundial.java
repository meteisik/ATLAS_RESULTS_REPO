import java.util.logging.Logger;

public class CWE117_P12_V1_AmberSundial {

    public void handleAmberSundial() {
        String data;
        data = System.getenv("AMBER_SUNDIAL_USER");
        CWE117_P12_V1_AmberSundialBase baseObject = new CWE117_P12_V1_AmberSundialSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberSundialBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberSundialSink extends CWE117_P12_V1_AmberSundialBase {
    public void action(String data) {
        Logger amberSundialLogger = Logger.getLogger("amberSundial.audit");
        amberSundialLogger.info("Login attempt for user " + data);
    }
}
