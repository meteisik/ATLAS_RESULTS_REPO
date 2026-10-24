import java.util.logging.Logger;

public class CWE117_P12_V1_VividSundial {

    public void handleVividSundial() {
        String data;
        data = System.getenv("VIVID_SUNDIAL_USER");
        CWE117_P12_V1_VividSundialBase baseObject = new CWE117_P12_V1_VividSundialSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VividSundialBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VividSundialSink extends CWE117_P12_V1_VividSundialBase {
    public void action(String data) {
        Logger vividSundialLogger = Logger.getLogger("vividSundial.audit");
        vividSundialLogger.info("Login attempt for user " + data);
    }
}
