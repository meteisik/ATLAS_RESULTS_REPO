import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetSundial {

    public void handleVelvetSundial() {
        String data;
        data = System.getenv("VELVET_SUNDIAL_USER");
        CWE117_P12_V1_VelvetSundialBase baseObject = new CWE117_P12_V1_VelvetSundialSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetSundialBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetSundialSink extends CWE117_P12_V1_VelvetSundialBase {
    public void action(String data) {
        Logger velvetSundialLogger = Logger.getLogger("velvetSundial.audit");
        velvetSundialLogger.info("Login attempt for user " + data);
    }
}
