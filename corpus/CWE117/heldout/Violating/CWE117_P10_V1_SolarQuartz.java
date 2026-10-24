import java.util.logging.Logger;

public class CWE117_P10_V1_SolarQuartz {

    public static String data;

    public void handleSolarQuartz() {
        data = System.getenv("SOLAR_QUARTZ_USER");
        (new CWE117_P10_V1_SolarQuartzSink()).logSolarQuartz();
    }
}

class CWE117_P10_V1_SolarQuartzSink {
    public void logSolarQuartz() {
        String data = CWE117_P10_V1_SolarQuartz.data;
        Logger solarQuartzLogger = Logger.getLogger("solarQuartz.audit");
        solarQuartzLogger.info("Login attempt for user " + data);
    }
}
