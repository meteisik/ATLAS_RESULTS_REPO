import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_CobaltOrbit {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void openCobaltOrbit() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("COBALT_ORBIT_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_CobaltOrbitBase baseObject = new CWE22_P12_V2_CobaltOrbitSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_CobaltOrbitBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_CobaltOrbitSink extends CWE22_P12_V2_CobaltOrbitBase {
    public void action(String data) {
        String cobaltOrbitRoot = "/home/user/uploads/";
        if (data != null) {
            File cobaltOrbitFile = new File(cobaltOrbitRoot + data);
            FileInputStream cobaltOrbitStream = null;
            InputStreamReader cobaltOrbitStreamReader = null;
            BufferedReader cobaltOrbitReader = null;
            if (cobaltOrbitFile.exists() && cobaltOrbitFile.isFile()) {
                try {
                    cobaltOrbitStream = new FileInputStream(cobaltOrbitFile);
                    cobaltOrbitStreamReader = new InputStreamReader(cobaltOrbitStream, "UTF-8");
                    cobaltOrbitReader = new BufferedReader(cobaltOrbitStreamReader);
                    System.out.println(cobaltOrbitReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_CobaltOrbitSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (cobaltOrbitReader != null) {
                            cobaltOrbitReader.close();
                        }
                        if (cobaltOrbitStreamReader != null) {
                            cobaltOrbitStreamReader.close();
                        }
                        if (cobaltOrbitStream != null) {
                            cobaltOrbitStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_CobaltOrbitSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
