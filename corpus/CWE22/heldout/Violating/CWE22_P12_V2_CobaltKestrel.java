import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_CobaltKestrel {

    public void openCobaltKestrel() {
        String data;
        if (5 == 5) {
            data = System.getenv("COBALT_KESTREL_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_CobaltKestrelBase baseObject = new CWE22_P12_V2_CobaltKestrelSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_CobaltKestrelBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_CobaltKestrelSink extends CWE22_P12_V2_CobaltKestrelBase {
    public void action(String data) {
        String cobaltKestrelRoot = "/home/user/uploads/";
        if (data != null) {
            File cobaltKestrelFile = new File(cobaltKestrelRoot + data);
            FileInputStream cobaltKestrelStream = null;
            InputStreamReader cobaltKestrelStreamReader = null;
            BufferedReader cobaltKestrelReader = null;
            if (cobaltKestrelFile.exists() && cobaltKestrelFile.isFile()) {
                try {
                    cobaltKestrelStream = new FileInputStream(cobaltKestrelFile);
                    cobaltKestrelStreamReader = new InputStreamReader(cobaltKestrelStream, "UTF-8");
                    cobaltKestrelReader = new BufferedReader(cobaltKestrelStreamReader);
                    System.out.println(cobaltKestrelReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_CobaltKestrelSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (cobaltKestrelReader != null) {
                            cobaltKestrelReader.close();
                        }
                        if (cobaltKestrelStreamReader != null) {
                            cobaltKestrelStreamReader.close();
                        }
                        if (cobaltKestrelStream != null) {
                            cobaltKestrelStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_CobaltKestrelSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
