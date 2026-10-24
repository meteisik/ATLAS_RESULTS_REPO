import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_ArcticKestrel {

    public void openArcticKestrel() {
        String data;
        if (true) {
            data = System.getenv("ARCTIC_KESTREL_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_ArcticKestrelBase baseObject = new CWE22_P12_V2_ArcticKestrelSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_ArcticKestrelBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_ArcticKestrelSink extends CWE22_P12_V2_ArcticKestrelBase {
    public void action(String data) {
        String arcticKestrelRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticKestrelFile = new File(arcticKestrelRoot + data);
            FileInputStream arcticKestrelStream = null;
            InputStreamReader arcticKestrelStreamReader = null;
            BufferedReader arcticKestrelReader = null;
            if (arcticKestrelFile.exists() && arcticKestrelFile.isFile()) {
                try {
                    arcticKestrelStream = new FileInputStream(arcticKestrelFile);
                    arcticKestrelStreamReader = new InputStreamReader(arcticKestrelStream, "UTF-8");
                    arcticKestrelReader = new BufferedReader(arcticKestrelStreamReader);
                    System.out.println(arcticKestrelReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_ArcticKestrelSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticKestrelReader != null) {
                            arcticKestrelReader.close();
                        }
                        if (arcticKestrelStreamReader != null) {
                            arcticKestrelStreamReader.close();
                        }
                        if (arcticKestrelStream != null) {
                            arcticKestrelStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_ArcticKestrelSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
