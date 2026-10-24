import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_ArcticLantern {

    public void openArcticLantern() {
        String data;
        if (5 == 5) {
            data = System.getenv("ARCTIC_LANTERN_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_ArcticLanternBase baseObject = new CWE22_P12_V2_ArcticLanternSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_ArcticLanternBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_ArcticLanternSink extends CWE22_P12_V2_ArcticLanternBase {
    public void action(String data) {
        String arcticLanternRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticLanternFile = new File(arcticLanternRoot + data);
            FileInputStream arcticLanternStream = null;
            InputStreamReader arcticLanternStreamReader = null;
            BufferedReader arcticLanternReader = null;
            if (arcticLanternFile.exists() && arcticLanternFile.isFile()) {
                try {
                    arcticLanternStream = new FileInputStream(arcticLanternFile);
                    arcticLanternStreamReader = new InputStreamReader(arcticLanternStream, "UTF-8");
                    arcticLanternReader = new BufferedReader(arcticLanternStreamReader);
                    System.out.println(arcticLanternReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_ArcticLanternSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticLanternReader != null) {
                            arcticLanternReader.close();
                        }
                        if (arcticLanternStreamReader != null) {
                            arcticLanternStreamReader.close();
                        }
                        if (arcticLanternStream != null) {
                            arcticLanternStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_ArcticLanternSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
