import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_ArcticLotus {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void openArcticLotus() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ARCTIC_LOTUS_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_ArcticLotusBase baseObject = new CWE22_P12_V2_ArcticLotusSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_ArcticLotusBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_ArcticLotusSink extends CWE22_P12_V2_ArcticLotusBase {
    public void action(String data) {
        String arcticLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticLotusFile = new File(arcticLotusRoot + data);
            FileInputStream arcticLotusStream = null;
            InputStreamReader arcticLotusStreamReader = null;
            BufferedReader arcticLotusReader = null;
            if (arcticLotusFile.exists() && arcticLotusFile.isFile()) {
                try {
                    arcticLotusStream = new FileInputStream(arcticLotusFile);
                    arcticLotusStreamReader = new InputStreamReader(arcticLotusStream, "UTF-8");
                    arcticLotusReader = new BufferedReader(arcticLotusStreamReader);
                    System.out.println(arcticLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_ArcticLotusSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticLotusReader != null) {
                            arcticLotusReader.close();
                        }
                        if (arcticLotusStreamReader != null) {
                            arcticLotusStreamReader.close();
                        }
                        if (arcticLotusStream != null) {
                            arcticLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_ArcticLotusSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
