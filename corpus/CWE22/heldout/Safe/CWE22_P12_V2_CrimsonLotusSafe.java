import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_CrimsonLotusSafe {

    public void openCrimsonLotus() {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        CWE22_P12_V2_CrimsonLotusSafeBase baseObject = new CWE22_P12_V2_CrimsonLotusSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_CrimsonLotusSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_CrimsonLotusSafeSink extends CWE22_P12_V2_CrimsonLotusSafeBase {
    public void action(String data) {
        String crimsonLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonLotusFile = new File(crimsonLotusRoot + data);
            FileInputStream crimsonLotusStream = null;
            InputStreamReader crimsonLotusStreamReader = null;
            BufferedReader crimsonLotusReader = null;
            if (crimsonLotusFile.exists() && crimsonLotusFile.isFile()) {
                try {
                    crimsonLotusStream = new FileInputStream(crimsonLotusFile);
                    crimsonLotusStreamReader = new InputStreamReader(crimsonLotusStream, "UTF-8");
                    crimsonLotusReader = new BufferedReader(crimsonLotusStreamReader);
                    System.out.println(crimsonLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_CrimsonLotusSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonLotusReader != null) {
                            crimsonLotusReader.close();
                        }
                        if (crimsonLotusStreamReader != null) {
                            crimsonLotusStreamReader.close();
                        }
                        if (crimsonLotusStream != null) {
                            crimsonLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_CrimsonLotusSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
