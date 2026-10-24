import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_CrimsonOrbitSafe {

    public void openCrimsonOrbit() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        CWE22_P12_V2_CrimsonOrbitSafeBase baseObject = new CWE22_P12_V2_CrimsonOrbitSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_CrimsonOrbitSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_CrimsonOrbitSafeSink extends CWE22_P12_V2_CrimsonOrbitSafeBase {
    public void action(String data) {
        String crimsonOrbitRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonOrbitFile = new File(crimsonOrbitRoot + data);
            FileInputStream crimsonOrbitStream = null;
            InputStreamReader crimsonOrbitStreamReader = null;
            BufferedReader crimsonOrbitReader = null;
            if (crimsonOrbitFile.exists() && crimsonOrbitFile.isFile()) {
                try {
                    crimsonOrbitStream = new FileInputStream(crimsonOrbitFile);
                    crimsonOrbitStreamReader = new InputStreamReader(crimsonOrbitStream, "UTF-8");
                    crimsonOrbitReader = new BufferedReader(crimsonOrbitStreamReader);
                    System.out.println(crimsonOrbitReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_CrimsonOrbitSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonOrbitReader != null) {
                            crimsonOrbitReader.close();
                        }
                        if (crimsonOrbitStreamReader != null) {
                            crimsonOrbitStreamReader.close();
                        }
                        if (crimsonOrbitStream != null) {
                            crimsonOrbitStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_CrimsonOrbitSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
