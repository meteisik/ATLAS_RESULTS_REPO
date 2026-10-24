import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V1_CrimsonLotus {

    private String locateCrimsonLotus() {
        String data;
        data = System.getenv("CRIMSON_LOTUS_PATH");
        return data;
    }

    public void openCrimsonLotus() {
        String data = locateCrimsonLotus();
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
                    Logger.getLogger("CWE22_P04_V1_CrimsonLotus").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P04_V1_CrimsonLotus").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
