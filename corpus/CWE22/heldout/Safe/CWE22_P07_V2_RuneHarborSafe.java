import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V2_RuneHarborSafe {

    public void openRuneHarbor() {
        String data;
        if (true) {
            data = (new CWE22_P07_V2_RuneHarborSafeSource()).locateRuneHarbor();
        } else {
            data = null;
        }
        String runeHarborRoot = "/home/user/uploads/";
        if (data != null) {
            File runeHarborFile = new File(runeHarborRoot + data);
            FileInputStream runeHarborStream = null;
            InputStreamReader runeHarborStreamReader = null;
            BufferedReader runeHarborReader = null;
            if (runeHarborFile.exists() && runeHarborFile.isFile()) {
                try {
                    runeHarborStream = new FileInputStream(runeHarborFile);
                    runeHarborStreamReader = new InputStreamReader(runeHarborStream, "UTF-8");
                    runeHarborReader = new BufferedReader(runeHarborStreamReader);
                    System.out.println(runeHarborReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V2_RuneHarborSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (runeHarborReader != null) {
                            runeHarborReader.close();
                        }
                        if (runeHarborStreamReader != null) {
                            runeHarborStreamReader.close();
                        }
                        if (runeHarborStream != null) {
                            runeHarborStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V2_RuneHarborSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V2_RuneHarborSafeSource {
    public String locateRuneHarbor() {
        String data;
        data = "foo";
        return data;
    }
}
