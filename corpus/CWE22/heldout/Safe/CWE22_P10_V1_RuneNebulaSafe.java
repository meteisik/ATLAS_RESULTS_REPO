import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V1_RuneNebulaSafe {
    public static String data;

    public void openRuneNebula() {
        data = "foo";
        (new CWE22_P10_V1_RuneNebulaSafeSink()).readRuneNebula();
    }
}

class CWE22_P10_V1_RuneNebulaSafeSink {
    public void readRuneNebula() {
        String data = CWE22_P10_V1_RuneNebulaSafe.data;
        String runeNebulaRoot = "/home/user/uploads/";
        if (data != null) {
            File runeNebulaFile = new File(runeNebulaRoot + data);
            FileInputStream runeNebulaStream = null;
            InputStreamReader runeNebulaStreamReader = null;
            BufferedReader runeNebulaReader = null;
            if (runeNebulaFile.exists() && runeNebulaFile.isFile()) {
                try {
                    runeNebulaStream = new FileInputStream(runeNebulaFile);
                    runeNebulaStreamReader = new InputStreamReader(runeNebulaStream, "UTF-8");
                    runeNebulaReader = new BufferedReader(runeNebulaStreamReader);
                    System.out.println(runeNebulaReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V1_RuneNebulaSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (runeNebulaReader != null) {
                            runeNebulaReader.close();
                        }
                        if (runeNebulaStreamReader != null) {
                            runeNebulaStreamReader.close();
                        }
                        if (runeNebulaStream != null) {
                            runeNebulaStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V1_RuneNebulaSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
