import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V1_LunarHelixSafe {
    private String lunarHelixData;

    private void readLunarHelix() {
        String data = lunarHelixData;
        String lunarHelixRoot = "/home/user/uploads/";
        if (data != null) {
            File lunarHelixFile = new File(lunarHelixRoot + data);
            FileInputStream lunarHelixStream = null;
            InputStreamReader lunarHelixStreamReader = null;
            BufferedReader lunarHelixReader = null;
            if (lunarHelixFile.exists() && lunarHelixFile.isFile()) {
                try {
                    lunarHelixStream = new FileInputStream(lunarHelixFile);
                    lunarHelixStreamReader = new InputStreamReader(lunarHelixStream, "UTF-8");
                    lunarHelixReader = new BufferedReader(lunarHelixStreamReader);
                    System.out.println(lunarHelixReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V1_LunarHelixSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (lunarHelixReader != null) {
                            lunarHelixReader.close();
                        }
                        if (lunarHelixStreamReader != null) {
                            lunarHelixStreamReader.close();
                        }
                        if (lunarHelixStream != null) {
                            lunarHelixStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V1_LunarHelixSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openLunarHelix() {
        String data;
        data = "foo";
        lunarHelixData = data;
        readLunarHelix();
    }
}
