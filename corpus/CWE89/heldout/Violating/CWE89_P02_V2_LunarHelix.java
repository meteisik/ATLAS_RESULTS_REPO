import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_LunarHelix {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runLunarHelix() throws SQLException {
        String dataCopy;
        {
            String data;
            if (IO.staticReturnsTrue()) {
                data = System.getenv("LUNAR_HELIX_FILTER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection lunarHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:lunarHelix");
            Statement lunarHelixStatement = null;
            ResultSet lunarHelixRows = null;
            try {
                lunarHelixStatement = lunarHelixConnection.createStatement();
                lunarHelixRows = lunarHelixStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(lunarHelixRows.getRow());
            } finally {
                if (lunarHelixRows != null) {
                    lunarHelixRows.close();
                }
                if (lunarHelixStatement != null) {
                    lunarHelixStatement.close();
                }
                lunarHelixConnection.close();
            }
        }
    }
}
