import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SaffronFlareSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSaffronFlare() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = (new CWE89_P07_V2_SaffronFlareSafeSource()).loadSaffronFlare();
        } else {
            data = null;
        }
        Connection saffronFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronFlare");
        Statement saffronFlareStatement = null;
        ResultSet saffronFlareRows = null;
        try {
            saffronFlareStatement = saffronFlareConnection.createStatement();
            saffronFlareRows = saffronFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronFlareRows.getRow());
        } finally {
            if (saffronFlareRows != null) {
                saffronFlareRows.close();
            }
            if (saffronFlareStatement != null) {
                saffronFlareStatement.close();
            }
            saffronFlareConnection.close();
        }
    }
}

class CWE89_P07_V2_SaffronFlareSafeSource {
    public String loadSaffronFlare() {
        String data;
        data = "foo";
        return data;
    }
}
