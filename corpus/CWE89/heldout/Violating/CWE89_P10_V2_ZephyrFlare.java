import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ZephyrFlare {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public void runZephyrFlare() throws SQLException {
        if (privateReturnsTrue()) {
            data = System.getenv("ZEPHYR_FLARE_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_ZephyrFlareSink()).queryZephyrFlare();
    }
}

class CWE89_P10_V2_ZephyrFlareSink {
    public void queryZephyrFlare() throws SQLException {
        String data = CWE89_P10_V2_ZephyrFlare.data;
        Connection zephyrFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrFlare");
        Statement zephyrFlareStatement = null;
        ResultSet zephyrFlareRows = null;
        try {
            zephyrFlareStatement = zephyrFlareConnection.createStatement();
            zephyrFlareRows = zephyrFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrFlareRows.getRow());
        } finally {
            if (zephyrFlareRows != null) {
                zephyrFlareRows.close();
            }
            if (zephyrFlareStatement != null) {
                zephyrFlareStatement.close();
            }
            zephyrFlareConnection.close();
        }
    }
}
