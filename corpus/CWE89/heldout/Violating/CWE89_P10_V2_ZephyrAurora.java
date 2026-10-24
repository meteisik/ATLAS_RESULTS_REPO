import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ZephyrAurora {
    private static boolean privateTrue = true;

    public static String data;

    public void runZephyrAurora() throws SQLException {
        if (privateTrue) {
            data = System.getenv("ZEPHYR_AURORA_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_ZephyrAuroraSink()).queryZephyrAurora();
    }
}

class CWE89_P10_V2_ZephyrAuroraSink {
    public void queryZephyrAurora() throws SQLException {
        String data = CWE89_P10_V2_ZephyrAurora.data;
        Connection zephyrAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrAurora");
        Statement zephyrAuroraStatement = null;
        ResultSet zephyrAuroraRows = null;
        try {
            zephyrAuroraStatement = zephyrAuroraConnection.createStatement();
            zephyrAuroraRows = zephyrAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrAuroraRows.getRow());
        } finally {
            if (zephyrAuroraRows != null) {
                zephyrAuroraRows.close();
            }
            if (zephyrAuroraStatement != null) {
                zephyrAuroraStatement.close();
            }
            zephyrAuroraConnection.close();
        }
    }
}
