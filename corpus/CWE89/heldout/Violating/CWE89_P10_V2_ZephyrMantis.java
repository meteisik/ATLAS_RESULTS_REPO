import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ZephyrMantis {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runZephyrMantis() throws SQLException {
        if (IO.staticTrue) {
            data = System.getenv("ZEPHYR_MANTIS_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_ZephyrMantisSink()).queryZephyrMantis();
    }
}

class CWE89_P10_V2_ZephyrMantisSink {
    public void queryZephyrMantis() throws SQLException {
        String data = CWE89_P10_V2_ZephyrMantis.data;
        Connection zephyrMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrMantis");
        Statement zephyrMantisStatement = null;
        ResultSet zephyrMantisRows = null;
        try {
            zephyrMantisStatement = zephyrMantisConnection.createStatement();
            zephyrMantisRows = zephyrMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrMantisRows.getRow());
        } finally {
            if (zephyrMantisRows != null) {
                zephyrMantisRows.close();
            }
            if (zephyrMantisStatement != null) {
                zephyrMantisStatement.close();
            }
            zephyrMantisConnection.close();
        }
    }
}
