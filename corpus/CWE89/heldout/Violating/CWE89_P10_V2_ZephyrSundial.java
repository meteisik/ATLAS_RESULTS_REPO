import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ZephyrSundial {

    public static String data;

    public void runZephyrSundial() throws SQLException {
        switch (7) {
        case 7:
            data = System.getenv("ZEPHYR_SUNDIAL_FILTER");
            break;
        default:
            data = null;
            break;
        }
        (new CWE89_P10_V2_ZephyrSundialSink()).queryZephyrSundial();
    }
}

class CWE89_P10_V2_ZephyrSundialSink {
    public void queryZephyrSundial() throws SQLException {
        String data = CWE89_P10_V2_ZephyrSundial.data;
        Connection zephyrSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrSundial");
        Statement zephyrSundialStatement = null;
        ResultSet zephyrSundialRows = null;
        try {
            zephyrSundialStatement = zephyrSundialConnection.createStatement();
            zephyrSundialRows = zephyrSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrSundialRows.getRow());
        } finally {
            if (zephyrSundialRows != null) {
                zephyrSundialRows.close();
            }
            if (zephyrSundialStatement != null) {
                zephyrSundialStatement.close();
            }
            zephyrSundialConnection.close();
        }
    }
}
