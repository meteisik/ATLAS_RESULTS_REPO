import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ZephyrSundial {

    public void runZephyrSundial() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_SUNDIAL_FILTER");
        CWE89_P12_V1_ZephyrSundialBase baseObject = new CWE89_P12_V1_ZephyrSundialSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ZephyrSundialBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ZephyrSundialSink extends CWE89_P12_V1_ZephyrSundialBase {
    public void action(String data) throws SQLException {
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
