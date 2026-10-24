import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ZephyrSundialSafe {

    public void runZephyrSundial() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_ZephyrSundialSafeBase baseObject = new CWE89_P12_V1_ZephyrSundialSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ZephyrSundialSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ZephyrSundialSafeSink extends CWE89_P12_V1_ZephyrSundialSafeBase {
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
