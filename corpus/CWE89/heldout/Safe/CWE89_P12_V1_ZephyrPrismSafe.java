import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ZephyrPrismSafe {

    public void runZephyrPrism() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_ZephyrPrismSafeBase baseObject = new CWE89_P12_V1_ZephyrPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ZephyrPrismSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ZephyrPrismSafeSink extends CWE89_P12_V1_ZephyrPrismSafeBase {
    public void action(String data) throws SQLException {
        Connection zephyrPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrPrism");
        Statement zephyrPrismStatement = null;
        ResultSet zephyrPrismRows = null;
        try {
            zephyrPrismStatement = zephyrPrismConnection.createStatement();
            zephyrPrismRows = zephyrPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrPrismRows.getRow());
        } finally {
            if (zephyrPrismRows != null) {
                zephyrPrismRows.close();
            }
            if (zephyrPrismStatement != null) {
                zephyrPrismStatement.close();
            }
            zephyrPrismConnection.close();
        }
    }
}
